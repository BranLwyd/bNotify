package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/boltdb/bolt"
	"github.com/golang/protobuf/proto"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/net/context"
	"google.golang.org/grpc"

	pb "../proto"
)

const (
	bnotifyPackageName = "cc.bran.bnotify"
	gcmSendAddress     = "https://android.googleapis.com/gcm/send"
	aesKeySize         = 16
	pbkdfIterCount     = 400000
	serverIDSize       = 16
	maxWait            = 1024 * time.Second
)

var (
	port             = flag.Int("port", 50051, "port to listen to RPCs on")
	settingsFilename = flag.String("settings", "bnotify.conf", "filename of settings file")
	stateFilename    = flag.String("state", "bnotify.state", "filename of state file")
)

type notificationService struct {
	db             *bolt.DB
	apiKey         string
	registrationID string
	gcmCipher      cipher.AEAD

	pending            int
	pendingIncremented *sync.Cond // pendingIncremented.L protects pending
}

func (ns *notificationService) SendNotification(ctx context.Context, req *pb.SendNotificationRequest) (*pb.SendNotificationResponse, error) {
	// Verify request.
	if req.Notification.Title == "" {
		return nil, errors.New("notification missing title")
	}
	if req.Notification.Text == "" {
		return nil, errors.New("notification missing text")
	}

	if err := ns.db.Batch(func(tx *bolt.Tx) error {
		// Read server ID & allocate sequence number.
		settingsBucket := tx.Bucket([]byte("settings"))
		if settingsBucket == nil {
			return errors.New("missing settings bucket")
		}
		serverID := settingsBucket.Get([]byte("serverID"))
		if serverID == nil {
			return errors.New("missing serverID")
		}

		messagesBucket := tx.Bucket([]byte("pending_messages"))
		if messagesBucket == nil {
			return errors.New("missing pending_messages bucket")
		}
		seq, err := messagesBucket.NextSequence()
		if err != nil {
			return fmt.Errorf("could not allocate sequence number: %v", err)
		}

		// Marshal request.
		plaintextMessage, err := proto.Marshal(&pb.Message{
			ServerId:     serverID,
			Seq:          seq,
			Notification: req.Notification,
		})
		if err != nil {
			return fmt.Errorf("could not marshal message proto: %v", err)
		}

		// Compute nonce = serverID || seq & encrypt.
		key := make([]byte, binary.Size(seq))
		binary.BigEndian.PutUint64(key, seq)
		nonce := append(serverID, key...)
		message := ns.gcmCipher.Seal(nil, nonce, plaintextMessage, nil)

		// Fill out final envelope proto & write to state.
		envelopeData, err := proto.Marshal(&pb.Envelope{
			Message: message,
			Nonce:   nonce,
		})
		if err != nil {
			return fmt.Errorf("could not marshal envelope proto: %v", err)
		}
		if err := messagesBucket.Put(key, envelopeData); err != nil {
			return fmt.Errorf("could not write message to state: %v", err)
		}
		return nil
	}); err != nil {
		log.Printf("Error while posting notification: %v", err)
		return nil, errors.New("internal error")
	}

	// Notify sender goroutine.
	ns.pendingIncremented.L.Lock()
	defer ns.pendingIncremented.L.Unlock()
	ns.pending++
	ns.pendingIncremented.Signal()

	return &pb.SendNotificationResponse{}, nil
}

func (ns *notificationService) startSendingNotifications() {
	go func() {
		wait := time.Second

		for {
			// Wait for a pending message to be available.
			time.Sleep(wait)
			ns.pendingIncremented.L.Lock()
			for ns.pending == 0 {
				ns.pendingIncremented.Wait()
			}
			ns.pendingIncremented.L.Unlock()

			// Read a message off the pending messages queue.
			var key, payload []byte
			if err := ns.db.View(func(tx *bolt.Tx) error {
				messagesBucket := tx.Bucket([]byte("pending_messages"))
				if messagesBucket == nil {
					return errors.New("missing pending_messages bucket")
				}
				k, p := messagesBucket.Cursor().First()
				key = append(key, k...)
				payload = append(payload, p...)
				return nil
			}); err != nil {
				// This is unrecoverable and permanent, so exit.
				log.Fatalf("Could not get notification: %v", err)
			}
			if key == nil {
				// This indicates a logic error in the program, so exit.
				log.Fatalf("Impossible condition: ns.pending is nonzero but no messages are available")
			}

			// Send notification.
			if err := ns.postNotification(payload); err != nil {
				log.Printf("Could not post notification: %v", err)
				if wait < maxWait {
					wait = 2 * wait
					continue
				}
				log.Printf("Failed to send notification too many times, dropping...")
			}

			// Remove sent notification from the pending queue.
			if err := ns.db.Batch(func(tx *bolt.Tx) error {
				messagesBucket := tx.Bucket([]byte("pending_messages"))
				if messagesBucket == nil {
					return errors.New("missing pending_messages bucket")
				}
				if err := messagesBucket.Delete(key); err != nil {
					return fmt.Errorf("error while deleting sent message: %v", err)
				}
				return nil
			}); err != nil {
				log.Printf("Could not remove notification: %v", err)
				continue
			}

			wait = time.Second
			ns.pendingIncremented.L.Lock()
			ns.pending--
			ns.pendingIncremented.L.Unlock()
		}
	}()
}

func (ns *notificationService) postNotification(payload []byte) error {
	// Set up request.
	values := url.Values{}
	values.Set("restricted_package_name", bnotifyPackageName)
	values.Set("registration_id", ns.registrationID)
	values.Set("data.payload", base64.StdEncoding.EncodeToString(payload))

	req, err := http.NewRequest("POST", gcmSendAddress, strings.NewReader(values.Encode()))
	if err != nil {
		return err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded;charset=UTF-8")
	req.Header.Add("Authorization", fmt.Sprintf("key=%s", ns.apiKey))

	// Make request to GCM server.
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Check for HTTP error code.
	if resp.StatusCode != 200 {
		return fmt.Errorf("GCM HTTP error: %v", resp.Status)
	}

	// Read the first line of the response and figure out if it indicates a GCM-level error.
	bodyReader := bufio.NewReader(resp.Body)
	lineBytes, _, err := bodyReader.ReadLine()
	if err != nil {
		return err
	}
	line := string(lineBytes)
	if strings.HasPrefix(line, "Error=") {
		return fmt.Errorf("GCM error: %v", strings.TrimPrefix(line, "Error="))
	}
	return nil
}

func main() {
	flag.Parse()

	// Read settings.
	settingsBytes, err := ioutil.ReadFile(*settingsFilename)
	if err != nil {
		log.Fatalf("Error reading settings file: %v", err)
	}
	settings := &pb.BNotifySettings{}
	err = proto.UnmarshalText(string(settingsBytes), settings)
	if err != nil {
		log.Fatalf("Error reading settings file: %v", err)
	}

	// Open state database & initialize if need be.
	db, err := bolt.Open(*stateFilename, 0640, &bolt.Options{Timeout: time.Second})
	if err != nil {
		log.Fatalf("Error opening state file: %v", err)
	}
	defer db.Close()

	var serverID []byte
	var pending int
	if err := db.Update(func(tx *bolt.Tx) error {
		messagesBucket, err := tx.CreateBucketIfNotExists([]byte("pending_messages"))
		if err != nil {
			return fmt.Errorf("could not create pending_messages bucket: %v", err)
		}
		pending = messagesBucket.Stats().KeyN

		settingsBucket, err := tx.CreateBucketIfNotExists([]byte("settings"))
		if err != nil {
			return fmt.Errorf("error creating settings bucket: %v", err)
		}
		if serverID = settingsBucket.Get([]byte("serverID")); serverID == nil {
			serverID = make([]byte, serverIDSize)
			if _, err := rand.Read(serverID); err != nil {
				return fmt.Errorf("error generating server ID: %v", err)
			}
			if err := settingsBucket.Put([]byte("serverID"), serverID); err != nil {
				return fmt.Errorf("error setting server ID: %v", err)
			}
		}
		return nil
	}); err != nil {
		log.Fatalf("Error initializing state file: %v", err)
	}

	// Derive key from password & salt (registration ID).
	key := pbkdf2.Key([]byte(settings.Password), []byte(settings.RegistrationId), pbkdfIterCount, aesKeySize, sha1.New)

	// Initialize cipher based on key.
	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		log.Fatalf("Error initializing block cipher: %v", err)
	}
	gcmCipher, err := cipher.NewGCMWithNonceSize(blockCipher, len(serverID)+binary.Size(uint64(0)))
	if err != nil {
		log.Fatalf("Error initializing GCM cipher: %v", err)
	}

	// Create service, socket, and gRPC server objects.
	service := &notificationService{
		db:             db,
		apiKey:         settings.ApiKey,
		registrationID: settings.RegistrationId,
		gcmCipher:      gcmCipher,

		pending:            pending,
		pendingIncremented: sync.NewCond(&sync.Mutex{}),
	}
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", *port))
	if err != nil {
		log.Fatalf("Error listening on port %d: %v", *port, err)
	}
	defer listener.Close()
	server := grpc.NewServer()
	pb.RegisterNotificationServiceServer(server, service)

	// Begin serving.
	log.Printf("Listening for requests on port %d...", *port)
	service.startSendingNotifications()
	server.Serve(listener)
}
