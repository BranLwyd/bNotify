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
)

var (
	port             = flag.Int("port", 50051, "port to listen for RPCs on")
	settingsFilename = flag.String("settings", "bnotify.conf", "filename of settings file")
	stateFilename    = flag.String("state", "bnotify.state", "filename of state file")

	waits = []time.Duration{0, time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 16 * time.Minute}
)

type notificationService struct {
	db             *bolt.DB
	apiKey         string
	registrationID string
	gcmCipher      cipher.AEAD
}

func (ns *notificationService) SendNotification(ctx context.Context, req *pb.SendNotificationRequest) (*pb.SendNotificationResponse, error) {
	// Verify request.
	if req.Notification.Title == "" {
		return nil, errors.New("notification missing title")
	}
	if req.Notification.Text == "" {
		return nil, errors.New("notification missing text")
	}

	// Enqueue request into state.
	var seq uint64
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
		theSeq, err := messagesBucket.NextSequence()
		if err != nil {
			return fmt.Errorf("could not allocate sequence number: %v", err)
		}
		seq = theSeq

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

		// Fill out final envelope & pending payload protos, then write to storage.
		payload, err := proto.Marshal(&pb.Envelope{
			Message: message,
			Nonce:   nonce,
		})
		if err != nil {
			return fmt.Errorf("could not marshal envelope proto: %v", err)
		}
		pendingPayload, err := proto.Marshal(&pb.PendingPayload{
			Payload: payload,
		})
		if err != nil {
			return fmt.Errorf("could not marshal pending payload proto: %v", err)
		}
		if err := messagesBucket.Put(key, pendingPayload); err != nil {
			return fmt.Errorf("could not write message to state: %v", err)
		}
		return nil
	}); err != nil {
		log.Printf("Error while posting notification: %v", err)
		return nil, errors.New("internal error")
	}

	// Kick off goroutine to actually send notification and return success.
	go ns.sendPayload(seq)
	return &pb.SendNotificationResponse{}, nil
}

func (ns *notificationService) sendPayload(seq uint64) {
	key := make([]byte, binary.Size(seq))
	binary.BigEndian.PutUint64(key, seq)

	for {
		// Read & update payload in state.
		var payload []byte
		var sendAttempts int
		if err := ns.db.Batch(func(tx *bolt.Tx) error {
			messagesBucket := tx.Bucket([]byte("pending_messages"))
			if messagesBucket == nil {
				return errors.New("missing pending_messages bucket")
			}
			ppBytes := messagesBucket.Get(key)
			if ppBytes == nil {
				return errors.New("pending payload missing from state")
			}
			pendingPayload := &pb.PendingPayload{}
			if err := proto.Unmarshal(ppBytes, pendingPayload); err != nil {
				return fmt.Errorf("could not unmarshal pending payload: %v", err)
			}
			payload = pendingPayload.Payload
			sendAttempts = int(pendingPayload.SendAttempts)
			if sendAttempts < len(waits) {
				pendingPayload.SendAttempts++
				ppBytes, err := proto.Marshal(pendingPayload)
				if err != nil {
					return fmt.Errorf("could not marshal pending payload: %v", err)
				}
				if err := messagesBucket.Put(key, ppBytes); err != nil {
					return fmt.Errorf("could not write pending payload: %v", err)
				}
			} else {
				// We are out of retries.
				if err := messagesBucket.Delete(key); err != nil {
					return fmt.Errorf("could not delete pending payload: %v", err)
				}
			}
			return nil
		}); err != nil {
			// Most/all errors that occur here are unrecoverable, so give up.
			log.Printf("[%d] Could not read and update payload: %v", seq, err)
			return
		}
		if sendAttempts >= len(waits) {
			log.Printf("[%d] Too many retries, giving up", seq)
		}
		waitTime := waits[sendAttempts]
		if waitTime > 0 {
			log.Printf("[%d] Waiting %v before retry", seq, waitTime)
			time.Sleep(waitTime)
		}

		// Post notification.
		if err := ns.postPayloadToGCM(payload); err != nil {
			log.Printf("[%d] Could not post notification: %v", seq, err)
			continue
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
			// We'll return; I guess we'll try to clean up again whenever the server restarts.
			log.Printf("[%d] Could not remove notification: %v", seq, err)
		}
		return
	}
}

func (ns *notificationService) postPayloadToGCM(payload []byte) error {
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
	var pendingSeqs []uint64
	if err := db.Update(func(tx *bolt.Tx) error {
		messagesBucket, err := tx.CreateBucketIfNotExists([]byte("pending_messages"))
		if err != nil {
			return fmt.Errorf("could not create pending_messages bucket: %v", err)
		}
		messagesBucket.ForEach(func(key, _ []byte) error {
			pendingSeqs = append(pendingSeqs, binary.BigEndian.Uint64(key))
			return nil
		})

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
	}
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", *port))
	if err != nil {
		log.Fatalf("Error listening on port %d: %v", *port, err)
	}
	defer listener.Close()
	server := grpc.NewServer()
	pb.RegisterNotificationServiceServer(server, service)

	// Begin serving.
	for _, seq := range pendingSeqs {
		go service.sendPayload(seq)
	}
	log.Printf("Listening for requests on port %d", *port)
	server.Serve(listener)
}
