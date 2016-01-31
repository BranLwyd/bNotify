package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"

	"code.google.com/p/go.crypto/pbkdf2"
	"github.com/golang/protobuf/proto"
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
	port             = flag.Int("port", 50051, "port to listen to RPCs on")
	settingsFilename = flag.String("settings", "bnotify.conf", "filename of settings file")
	stateFilename    = flag.String("state", "bnotify.state", "filename of state file")

	uint64Size = binary.Size(uint64(0))

	stateMu sync.Mutex
)

type notificationService struct {
	httpClient     *http.Client
	apiKey         string
	registrationID string
	gcmCipher      cipher.AEAD
}

func (ns *notificationService) SendNotification(ctx context.Context, req *pb.SendNotificationRequest) (*pb.SendNotificationResponse, error) {
	log.Printf("Got notification request")

	// Verify request.
	if req.Notification.Title == "" {
		return nil, errors.New("notification missing title")
	}
	if req.Notification.Text == "" {
		return nil, errors.New("notification missing text")
	}

	// Read state.
	serverID, seq, err := getServerIDAndSeq(true)
	if err != nil {
		log.Printf("Error while posting notification: %v", err)
		return nil, errors.New("internal error")
	}

	// Marshal request notification & encrypt.
	plaintextMessage, err := proto.Marshal(&pb.Message{
		ServerId:     serverID,
		Seq:          seq,
		Notification: req.Notification,
	})
	if err != nil {
		log.Printf("Error while posting notification: %v", err)
		return nil, errors.New("internal error")
	}
	nonce := make([]byte, ns.gcmCipher.NonceSize())
	binary.BigEndian.PutUint64(nonce, seq) // Ensure we do not reuse nonce.
	if _, err := rand.Read(nonce[uint64Size:]); err != nil {
		log.Printf("Error while posting notification: %v", err)
		return nil, errors.New("internal error")
	}
	message := ns.gcmCipher.Seal(nil, nonce, plaintextMessage, nil)

	// Fill out final envelope proto & base-64 encode into a payload.
	envelopeData, err := proto.Marshal(&pb.Envelope{
		Message: message,
		Nonce:   nonce,
	})
	if err != nil {
		log.Printf("Error while posting notification: %v", err)
		return nil, errors.New("internal error")
	}
	payload := base64.StdEncoding.EncodeToString(envelopeData)

	// Post the notification.
	if err := ns.postNotification(payload); err != nil {
		log.Printf("Error while posting notification: %v", err)
		return nil, errors.New("internal error")
	}
	return &pb.SendNotificationResponse{}, nil
}

func (ns *notificationService) postNotification(payload string) error {
	// Set up request.
	values := url.Values{}
	values.Set("restricted_package_name", bnotifyPackageName)
	values.Set("registration_id", ns.registrationID)
	values.Set("data.payload", payload)

	req, err := http.NewRequest("POST", gcmSendAddress, strings.NewReader(values.Encode()))
	if err != nil {
		return err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded;charset=UTF-8")
	req.Header.Add("Authorization", fmt.Sprintf("key=%s", ns.apiKey))

	// Make request to GCM server.
	resp, err := ns.httpClient.Do(req)
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

func getServerIDAndSeq(increment bool) (serverID string, seq uint64, _ error) {
	// TODO(bran): consider using a library (e.g. SQLite) to handle intricacies of handling files on disk
	//             (this is probably subtly buggy under certain failure modes, & nonce reuse is disastrous...)
	stateMu.Lock()
	defer stateMu.Unlock()

	// Get current state.
	var state *pb.BNotifyServerState
	inFile, err := os.Open(*stateFilename)
	if err == nil {
		if err := func() error {
			defer inFile.Close()
			data, err := ioutil.ReadAll(inFile)
			if err != nil {
				return fmt.Errorf("could not read state file: %v", err)
			}
			state = &pb.BNotifyServerState{}
			if err := proto.Unmarshal(data, state); err != nil {
				return fmt.Errorf("could not deserialize state: %v", err)
			}
			return nil
		}(); err != nil {
			return "", 0, err
		}
	} else {
		log.Printf("Could not open state file (%v); continuing with fresh state", err)
		serverIDBytes := make([]byte, serverIDSize)
		if _, err := rand.Read(serverIDBytes); err != nil {
			return "", 0, fmt.Errorf("could not generate server ID: %v", err)
		}
		state = &pb.BNotifyServerState{
			ServerId: base64.RawStdEncoding.EncodeToString(serverIDBytes),
			NextSeq:  1,
		}
	}

	// Get result & update state if requested.
	serverID, nextSeq := state.ServerId, state.NextSeq
	if nextSeq == 0 {
		return "", 0, errors.New("out of message sequence numbers")
	}
	if increment {
		state.NextSeq++
	}

	// Write state back.
	// (do this even if we aren't changing the state to make sure that we
	// can write state--allows us to fail early if state flag is improperly
	// set)
	stateBytes, err := proto.Marshal(state)
	if err != nil {
		return "", 0, fmt.Errorf("could not serialize state: %v", err)
	}
	outFile, err := ioutil.TempFile("", "bnotifyd_")
	if err != nil {
		return "", 0, fmt.Errorf("could not open temporary file: %v", err)
	}
	tempFilename := outFile.Name()
	if err := func() error {
		defer outFile.Close()
		if err := outFile.Chmod(0640); err != nil {
			return fmt.Errorf("could not chmod tempfile: %v", err)
		}
		if err := outFile.Truncate(0); err != nil {
			return fmt.Errorf("could not truncate tempfile: %v", err)
		}
		if _, err := io.Copy(outFile, bytes.NewReader(stateBytes)); err != nil {
			return fmt.Errorf("could not write to tempfile: %v", err)
		}
		if err := outFile.Sync(); err != nil {
			return fmt.Errorf("could not sync tempfile: %v", err)
		}
		if err := outFile.Close(); err != nil {
			return fmt.Errorf("could not close tempfile: %v", err)
		}
		return nil
	}(); err != nil {
		return "", 0, err
	}
	if err := os.Rename(tempFilename, *stateFilename); err != nil {
		return "", 0, fmt.Errorf("could not rename tempfile: %v", err)
	}

	return serverID, nextSeq, nil
}

func main() {
	// Parse flags.
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

	// Read state file to make sure we can (fail fast for bad config).
	if _, _, err := getServerIDAndSeq(false); err != nil {
		log.Fatalf("Error checking state file: %v", err)
	}

	// Derive key from password & salt (registration ID).
	key := pbkdf2.Key([]byte(settings.Password), []byte(settings.RegistrationId), pbkdfIterCount, aesKeySize, sha1.New)

	// Initialize cipher based on key.
	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		log.Fatalf("Error initializing block cipher: %v", err)
	}
	gcmCipher, err := cipher.NewGCM(blockCipher)
	if err != nil {
		log.Fatalf("Error initializing GCM cipher: %v", err)
	}

	// Sanity check nonce size.
	if gcmCipher.NonceSize() < uint64Size {
		// This should be impossible, but may as well panic with a useful message.
		log.Fatalf(fmt.Sprintf("cipher nonce size too small (%d < %d)", gcmCipher.NonceSize(), uint64Size))
	}

	// Create service, socket, and gRPC server objects.
	service := &notificationService{
		httpClient:     new(http.Client),
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
	log.Printf("Listening for requests on port %d...", *port)
	server.Serve(listener)
}
