package main

import (
	pb "../proto"

	"bufio"
	"code.google.com/p/go.crypto/pbkdf2"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"flag"
	"fmt"
	"github.com/golang/protobuf/proto"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

// Constants
const (
	BNOTIFY_PACKAGE_NAME = "cc.bran.bnotify"
	GCM_SEND_ADDRESS     = "https://android.googleapis.com/gcm/send"
	AES_KEY_SIZE         = 16
	SALT_SIZE            = 16
	PBKDF2_ITER_COUNT    = 4096
)

// Flags
var (
	port             = flag.Int("port", 50051, "port to listen to RPCs on")
	settingsFilename = flag.String("settings", "bnotify.conf", "filename of settings file")
)

// Types
type notificationService struct {
	httpClient     *http.Client
	apiKey         string
	registrationId string
	salt           string
	gcmCipher      cipher.AEAD
}

// Code
func (ns *notificationService) SendNotification(ctx context.Context, req *pb.SendNotificationRequest) (*pb.SendNotificationResponse, error) {
	// Marshal request notification & encrypt.
	plaintextMessage, err := proto.Marshal(req.Notification)
	if err != nil {
		log.Printf("Error while posting notification: %s", err)
		return nil, err
	}
	nonce := make([]byte, ns.gcmCipher.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		log.Printf("Error while posting notification: %s", err)
		return nil, err
	}
	message := ns.gcmCipher.Seal(nil, nonce, plaintextMessage, nil)

	// Fill out final envelope proto & base-64 encode into a payload.
	envelopeProto := &pb.Envelope{
		Message: message,
		Salt:    []byte(ns.salt),
		Nonce:   nonce,
	}
	envelopeData, err := proto.Marshal(envelopeProto)
	if err != nil {
		log.Printf("Error while posting notification: %s", err)
		return nil, err
	}
	payload := base64.StdEncoding.EncodeToString(envelopeData)

	// Post the notification.
	err = postNotification(ns.httpClient, ns.apiKey, ns.registrationId, payload)
	if err != nil {
		log.Printf("Error while posting notification: %s", err)
		return nil, err
	}
	return &pb.SendNotificationResponse{}, nil
}

func postNotification(httpClient *http.Client, apiKey string, registrationId string, payload string) error {
	// Set up request.
	values := url.Values{}
	values.Set("restricted_package_name", BNOTIFY_PACKAGE_NAME)
	values.Set("registration_id", registrationId)
	values.Set("data.payload", payload)

	req, err := http.NewRequest("POST", GCM_SEND_ADDRESS, strings.NewReader(values.Encode()))
	if err != nil {
		return err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded;charset=UTF-8")
	req.Header.Add("Authorization", fmt.Sprintf("key=%s", apiKey))

	// Make request to GCM server.
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Check for HTTP error code.
	if resp.StatusCode != 200 {
		return fmt.Errorf("GCM HTTP error (%s)", resp.Status)
	}

	// Read the first line of the response and figure out if it indicates a GCM-level error.
	bodyReader := bufio.NewReader(resp.Body)
	lineBytes, _, err := bodyReader.ReadLine()
	if err != nil {
		return err
	}
	line := string(lineBytes)
	if strings.HasPrefix(line, "Error=") {
		return fmt.Errorf("GCM error (%s)", strings.TrimPrefix(line, "Error="))
	}

	return nil
}

func main() {
	// Parse flags.
	flag.Parse()

	// Read settings.
	settingsBytes, err := ioutil.ReadFile(*settingsFilename)
	if err != nil {
		log.Fatalf("Error reading settings file: %s", err)
	}
	settings := &pb.BNotifySettings{}
	err = proto.UnmarshalText(string(settingsBytes), settings)
	if err != nil {
		log.Fatalf("Error reading settings file: %s", err)
	}

	// Generate salt & derive key from password + salt.
	salt := make([]byte, SALT_SIZE)
	_, err = rand.Read(salt)
	if err != nil {
		log.Fatalf("Error generating salt: %s", err)
	}
	key := pbkdf2.Key([]byte(settings.Password), salt, PBKDF2_ITER_COUNT, AES_KEY_SIZE, sha1.New)

	// Initialize cipher based on key.
	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		log.Fatalf("Error initializing block cipher: %s", err)
	}
	gcmCipher, err := cipher.NewGCM(blockCipher)
	if err != nil {
		log.Fatalf("Error initializing GCM cipher: %s", err)
	}

	// Create service, socket, and gRPC server objects.
	service := &notificationService{
		httpClient:     new(http.Client),
		apiKey:         settings.ApiKey,
		registrationId: settings.RegistrationId,
		salt:           string(salt),
		gcmCipher:      gcmCipher,
	}
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("Error listening on port %d: %s", *port, err)
	}
	defer listener.Close()
	server := grpc.NewServer()
	pb.RegisterNotificationServiceServer(server, service)

	// Attempt to catch signals to shut down the listener.
	// (this is evidently necessary to remove the socket file)
	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, os.Interrupt, syscall.SIGTERM)
	go func() {
		for sig := range signalChannel {
			log.Printf("Received signal '%s', exiting...", sig)
			listener.Close()
			os.Exit(1)
		}
	}()

	// Begin serving.
	log.Printf("Listening for requests on port %d...", *port)
	server.Serve(listener)
}
