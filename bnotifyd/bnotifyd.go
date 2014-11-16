package main

import (
	"bufio"
	"bytes"
	"code.google.com/p/go.crypto/pbkdf2"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/rpc"
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
	PBKDF2_ITER_COUNT    = 4096
)

// Flags
var (
	socketFilename        = flag.String("socket_filename", "bnotify.sock", "path of UNIX socket to listen to RPCs on")
	apiKeyFilename        = flag.String("api_key", "api.key", "filename of API key file to use")
	encryptionKeyFilename = flag.String("encryption_key", "encryption.key", "filename of encryption key file to use")
	registrationFilename  = flag.String("registration_id", "registration.id", "filename of the registration ID file to use")
)

// Types
type NotificationService struct {
	httpClient         *http.Client
	apiKey             string
	registrationId     string
	encryptionPassword string
}

type NotificationRequest struct {
	Title string `json:"title"`
	Text  string `json:"text"`
}

type NotificationResponse struct{}

// Code
func (ns *NotificationService) Notify(req *NotificationRequest, resp *NotificationResponse) error {
	log.Printf("Got request: {title='%s', text='%s'}", req.Title, req.Text)

	// Marshal request into JSON.
	plaintextPayload, err := json.Marshal(req)
	if err != nil {
		log.Printf("Error while posting notification: %s", err)
		return err
	}

	// Encrypt (first deriving key from password + random salt).
	plaintextPayload = pkcs5Pad(plaintextPayload, aes.BlockSize)
	encryptedPayload := make([]byte, 2*aes.BlockSize+len(plaintextPayload))
	salt := encryptedPayload[:aes.BlockSize]
	iv := encryptedPayload[aes.BlockSize : 2*aes.BlockSize]
	_, err = rand.Read(encryptedPayload[:2*aes.BlockSize])
	if err != nil {
		log.Fatalf("Error while posting notification: %s", err)
	}
	key := pbkdf2.Key([]byte(ns.encryptionPassword), salt, PBKDF2_ITER_COUNT, AES_KEY_SIZE, sha1.New)

	aesBlock, err := aes.NewCipher(key)
	if err != nil {
		log.Printf("Error while posting notification: %s", err)
		return err
	}

	aesCbc := cipher.NewCBCEncrypter(aesBlock, iv)
	if err != nil {
		log.Printf("Error while posting notification: %s", err)
		return err
	}

	aesCbc.CryptBlocks(encryptedPayload[2*aes.BlockSize:], plaintextPayload)

	// Base64-encode the encrypted payload & IV.
	base64Payload := base64.StdEncoding.EncodeToString(encryptedPayload)

	err = postNotification(ns.httpClient, ns.apiKey, ns.registrationId, string(base64Payload))
	if err != nil {
		log.Printf("Error while posting notification: %s", err)
		return err
	}

	return nil
}

func pkcs5Pad(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
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

func readFileContent(keyFilename string) (string, error) {
	content, err := ioutil.ReadFile(keyFilename)
	if err != nil {
		return "", err
	}

	return string(content), nil
}

func main() {
	// Parse flags.
	flag.Parse()

	// Read API key, registration ID, and encryption password.
	apiKey, err := readFileContent(*apiKeyFilename)
	if err != nil {
		log.Fatalf("Error reading API key: %s", err)
	}

	registrationId, err := readFileContent(*registrationFilename)
	if err != nil {
		log.Fatalf("Error reading registration ID: %s", err)
	}

	encryptionPassword, err := readFileContent(*encryptionKeyFilename)
	if err != nil {
		log.Fatalf("Error reading encryption key: %s", err)
	}

	// Create service object & socket.
	notificationService := NotificationService{
		httpClient:         new(http.Client),
		apiKey:             apiKey,
		registrationId:     registrationId,
		encryptionPassword: encryptionPassword,
	}

	rpc.Register(&notificationService)
	listener, err := net.Listen("unix", *socketFilename)
	if err != nil {
		log.Fatalf("Error listening to %s: %s", *socketFilename, err)
	}
	defer listener.Close()

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
	log.Printf("Listening for requests on %s...", *socketFilename)
	rpc.Accept(listener)
}
