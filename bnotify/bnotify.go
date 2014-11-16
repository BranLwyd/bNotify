package main

import (
	"flag"
	"log"
	"net/http"
	"net/rpc"
)

// Flags
var (
	socketFilename = flag.String("socket_filename", "bnotify.sock", "path of UNIX socket to listen to RPCs on")
	title          = flag.String("title", "", "title to send in notification")
	text           = flag.String("text", "", "text to send in notification")
)

// Types
// TODO(bran): don't C&P from bnotifyd.go
type NotificationService struct {
	httpClient     *http.Client
	apiKey         string
	registrationId string
}

type NotificationRequest struct {
	Title string `json:"title"`
	Text  string `json:"text"`
}

type NotificationResponse struct{}

// Code
func main() {
	// Parse flags.
	flag.Parse()

	// Connect to RPC server.
	client, err := rpc.Dial("unix", *socketFilename)
	if err != nil {
		log.Fatalf("Error connecting to bnotifyd server: %s", err)
	}

	// Make request.
	request := NotificationRequest{Title: *title, Text: *text}
	var reply NotificationResponse
	err = client.Call("NotificationService.Notify", request, &reply)
	if err != nil {
		log.Fatalf("Error during bnotify RPC: %s", err)
	}
}
