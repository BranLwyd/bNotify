package main

import (
	pb "../proto"

	"flag"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"log"
)

// Flags
var (
	host  = flag.String("host", "localhost:50051", "address of host")
	title = flag.String("title", "", "title to send in notification")
	text  = flag.String("text", "", "text to send in notification")
)

// Code
func main() {
	// Parse flags.
	flag.Parse()

	// Connect to RPC server.
	conn, err := grpc.Dial(*host)
	if err != nil {
		log.Fatalf("Error connecting to bnotifyd server: %s", err)
	}
	defer conn.Close()
	ns := pb.NewNotificationServiceClient(conn)

	// Make request.
	request := &pb.SendNotificationRequest{
		Notification: &pb.Notification{
			Title: *title,
			Text:  *text,
		},
	}
	_, err = ns.SendNotification(context.Background(), request)
	if err != nil {
		log.Fatalf("Error during bnotify RPC: %s", err)
	}
}
