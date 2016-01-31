package main

import (
	pb "../proto"

	"flag"
	"log"

	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

var (
	host  = flag.String("host", "localhost:50051", "address of host")
	title = flag.String("title", "", "title to send in notification")
	text  = flag.String("text", "", "text to send in notification")
)

// TODO(bran): add retry
func main() {
	// Parse & verify flags.
	flag.Parse()
	if *title == "" {
		log.Fatalf("--title is required")
	}
	if *text == "" {
		log.Fatalf("--text is required")
	}

	// Connect to RPC server.
	conn, err := grpc.Dial(*host, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("Error connecting to bnotifyd: %v", err)
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
		log.Fatalf("Error during SendNotification RPC: %v", err)
	}
}
