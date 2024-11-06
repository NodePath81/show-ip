package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"os"

	pb "show-ip/server/grpc-api"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func main() {
	// Define flags for the server address
	host := flag.String("host", "localhost", "The server host")
	port := flag.String("port", "50051", "The server port")
	certFile := flag.String("cert", "", "Path to the custom certificate file")
	skipVerify := flag.Bool("insecure", false, "Skip server certificate validation")

	// Parse the flags
	flag.Parse()

	// Construct the server address without DNS schema
	address := *host + ":" + *port

	var creds credentials.TransportCredentials

	if *certFile != "" {
		// Load custom certificate
		certPool := x509.NewCertPool()
		certData, err := os.ReadFile(*certFile)
		if err != nil {
			log.Fatalf("failed to read custom certificate file: %v", err)
		}
		if !certPool.AppendCertsFromPEM(certData) {
			log.Fatalf("failed to append custom certificate to pool")
		}
		creds = credentials.NewTLS(&tls.Config{
			RootCAs:            certPool,
			InsecureSkipVerify: *skipVerify,
		})
	} else {
		// Load system's root CA certificates
		systemRoots, err := x509.SystemCertPool()
		if err != nil {
			log.Fatalf("failed to load system root CA certificates: %v", err)
		}
		creds = credentials.NewTLS(&tls.Config{
			RootCAs:            systemRoots,
			InsecureSkipVerify: *skipVerify,
		})
	}

	// Set up
	conn, err := grpc.NewClient(address, grpc.WithTransportCredentials(creds))

	if err != nil {
		log.Fatalf("Could not connect: %v", err)
	}

	defer conn.Close()

	c := pb.NewShowIPServiceClient(conn)

	r, err := c.GetClientIP(context.Background(), &pb.ClientIPRequest{})
	if err != nil {
		log.Fatalf("Could not get IP: %v", err)
	}
	fmt.Printf("%s\n", r.GetIp())
}
