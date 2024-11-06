package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"log"
	"math/big"
	"net"
	"os"
	"strconv"
	"time"

	pb "show-ip/server/grpc-api"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

type server struct {
	pb.UnimplementedShowIPServiceServer
}

func (s *server) GetClientIP(ctx context.Context, in *pb.ClientIPRequest) (*pb.ClientIPReply, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil, status.Errorf(codes.Internal, "could not get peer from context")
	}
	host, _, err := net.SplitHostPort(p.Addr.String())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "could not split host and port: %v", err)
	}
	return &pb.ClientIPReply{Ip: host}, nil
}

func generateSelfSignedCert(certPath, keyPath, commonName string) (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"My Organization"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{commonName},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	certOut, err := os.Create(certPath)
	if err != nil {
		return tls.Certificate{}, err
	}
	defer certOut.Close()
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	keyOut, err := os.Create(keyPath)
	if err != nil {
		return tls.Certificate{}, err
	}
	defer keyOut.Close()
	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})

	return tls.LoadX509KeyPair(certPath, keyPath)
}

func main() {
	port := flag.Uint("port", 50051, "The server port")
	certFile := flag.String("cert", "server.crt", "Path to the server certificate file")
	keyFile := flag.String("key", "server.key", "Path to the server key file")
	commonName := flag.String("cn", "localhost", "Common Name for the self-signed certificate")

	// Parse the flags
	flag.Parse()

	var creds credentials.TransportCredentials
	var err error

	checkAndGenerateCert := func(certFile, keyFile string) (tls.Certificate, error) {
		if fileExists(certFile) && fileExists(keyFile) {
			cert, err := tls.LoadX509KeyPair(certFile, keyFile)
			if err == nil {
				return cert, nil
			}
			log.Printf("failed to load existing certificate and key, generating new ones: %v", err)
		}
		return generateSelfSignedCert(certFile, keyFile, *commonName)
	}

	if *certFile == "server.crt" && *keyFile == "server.key" {
		// Check existence and validation of default cert and key
		cert, err := checkAndGenerateCert(*certFile, *keyFile)
		if err != nil {
			log.Fatalf("failed to generate or load certificate: %v", err)
		}
		creds = credentials.NewTLS(&tls.Config{
			Certificates: []tls.Certificate{cert},
		})
	} else {
		// Load server's certificate and private key
		serverCert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
		if err != nil {
			log.Fatalf("failed to load server certificate and key: %v", err)
		}
		creds = credentials.NewTLS(&tls.Config{
			Certificates: []tls.Certificate{serverCert},
		})
	}

	// Convert port to string
	portStr := strconv.FormatUint(uint64(*port), 10)

	lis, err := net.Listen("tcp", "[::]:"+portStr)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer(grpc.Creds(creds))
	pb.RegisterShowIPServiceServer(s, &server{})
	log.Printf("server listening at %v", lis.Addr())
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}
