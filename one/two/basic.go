package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

func main() {
	p, err := filepath.Abs(filepath.Join("run", "docker", "plugins"))
	if err != nil {
		panic(err)
	}
	if err := os.MkdirAll(p, 0o755); err != nil {
		panic(err)
	}
	l, err := net.Listen("unix", filepath.Join(p, "basic.sock"))
	if err != nil {
		panic(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/Plugin.Activate", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.docker.plugins.v1.1+json")
		fmt.Println(w, `{"Implements": ["dummy"]}`)
	})

	// Configure TLS with secure settings
	tlsConfig := &tls.Config{
		MinVersion:               tls.VersionTLS12, // Enforce TLS 1.2 minimum
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		},
	}

	server := http.Server{
		Addr:              l.Addr().String(),
		Handler:           mux,
		ReadHeaderTimeout: 2 * time.Second, // This server is not for production code; picked an arbitrary timeout to satisfy gosec (G112: Potential Slowloris Attack)
		TLSConfig:         tlsConfig,
	}

	// Get TLS certificate and key paths from environment variables
	certFile := os.Getenv("TLS_CERT_FILE")
	keyFile := os.Getenv("TLS_KEY_FILE")

	// Default certificate paths if not specified
	if certFile == "" {
		certFile = filepath.Join(p, "server.crt")
	}
	if keyFile == "" {
		keyFile = filepath.Join(p, "server.key")
	}

	// Check if certificate files exist, generate self-signed if needed for development
	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		log.Printf("TLS certificate not found at %s. Please provide valid TLS certificates via TLS_CERT_FILE and TLS_KEY_FILE environment variables.", certFile)
		log.Fatal("Server requires TLS certificates to start securely")
	}

	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		log.Printf("TLS key not found at %s. Please provide valid TLS certificates via TLS_CERT_FILE and TLS_KEY_FILE environment variables.", keyFile)
		log.Fatal("Server requires TLS certificates to start securely")
	}

	// Use ServeTLS instead of Serve to enable encrypted transport
	if err := server.ServeTLS(l, certFile, keyFile); err != nil {
		log.Fatalf("Server failed to start with TLS: %v", err)
	}
}
