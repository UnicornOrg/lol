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

	// Load TLS certificate from environment variables or default test paths
	certFile := os.Getenv("TLS_CERT_FILE")
	keyFile := os.Getenv("TLS_KEY_FILE")

	// For development/testing, provide default paths if not set
	if certFile == "" {
		certFile = "certs/server.crt"
	}
	if keyFile == "" {
		keyFile = "certs/server.key"
	}

	// Load TLS certificate and key
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatalf("Failed to load TLS certificate: %v. Set TLS_CERT_FILE and TLS_KEY_FILE environment variables or place certificates at %s and %s", err, certFile, keyFile)
	}

	// Configure TLS with secure settings
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12, // Enforce minimum TLS 1.2
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		},
		PreferServerCipherSuites: true,
	}

	server := http.Server{
		Addr:              l.Addr().String(),
		Handler:           mux,
		ReadHeaderTimeout: 2 * time.Second, // This server is not for production code; picked an arbitrary timeout to satisfy gosec (G112: Potential Slowloris Attack)
		TLSConfig:         tlsConfig,
	}

	mux.HandleFunc("/Plugin.Activate", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.docker.plugins.v1.1+json")
		fmt.Println(w, `{"Implements": ["dummy"]}`)
	})

	// Use ServeTLS instead of Serve to enable TLS encryption
	// Note: Since we're using a Unix socket, we need to use ServeTLS with empty cert/key paths
	// because the TLS config is already set in the server
	if err := server.ServeTLS(l, "", ""); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
