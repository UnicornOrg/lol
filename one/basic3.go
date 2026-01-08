package main

import (
	"crypto/tls"
	"fmt"
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

	// Load TLS certificate and key from environment variables or default paths
	certFile := os.Getenv("TLS_CERT_FILE")
	keyFile := os.Getenv("TLS_KEY_FILE")
	if certFile == "" {
		certFile = filepath.Join(p, "server.crt")
	}
	if keyFile == "" {
		keyFile = filepath.Join(p, "server.key")
	}

	// Load the TLS certificate
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		panic(fmt.Sprintf("failed to load TLS certificates: %v", err))
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

	mux := http.NewServeMux()
	server := http.Server{
		Addr:              l.Addr().String(),
		ReadHeaderTimeout: 2 * time.Second,
		TLSConfig:         tlsConfig,
	}
	mux.HandleFunc("/Plugin.Activate", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.docker.plugins.v1.1+json")
		fmt.Println(w, `{"Implements": ["dummy"]}`)
	})

	// Use ServeTLS instead of Serve to enable encrypted transport
	// Pass empty strings since certificates are already loaded in TLSConfig
	if err := server.ServeTLS(l, "", ""); err != nil {
		panic(fmt.Sprintf("failed to start TLS server: %v", err))
	}
}
