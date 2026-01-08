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
	p, err := filepath.Abs(filepath.Join("run", "docker2", "plugins2"))
	
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

	// Configure TLS with secure settings to prevent plaintext transport
	tlsConfig := &tls.Config{
		MinVersion:               tls.VersionTLS12, // Minimum TLS 1.2
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		},
	}

	server := http.Server{
		Addr:              l.Addr().String(),
		Handler:           mux,
		ReadHeaderTimeout: 2 * time.Second, // This server is not for production code; picked an arbitrary timeout to statisfy gosec (G112: Potential Slowloris Attack)
		TLSConfig:         tlsConfig,
	}

	mux.HandleFunc("/Plugin.Activate", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.docker.plugins.v1.1+json")
		fmt.Println(w, `{"Implements": ["dummy"]}`)
	})

	// Load TLS certificates from environment variables or use defaults
	certFile := os.Getenv("TLS_CERT_FILE")
	keyFile := os.Getenv("TLS_KEY_FILE")

	if certFile == "" {
		certFile = "server.crt"
	}
	if keyFile == "" {
		keyFile = "server.key"
	}

	// Use ServeTLS instead of Serve to enable encrypted transport
	if err := server.ServeTLS(l, certFile, keyFile); err != nil {
		panic(err)
	}
}
