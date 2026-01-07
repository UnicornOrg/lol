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

	mux := http.NewServeMux()

	// Configure TLS with secure settings to prevent plain text transport
	tlsConfig := &tls.Config{
		MinVersion:               tls.VersionTLS12, // Minimum TLS 1.2
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
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

	// Use ServeTLS with a TLS listener instead of plain Serve
	// For production, replace with actual certificate and key files
	// For now, using self-signed certificates from environment variables or generate them
	certFile := os.Getenv("TLS_CERT_FILE")
	keyFile := os.Getenv("TLS_KEY_FILE")

	if certFile == "" {
		certFile = filepath.Join(p, "server.crt")
	}
	if keyFile == "" {
		keyFile = filepath.Join(p, "server.key")
	}

	// Wrap the listener with TLS
	tlsListener := tls.NewListener(l, tlsConfig)

	// Load certificates and serve over TLS
	if err := server.ServeTLS(tlsListener, certFile, keyFile); err != nil {
		panic(err)
	}
}
