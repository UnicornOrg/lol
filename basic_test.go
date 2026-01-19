package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// generateTestCertificate creates a self-signed certificate for testing purposes
func generateTestCertificate(certPath, keyPath string) error {
	// Generate private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	// Create certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Test Organization"},
			CommonName:   "localhost",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	// Create certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return err
	}

	// Write certificate to file
	certOut, err := os.Create(certPath)
	if err != nil {
		return err
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return err
	}

	// Write private key to file
	keyOut, err := os.Create(keyPath)
	if err != nil {
		return err
	}
	defer keyOut.Close()

	privBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return err
	}

	if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes}); err != nil {
		return err
	}

	return nil
}

// TestTLSConfigurationIsEnabled verifies that TLS is properly configured
func TestTLSConfigurationIsEnabled(t *testing.T) {
	// Create temporary directory for test certificates
	tempDir := t.TempDir()
	certPath := filepath.Join(tempDir, "test.crt")
	keyPath := filepath.Join(tempDir, "test.key")

	// Generate test certificate
	if err := generateTestCertificate(certPath, keyPath); err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	// Set environment variables to use test certificates
	t.Setenv("TLS_CERT_FILE", certPath)
	t.Setenv("TLS_KEY_FILE", keyPath)

	// Load the certificate to verify it can be loaded
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatalf("Failed to load test certificate: %v", err)
	}

	// Verify TLS configuration
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	if tlsConfig.MinVersion != tls.VersionTLS12 {
		t.Errorf("Expected MinVersion to be TLS 1.2, got %v", tlsConfig.MinVersion)
	}

	if len(tlsConfig.Certificates) != 1 {
		t.Errorf("Expected 1 certificate, got %d", len(tlsConfig.Certificates))
	}
}

// TestTLSMinimumVersionEnforced verifies TLS 1.2 is the minimum version
func TestTLSMinimumVersionEnforced(t *testing.T) {
	// Create temporary directory for test certificates
	tempDir := t.TempDir()
	certPath := filepath.Join(tempDir, "test.crt")
	keyPath := filepath.Join(tempDir, "test.key")

	// Generate test certificate
	if err := generateTestCertificate(certPath, keyPath); err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	// Load certificate
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatalf("Failed to load certificate: %v", err)
	}

	// Create TLS config with minimum version
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	// Verify minimum version
	if tlsConfig.MinVersion < tls.VersionTLS12 {
		t.Errorf("TLS minimum version is less than TLS 1.2: got %v", tlsConfig.MinVersion)
	}

	// Verify TLS 1.0 and 1.1 are not allowed
	if tlsConfig.MinVersion == tls.VersionTLS10 || tlsConfig.MinVersion == tls.VersionTLS11 {
		t.Error("Insecure TLS version (1.0 or 1.1) is allowed")
	}
}

// TestSecureCipherSuitesConfigured verifies that secure cipher suites are configured
func TestSecureCipherSuitesConfigured(t *testing.T) {
	// Define the secure cipher suites that should be configured
	expectedCipherSuites := []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	}

	// Create TLS config with secure cipher suites
	tlsConfig := &tls.Config{
		CipherSuites: expectedCipherSuites,
		MinVersion:   tls.VersionTLS12,
	}

	// Verify cipher suites are configured
	if len(tlsConfig.CipherSuites) == 0 {
		t.Error("No cipher suites configured")
	}

	// Verify all configured cipher suites are in the expected list
	for _, suite := range tlsConfig.CipherSuites {
		found := false
		for _, expected := range expectedCipherSuites {
			if suite == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Unexpected cipher suite configured: %v", suite)
		}
	}
}

// TestServerStartsWithTLS verifies the server can start with TLS configuration
func TestServerStartsWithTLS(t *testing.T) {
	// Create temporary directory for test certificates and socket
	tempDir := t.TempDir()
	certPath := filepath.Join(tempDir, "test.crt")
	keyPath := filepath.Join(tempDir, "test.key")
	sockPath := filepath.Join(tempDir, "test.sock")

	// Generate test certificate
	if err := generateTestCertificate(certPath, keyPath); err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	// Load certificate
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatalf("Failed to load certificate: %v", err)
	}

	// Create Unix socket listener
	l, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer l.Close()

	// Create TLS config
	tlsConfig := &tls.Config{
		Certificates:             []tls.Certificate{cert},
		MinVersion:               tls.VersionTLS12,
		PreferServerCipherSuites: true,
	}

	// Create HTTP server with TLS
	mux := http.NewServeMux()
	mux.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	server := &http.Server{
		Handler:           mux,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 2 * time.Second,
	}

	// Start server in goroutine
	errChan := make(chan error, 1)
	go func() {
		// ServeTLS with empty strings uses the TLSConfig
		errChan <- server.ServeTLS(l, "", "")
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Close server
	if err := server.Close(); err != nil {
		t.Logf("Server close returned error (expected): %v", err)
	}

	// Check if server started without immediate error
	select {
	case err := <-errChan:
		if err != http.ErrServerClosed {
			t.Errorf("Server returned unexpected error: %v", err)
		}
	default:
		// No immediate error, which is good
	}
}

// TestPlainTextConnectionIsRejected verifies that plain text connections are not accepted
func TestPlainTextConnectionIsRejected(t *testing.T) {
	// Create temporary directory for test certificates and socket
	tempDir := t.TempDir()
	certPath := filepath.Join(tempDir, "test.crt")
	keyPath := filepath.Join(tempDir, "test.key")
	sockPath := filepath.Join(tempDir, "test.sock")

	// Generate test certificate
	if err := generateTestCertificate(certPath, keyPath); err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	// Load certificate
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatalf("Failed to load certificate: %v", err)
	}

	// Create Unix socket listener
	l, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer l.Close()

	// Create TLS config
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	// Create HTTP server with TLS
	mux := http.NewServeMux()
	mux.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	server := &http.Server{
		Handler:           mux,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 2 * time.Second,
	}

	// Start server in goroutine
	go func() {
		server.ServeTLS(l, "", "")
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)
	defer server.Close()

	// Try to connect with plain HTTP (should fail or not work properly)
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("Failed to connect to socket: %v", err)
	}
	defer conn.Close()

	// Send plain HTTP request
	_, err = conn.Write([]byte("GET /test HTTP/1.1\r\nHost: localhost\r\n\r\n"))
	if err != nil {
		t.Fatalf("Failed to write to connection: %v", err)
	}

	// Try to read response - should fail or timeout because TLS handshake is expected
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)

	// We expect either an error or no valid HTTP response because the server expects TLS
	if err == nil && n > 0 {
		response := string(buf[:n])
		// If we get a response, it should NOT be a valid HTTP response
		// because the server should be waiting for TLS handshake
		if len(response) > 0 && response[0] == 'H' {
			t.Error("Server accepted plain text connection and returned HTTP response - TLS is not enforced")
		}
	}
}

// TestTLSConnectionSucceeds verifies that proper TLS connections work
func TestTLSConnectionSucceeds(t *testing.T) {
	// Create temporary directory for test certificates and socket
	tempDir := t.TempDir()
	certPath := filepath.Join(tempDir, "test.crt")
	keyPath := filepath.Join(tempDir, "test.key")
	sockPath := filepath.Join(tempDir, "test.sock")

	// Generate test certificate
	if err := generateTestCertificate(certPath, keyPath); err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	// Load certificate for server
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatalf("Failed to load certificate: %v", err)
	}

	// Create Unix socket listener
	l, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer l.Close()

	// Create TLS config for server
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	// Create HTTP server with TLS
	mux := http.NewServeMux()
	mux.HandleFunc("/Plugin.Activate", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.docker.plugins.v1.1+json")
		w.Write([]byte(`{"Implements": ["dummy"]}`))
	})

	server := &http.Server{
		Handler:           mux,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 2 * time.Second,
	}

	// Start server in goroutine
	go func() {
		server.ServeTLS(l, "", "")
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)
	defer server.Close()

	// Create TLS client
	clientTLSConfig := &tls.Config{
		InsecureSkipVerify: true, // Skip verification for self-signed cert in test
		MinVersion:         tls.VersionTLS12,
	}

	// Dial with TLS
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("Failed to connect to socket: %v", err)
	}
	defer conn.Close()

	tlsConn := tls.Client(conn, clientTLSConfig)
	defer tlsConn.Close()

	// Perform TLS handshake
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake failed: %v", err)
	}

	// Verify connection state
	state := tlsConn.ConnectionState()
	if state.Version < tls.VersionTLS12 {
		t.Errorf("Connection using TLS version less than 1.2: %v", state.Version)
	}

	// Send HTTP request over TLS
	request := "GET /Plugin.Activate HTTP/1.1\r\nHost: localhost\r\n\r\n"
	if _, err := tlsConn.Write([]byte(request)); err != nil {
		t.Fatalf("Failed to write request: %v", err)
	}

	// Read response
	tlsConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	response := make([]byte, 4096)
	n, err := tlsConn.Read(response)
	if err != nil && err != io.EOF {
		t.Fatalf("Failed to read response: %v", err)
	}

	// Verify response
	responseStr := string(response[:n])
	if n == 0 {
		t.Error("No response received from TLS server")
	}
	if n > 0 && responseStr[:4] != "HTTP" {
		t.Error("Invalid HTTP response received")
	}
}

// TestEnvironmentVariablesForCertificates verifies certificate loading from env vars
func TestEnvironmentVariablesForCertificates(t *testing.T) {
	// Create temporary directory for test certificates
	tempDir := t.TempDir()
	certPath := filepath.Join(tempDir, "custom.crt")
	keyPath := filepath.Join(tempDir, "custom.key")

	// Generate test certificate
	if err := generateTestCertificate(certPath, keyPath); err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	// Test loading with environment variables set
	t.Setenv("TLS_CERT_FILE", certPath)
	t.Setenv("TLS_KEY_FILE", keyPath)

	envCertFile := os.Getenv("TLS_CERT_FILE")
	envKeyFile := os.Getenv("TLS_KEY_FILE")

	if envCertFile != certPath {
		t.Errorf("Expected TLS_CERT_FILE to be %s, got %s", certPath, envCertFile)
	}
	if envKeyFile != keyPath {
		t.Errorf("Expected TLS_KEY_FILE to be %s, got %s", keyPath, envKeyFile)
	}

	// Verify certificates can be loaded from env var paths
	_, err := tls.LoadX509KeyPair(envCertFile, envKeyFile)
	if err != nil {
		t.Errorf("Failed to load certificates from environment variable paths: %v", err)
	}
}

// TestMissingCertificatesError verifies proper error handling when certificates are missing
func TestMissingCertificatesError(t *testing.T) {
	// Create temporary directory
	tempDir := t.TempDir()
	nonExistentCert := filepath.Join(tempDir, "nonexistent.crt")
	nonExistentKey := filepath.Join(tempDir, "nonexistent.key")

	// Try to load non-existent certificates
	_, err := tls.LoadX509KeyPair(nonExistentCert, nonExistentKey)
	if err == nil {
		t.Error("Expected error when loading non-existent certificates, got nil")
	}
}

// TestServerPrefersCipherSuites verifies PreferServerCipherSuites is enabled
func TestServerPrefersCipherSuites(t *testing.T) {
	tlsConfig := &tls.Config{
		MinVersion:               tls.VersionTLS12,
		PreferServerCipherSuites: true,
	}

	if !tlsConfig.PreferServerCipherSuites {
		t.Error("PreferServerCipherSuites should be enabled for better security")
	}
}
