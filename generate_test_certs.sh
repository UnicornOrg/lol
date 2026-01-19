#!/bin/bash
# Script to generate self-signed test certificates for TLS server

set -e

CERT_DIR="${1:-./certs}"

echo "Creating certificate directory at $CERT_DIR..."
mkdir -p "$CERT_DIR"

echo "Generating private key..."
openssl ecparam -genkey -name prime256v1 -out "$CERT_DIR/server.key"

echo "Generating self-signed certificate..."
openssl req -new -x509 -key "$CERT_DIR/server.key" -out "$CERT_DIR/server.crt" -days 365 \
    -subj "/C=US/ST=Test/L=Test/O=Test Organization/CN=localhost"

echo ""
echo "Test certificates generated successfully!"
echo "Certificate: $CERT_DIR/server.crt"
echo "Private Key: $CERT_DIR/server.key"
echo ""
echo "You can now run the application with:"
echo "  export TLS_CERT_FILE=$CERT_DIR/server.crt"
echo "  export TLS_KEY_FILE=$CERT_DIR/server.key"
echo "  go run basic.go"
