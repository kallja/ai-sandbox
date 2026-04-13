#!/bin/bash
set -euo pipefail

CERT_DIR="$(cd "$(dirname "$0")" && pwd)/certs"
mkdir -p "$CERT_DIR"

if [ -f "$CERT_DIR/mitmproxy-ca-cert.pem" ]; then
  echo "CA cert already exists at $CERT_DIR/mitmproxy-ca-cert.pem — skipping generation."
  echo "Delete proxy/certs/ and re-run to regenerate."
  exit 0
fi

echo "Generating mitmproxy CA certificate..."

openssl req -x509 -new -nodes \
  -days 3650 \
  -subj "/CN=mitmproxy" \
  -keyout "$CERT_DIR/mitmproxy-ca.key" \
  -out "$CERT_DIR/mitmproxy-ca-cert.pem" \
  2>/dev/null

# mitmproxy expects combined key+cert as mitmproxy-ca.pem
cat "$CERT_DIR/mitmproxy-ca.key" "$CERT_DIR/mitmproxy-ca-cert.pem" \
  > "$CERT_DIR/mitmproxy-ca.pem"

echo "CA cert generated at $CERT_DIR/"
