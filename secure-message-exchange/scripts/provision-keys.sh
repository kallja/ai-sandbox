#!/usr/bin/env bash
set -euo pipefail

PROJECT="${GCP_PROJECT:?Set GCP_PROJECT environment variable}"

SCRIPT_DIR="$(cd "$(dirname "${0}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

KEY_DIR=$(mktemp -d)
trap 'rm -rf "${KEY_DIR}"' EXIT

echo "=== E2EE Relay Key Provisioning ==="
echo ""
echo "Generating relay server identity keys..."
go run "${ROOT_DIR}/cmd/keygen" --dir="${KEY_DIR}"

echo ""
echo "Uploading Ed25519 private key to Secret Manager..."
gcloud secrets versions add e2ee-relay-ed25519-private \
  --project="${PROJECT}" \
  --data-file="${KEY_DIR}/ed25519.pem"

echo "Uploading X25519 private key to Secret Manager..."
gcloud secrets versions add e2ee-relay-x25519-private \
  --project="${PROJECT}" \
  --data-file="${KEY_DIR}/x25519.pem"

echo "Uploading Ed25519 public key to Secret Manager..."
gcloud secrets versions add e2ee-relay-ed25519-public \
  --project="${PROJECT}" \
  --data-file="${KEY_DIR}/ed25519.pub"

echo "Uploading X25519 public key to Secret Manager..."
gcloud secrets versions add e2ee-relay-x25519-public \
  --project="${PROJECT}" \
  --data-file="${KEY_DIR}/x25519.pub"

echo ""
echo "=== Key Provisioning Complete ==="
echo ""
echo "Relay server fingerprint:"
cat "${KEY_DIR}/fingerprint.txt"
echo ""
echo "Public keys for client configuration:"
echo "  Ed25519: $(cat "${KEY_DIR}/ed25519.pub" | base64)"
echo "  X25519:  $(cat "${KEY_DIR}/x25519.pub" | base64)"
echo ""
echo "Add these to your client peer config files under the 'relay' section."
