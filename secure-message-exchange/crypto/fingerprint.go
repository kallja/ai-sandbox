// Package crypto provides cryptographic primitives for the E2EE Relay Protocol.
package crypto

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
)

// Fingerprint returns the 32-byte SHA-256 hash of a raw Ed25519 public key.
// This is the routing fingerprint used in the protocol's routing header.
func Fingerprint(pub ed25519.PublicKey) [32]byte {
	return sha256.Sum256(pub)
}

// FingerprintHex returns the hex-encoded fingerprint string.
func FingerprintHex(pub ed25519.PublicKey) string {
	fp := Fingerprint(pub)
	return hex.EncodeToString(fp[:])
}
