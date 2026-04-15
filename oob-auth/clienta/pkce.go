// Package clienta implements the Requester side of the OOB-Auth protocol.
// It generates PKCE challenges, encrypts OAuth intents, publishes them
// to the relay, and waits for the Broker's encrypted response.
package clienta

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

const codeVerifierLength = 32 // 32 bytes → 43 base64url chars

// GeneratePKCE creates a PKCE code_verifier and its corresponding
// code_challenge (S256). The caller must zero the verifier after use.
func GeneratePKCE() (verifier string, challenge string, err error) {
	buf := make([]byte, codeVerifierLength)
	if _, err := rand.Read(buf); err != nil {
		return "", "", err
	}
	verifier = base64.RawURLEncoding.EncodeToString(buf)
	challenge = computeS256Challenge(verifier)
	return verifier, challenge, nil
}

// computeS256Challenge returns base64url(SHA-256(verifier)).
func computeS256Challenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}
