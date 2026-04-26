package envelope

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"

	"github.com/kallja/ai-sandbox/secure-message-exchange/crypto"
	"github.com/kallja/ai-sandbox/secure-message-exchange/wire"

	"golang.org/x/crypto/chacha20poly1305"
)

// SealResponse constructs the 4096-byte server response. The response is
// encrypted using a key derived from the server's private key and the
// client's ephemeral public key (with response-specific domain separation).
func SealResponse(
	statusCode byte,
	payload []byte,
	serverPriv *ecdh.PrivateKey,
	clientEphPub [wire.EphKeySize]byte,
) ([wire.ResponseSize]byte, error) {
	var out [wire.ResponseSize]byte

	clientPub, err := ecdh.X25519().NewPublicKey(clientEphPub[:])
	if err != nil {
		return out, fmt.Errorf("parse client ephemeral key: %w", err)
	}

	// Build plaintext: status header + payload.
	plaintext := make([]byte, wire.ResponsePlaintextSize)
	plaintext[0] = statusCode
	// Bytes [1:256] of status header are padding (left as zero).

	if statusCode == wire.StatusDataFollows {
		if len(payload) > wire.ResponsePayloadSize {
			return out, fmt.Errorf("payload too large: %d > %d", len(payload), wire.ResponsePayloadSize)
		}
		copy(plaintext[wire.StatusHeaderSize:], payload)
		// Pad remainder with random noise.
		remaining := wire.ResponsePayloadSize - len(payload)
		if remaining > 0 {
			rand.Read(plaintext[wire.StatusHeaderSize+len(payload):])
		}
	} else {
		// QUEUE_EMPTY or ERR_AUTH_FAIL: fill payload region with random noise.
		rand.Read(plaintext[wire.StatusHeaderSize:])
	}

	// Derive response key with domain separation.
	symKey, err := crypto.DeriveResponseKey(serverPriv, clientPub)
	if err != nil {
		return out, fmt.Errorf("derive response key: %w", err)
	}
	defer crypto.Zero(symKey[:])

	aead, err := chacha20poly1305.NewX(symKey[:])
	if err != nil {
		return out, fmt.Errorf("create AEAD: %w", err)
	}

	var nonce [wire.ResponseNonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return out, fmt.Errorf("generate nonce: %w", err)
	}

	ct := aead.Seal(nil, nonce[:], plaintext, nil)
	if len(ct) != wire.ResponseCiphertextSize {
		return out, fmt.Errorf("response ciphertext size %d, want %d", len(ct), wire.ResponseCiphertextSize)
	}

	copy(out[wire.ResponseNonceOffset:], nonce[:])
	copy(out[wire.ResponseCiphertextOffset:], ct)

	return out, nil
}

// OpenResponse decrypts a 4096-byte server response (client-side).
// The client uses its ephemeral private key and the server's public key
// to derive the response decryption key.
func OpenResponse(
	data [wire.ResponseSize]byte,
	ephPriv *ecdh.PrivateKey,
	serverPub *ecdh.PublicKey,
) (statusCode byte, payload []byte, err error) {
	// Derive response key.
	symKey, err := crypto.DeriveResponseKey(ephPriv, serverPub)
	if err != nil {
		return 0, nil, fmt.Errorf("derive response key: %w", err)
	}
	defer crypto.Zero(symKey[:])

	aead, err := chacha20poly1305.NewX(symKey[:])
	if err != nil {
		return 0, nil, fmt.Errorf("create AEAD: %w", err)
	}

	var nonce [wire.ResponseNonceSize]byte
	copy(nonce[:], data[wire.ResponseNonceOffset:wire.ResponseCiphertextOffset])
	ct := data[wire.ResponseCiphertextOffset:]

	plaintext, err := aead.Open(nil, nonce[:], ct, nil)
	if err != nil {
		return 0, nil, fmt.Errorf("decrypt response: %w", err)
	}

	statusCode = plaintext[0]
	payload = make([]byte, wire.ResponsePayloadSize)
	copy(payload, plaintext[wire.StatusHeaderSize:])

	return statusCode, payload, nil
}
