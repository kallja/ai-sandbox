package envelope

import (
	"crypto/ecdh"
	"fmt"

	"github.com/kallja/ai-sandbox/secure-message-exchange/crypto"
	"github.com/kallja/ai-sandbox/secure-message-exchange/wire"
)

// SealOuterEnvelope constructs the full 4096-byte request body by encrypting
// the routing header + inner envelope with a sealed box to the server's key.
func SealOuterEnvelope(
	routingHeader [wire.RoutingHeaderSize]byte,
	innerEnvelope [wire.InnerEnvelopeSize]byte,
	serverPub *ecdh.PublicKey,
) ([wire.OuterEnvelopeSize]byte, error) {
	var out [wire.OuterEnvelopeSize]byte

	// Build plaintext: routing header || inner envelope.
	plaintext := make([]byte, wire.OuterPlaintextSize)
	copy(plaintext[:wire.RoutingHeaderSize], routingHeader[:])
	copy(plaintext[wire.RoutingHeaderSize:], innerEnvelope[:])

	// Sealed box encrypt.
	ephPub, nonce, ct, err := crypto.SealedBoxSeal(plaintext, serverPub)
	if err != nil {
		return out, fmt.Errorf("seal outer envelope: %w", err)
	}

	// Verify sizes match the wire format.
	if len(ephPub) != wire.EphKeySize {
		return out, fmt.Errorf("ephemeral key size %d, want %d", len(ephPub), wire.EphKeySize)
	}
	if len(ct) != wire.OuterCiphertextSize {
		return out, fmt.Errorf("ciphertext size %d, want %d", len(ct), wire.OuterCiphertextSize)
	}

	// Assemble: ephPub || nonce || ciphertext.
	copy(out[wire.OuterEphKeyOffset:], ephPub)
	copy(out[wire.OuterNonceOffset:], nonce[:])
	copy(out[wire.OuterCiphertextOffset:], ct)

	return out, nil
}

// OpenOuterEnvelope decrypts a 4096-byte request body (server-side).
// Returns the routing header, inner envelope, and the client's ephemeral
// public key (needed for encrypting the response).
func OpenOuterEnvelope(
	data [wire.OuterEnvelopeSize]byte,
	serverPriv *ecdh.PrivateKey,
) (routingHeader [wire.RoutingHeaderSize]byte, innerEnvelope [wire.InnerEnvelopeSize]byte, ephPub [wire.EphKeySize]byte, err error) {
	// Extract fields.
	copy(ephPub[:], data[wire.OuterEphKeyOffset:wire.OuterNonceOffset])
	var nonce [wire.NonceSize]byte
	copy(nonce[:], data[wire.OuterNonceOffset:wire.OuterCiphertextOffset])
	ct := data[wire.OuterCiphertextOffset:]

	// Decrypt.
	plaintext, err := crypto.SealedBoxOpen(ct, nonce, ephPub[:], serverPriv)
	if err != nil {
		return routingHeader, innerEnvelope, ephPub, fmt.Errorf("open outer envelope: %w", err)
	}

	if len(plaintext) != wire.OuterPlaintextSize {
		return routingHeader, innerEnvelope, ephPub, fmt.Errorf("plaintext size %d, want %d", len(plaintext), wire.OuterPlaintextSize)
	}

	copy(routingHeader[:], plaintext[:wire.RoutingHeaderSize])
	copy(innerEnvelope[:], plaintext[wire.RoutingHeaderSize:])

	return routingHeader, innerEnvelope, ephPub, nil
}
