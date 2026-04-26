// Package envelope handles construction and parsing of the E2EE Relay
// Protocol's fixed-size wire-format messages.
package envelope

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"

	"github.com/kallja/ai-sandbox/secure-message-exchange/crypto"
	"github.com/kallja/ai-sandbox/secure-message-exchange/wire"
)

// RoutingHeader holds the parsed fields of a 256-byte routing header.
type RoutingHeader struct {
	MessageID            [32]byte
	SenderFingerprint    [32]byte
	RecipientFingerprint [32]byte
	Signature            [64]byte
}

// NewRoutingHeader builds a routing header, signing it with the sender's
// Ed25519 private key. The signature covers MessageID || SenderFP ||
// RecipientFP || innerEnvelope.
func NewRoutingHeader(
	senderPriv ed25519.PrivateKey,
	recipientFingerprint [32]byte,
	innerEnvelope []byte,
) (*RoutingHeader, error) {
	rh := &RoutingHeader{
		SenderFingerprint:    crypto.Fingerprint(senderPriv.Public().(ed25519.PublicKey)),
		RecipientFingerprint: recipientFingerprint,
	}

	if _, err := rand.Read(rh.MessageID[:]); err != nil {
		return nil, fmt.Errorf("generate message ID: %w", err)
	}

	sigData := rh.signatureInput(innerEnvelope)
	copy(rh.Signature[:], ed25519.Sign(senderPriv, sigData))

	return rh, nil
}

// Marshal serializes the routing header to exactly 256 bytes.
func (rh *RoutingHeader) Marshal() [wire.RoutingHeaderSize]byte {
	var buf [wire.RoutingHeaderSize]byte
	copy(buf[wire.MessageIDOffset:], rh.MessageID[:])
	copy(buf[wire.SenderFPOffset:], rh.SenderFingerprint[:])
	copy(buf[wire.RecipientFPOffset:], rh.RecipientFingerprint[:])
	copy(buf[wire.SignatureOffset:], rh.Signature[:])
	// Remaining bytes [160:255] are zero-padded.
	return buf
}

// ParseRoutingHeader deserializes a 256-byte routing header.
func ParseRoutingHeader(data [wire.RoutingHeaderSize]byte) *RoutingHeader {
	rh := &RoutingHeader{}
	copy(rh.MessageID[:], data[wire.MessageIDOffset:])
	copy(rh.SenderFingerprint[:], data[wire.SenderFPOffset:])
	copy(rh.RecipientFingerprint[:], data[wire.RecipientFPOffset:])
	copy(rh.Signature[:], data[wire.SignatureOffset:])
	return rh
}

// Verify checks the Ed25519 signature against the sender's public key
// and the inner envelope data. Returns true if valid.
func (rh *RoutingHeader) Verify(senderPub ed25519.PublicKey, innerEnvelope []byte) bool {
	sigData := rh.signatureInput(innerEnvelope)
	return ed25519.Verify(senderPub, sigData, rh.Signature[:])
}

// signatureInput builds the data that is signed: MessageID || SenderFP || RecipientFP || innerEnvelope.
func (rh *RoutingHeader) signatureInput(innerEnvelope []byte) []byte {
	data := make([]byte, 32+32+32+len(innerEnvelope))
	copy(data[0:], rh.MessageID[:])
	copy(data[32:], rh.SenderFingerprint[:])
	copy(data[64:], rh.RecipientFingerprint[:])
	copy(data[96:], innerEnvelope)
	return data
}
