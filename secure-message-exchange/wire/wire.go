// Package wire defines the byte-level constants and helpers for the E2EE
// Relay Protocol wire format. All sizes account for the 16-byte AEAD
// overhead of XChaCha20-Poly1305.
package wire

import (
	"crypto/rand"
	"fmt"
)

// AEAD overhead: XChaCha20-Poly1305 Poly1305 authentication tag.
const AEADOverhead = 16

// --- Outer Envelope (Client → Server request) ---

const (
	OuterEnvelopeSize   = 4096
	EphKeySize          = 32  // X25519 ephemeral public key
	NonceSize           = 24  // XChaCha20 nonce
	OuterCiphertextSize = OuterEnvelopeSize - EphKeySize - NonceSize // 4040
	OuterPlaintextSize  = OuterCiphertextSize - AEADOverhead         // 4024
)

// Outer envelope byte offsets.
const (
	OuterEphKeyOffset      = 0
	OuterNonceOffset       = OuterEphKeyOffset + EphKeySize       // 32
	OuterCiphertextOffset  = OuterNonceOffset + NonceSize         // 56
)

// --- Routing Header (inside decrypted outer envelope) ---

const (
	RoutingHeaderSize = 256

	MessageIDSize         = 32
	FingerprintSize       = 32
	SignatureSize         = 64
	RoutingPaddingSize    = RoutingHeaderSize - MessageIDSize - 2*FingerprintSize - SignatureSize // 96

	MessageIDOffset       = 0
	SenderFPOffset        = MessageIDOffset + MessageIDSize       // 32
	RecipientFPOffset     = SenderFPOffset + FingerprintSize      // 64
	SignatureOffset       = RecipientFPOffset + FingerprintSize   // 96
	RoutingPaddingOffset  = SignatureOffset + SignatureSize        // 160
)

// --- Inner Envelope (E2EE peer-to-peer payload) ---

const (
	InnerEnvelopeSize = OuterPlaintextSize - RoutingHeaderSize // 3768
)

// Message types for the inner envelope.
const (
	TypeHandshake byte = 0x01
	TypeRatchet   byte = 0x02
)

// Handshake inner envelope field sizes.
const (
	HandshakeTypeSize     = 1
	HandshakeEphKeySize   = 32
	HandshakeMLKEMCtSize  = 1088
	HandshakeHeaderSize   = HandshakeTypeSize + HandshakeEphKeySize + HandshakeMLKEMCtSize // 1121
	HandshakeAEADCtSize   = InnerEnvelopeSize - HandshakeHeaderSize                        // 2647
	HandshakePlaintextMax = HandshakeAEADCtSize - AEADOverhead                             // 2631
)

// Handshake inner envelope byte offsets.
const (
	HandshakeTypeOffset    = 0
	HandshakeEphKeyOffset  = HandshakeTypeOffset + HandshakeTypeSize     // 1
	HandshakeMLKEMCtOffset = HandshakeEphKeyOffset + HandshakeEphKeySize // 33
	HandshakeAEADCtOffset  = HandshakeMLKEMCtOffset + HandshakeMLKEMCtSize // 1121
)

// Ratchet inner envelope field sizes.
const (
	RatchetTypeSize       = 1
	RatchetEphKeySize     = 32
	RatchetMsgNumSize     = 4
	RatchetPrevChainSize  = 4
	RatchetHeaderSize     = RatchetTypeSize + RatchetEphKeySize + RatchetMsgNumSize + RatchetPrevChainSize // 41
	RatchetAEADCtSize     = InnerEnvelopeSize - RatchetHeaderSize                                          // 3727
	RatchetPlaintextMax   = RatchetAEADCtSize - AEADOverhead                                               // 3711
)

// Ratchet inner envelope byte offsets.
const (
	RatchetTypeOffset      = 0
	RatchetEphKeyOffset    = RatchetTypeOffset + RatchetTypeSize           // 1
	RatchetMsgNumOffset    = RatchetEphKeyOffset + RatchetEphKeySize       // 33
	RatchetPrevChainOffset = RatchetMsgNumOffset + RatchetMsgNumSize       // 37
	RatchetAEADCtOffset    = RatchetPrevChainOffset + RatchetPrevChainSize // 41
)

// --- Server Response ---

const (
	ResponseSize           = 4096
	ResponseNonceSize      = 24
	ResponseCiphertextSize = ResponseSize - ResponseNonceSize          // 4072
	ResponsePlaintextSize  = ResponseCiphertextSize - AEADOverhead     // 4056
	StatusHeaderSize       = 256
	ResponsePayloadSize    = ResponsePlaintextSize - StatusHeaderSize   // 3800
)

// Response byte offsets.
const (
	ResponseNonceOffset      = 0
	ResponseCiphertextOffset = ResponseNonceOffset + ResponseNonceSize // 24
)

// Status codes in the server response status header.
const (
	StatusDataFollows byte = 0x01
	StatusQueueEmpty  byte = 0x02
	StatusErrAuthFail byte = 0x03
)

// --- Proof of Work ---

// DefaultPoWDifficulty is the number of leading zero bits required for V1.
const DefaultPoWDifficulty = 20

// --- Helpers ---

// PadToSize pads data with cryptographically random bytes to reach the
// target size. Returns an error if data is already larger than size.
func PadToSize(data []byte, size int) ([]byte, error) {
	if len(data) > size {
		return nil, fmt.Errorf("wire: data length %d exceeds target size %d", len(data), size)
	}
	if len(data) == size {
		out := make([]byte, size)
		copy(out, data)
		return out, nil
	}
	out := make([]byte, size)
	copy(out, data)
	if _, err := rand.Read(out[len(data):]); err != nil {
		return nil, fmt.Errorf("wire: random padding: %w", err)
	}
	return out, nil
}

// ValidateSize returns an error if the data length does not match expected.
func ValidateSize(data []byte, expected int, label string) error {
	if len(data) != expected {
		return fmt.Errorf("wire: %s: expected %d bytes, got %d", label, expected, len(data))
	}
	return nil
}
