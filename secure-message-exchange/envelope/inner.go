package envelope

import (
	"encoding/binary"
	"fmt"

	"github.com/kallja/ai-sandbox/secure-message-exchange/wire"
)

// InnerEnvelope is the interface for parsed inner envelopes.
type InnerEnvelope interface {
	Type() byte
}

// HandshakeInner holds the fields of a handshake inner envelope (type 0x01).
type HandshakeInner struct {
	EphX25519Pub    [32]byte
	MLKEMCiphertext [1088]byte
	AEADCiphertext  []byte // wire.HandshakeAEADCtSize bytes
}

func (h *HandshakeInner) Type() byte { return wire.TypeHandshake }

// RatchetInner holds the fields of a ratcheted inner envelope (type 0x02).
type RatchetInner struct {
	RatchetPub     [32]byte
	MessageNumber  uint32
	PrevChainLen   uint32
	AEADCiphertext []byte // wire.RatchetAEADCtSize bytes
}

func (r *RatchetInner) Type() byte { return wire.TypeRatchet }

// BuildHandshakeInner serializes a handshake inner envelope to exactly
// InnerEnvelopeSize bytes.
func BuildHandshakeInner(ephX25519Pub []byte, mlkemCiphertext []byte, aeadCiphertext []byte) ([wire.InnerEnvelopeSize]byte, error) {
	var buf [wire.InnerEnvelopeSize]byte

	if len(ephX25519Pub) != wire.HandshakeEphKeySize {
		return buf, fmt.Errorf("ephemeral X25519 key: got %d bytes, want %d", len(ephX25519Pub), wire.HandshakeEphKeySize)
	}
	if len(mlkemCiphertext) != wire.HandshakeMLKEMCtSize {
		return buf, fmt.Errorf("ML-KEM ciphertext: got %d bytes, want %d", len(mlkemCiphertext), wire.HandshakeMLKEMCtSize)
	}
	if len(aeadCiphertext) > wire.HandshakeAEADCtSize {
		return buf, fmt.Errorf("AEAD ciphertext: got %d bytes, max %d", len(aeadCiphertext), wire.HandshakeAEADCtSize)
	}

	buf[wire.HandshakeTypeOffset] = wire.TypeHandshake
	copy(buf[wire.HandshakeEphKeyOffset:], ephX25519Pub)
	copy(buf[wire.HandshakeMLKEMCtOffset:], mlkemCiphertext)
	copy(buf[wire.HandshakeAEADCtOffset:], aeadCiphertext)
	// Remaining bytes are zero-padded (AEAD ciphertext should fill exactly).

	return buf, nil
}

// BuildRatchetInner serializes a ratcheted inner envelope to exactly
// InnerEnvelopeSize bytes.
func BuildRatchetInner(ratchetPub []byte, msgNum, prevChain uint32, aeadCiphertext []byte) ([wire.InnerEnvelopeSize]byte, error) {
	var buf [wire.InnerEnvelopeSize]byte

	if len(ratchetPub) != wire.RatchetEphKeySize {
		return buf, fmt.Errorf("ratchet public key: got %d bytes, want %d", len(ratchetPub), wire.RatchetEphKeySize)
	}
	if len(aeadCiphertext) > wire.RatchetAEADCtSize {
		return buf, fmt.Errorf("AEAD ciphertext: got %d bytes, max %d", len(aeadCiphertext), wire.RatchetAEADCtSize)
	}

	buf[wire.RatchetTypeOffset] = wire.TypeRatchet
	copy(buf[wire.RatchetEphKeyOffset:], ratchetPub)
	binary.BigEndian.PutUint32(buf[wire.RatchetMsgNumOffset:], msgNum)
	binary.BigEndian.PutUint32(buf[wire.RatchetPrevChainOffset:], prevChain)
	copy(buf[wire.RatchetAEADCtOffset:], aeadCiphertext)

	return buf, nil
}

// ParseInner reads the type byte and dispatches to the appropriate parser.
func ParseInner(data [wire.InnerEnvelopeSize]byte) (InnerEnvelope, error) {
	switch data[0] {
	case wire.TypeHandshake:
		return parseHandshakeInner(data), nil
	case wire.TypeRatchet:
		return parseRatchetInner(data), nil
	default:
		return nil, fmt.Errorf("unknown inner envelope type: 0x%02x", data[0])
	}
}

func parseHandshakeInner(data [wire.InnerEnvelopeSize]byte) *HandshakeInner {
	h := &HandshakeInner{}
	copy(h.EphX25519Pub[:], data[wire.HandshakeEphKeyOffset:])
	copy(h.MLKEMCiphertext[:], data[wire.HandshakeMLKEMCtOffset:])
	h.AEADCiphertext = make([]byte, wire.HandshakeAEADCtSize)
	copy(h.AEADCiphertext, data[wire.HandshakeAEADCtOffset:])
	return h
}

func parseRatchetInner(data [wire.InnerEnvelopeSize]byte) *RatchetInner {
	r := &RatchetInner{}
	copy(r.RatchetPub[:], data[wire.RatchetEphKeyOffset:])
	r.MessageNumber = binary.BigEndian.Uint32(data[wire.RatchetMsgNumOffset:])
	r.PrevChainLen = binary.BigEndian.Uint32(data[wire.RatchetPrevChainOffset:])
	r.AEADCiphertext = make([]byte, wire.RatchetAEADCtSize)
	copy(r.AEADCiphertext, data[wire.RatchetAEADCtOffset:])
	return r
}
