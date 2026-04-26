package envelope

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/kallja/ai-sandbox/secure-message-exchange/wire"
)

func TestBuildParseHandshake(t *testing.T) {
	ephKey := make([]byte, 32)
	rand.Read(ephKey)

	mlkemCt := make([]byte, 1088)
	rand.Read(mlkemCt)

	aeadCt := make([]byte, wire.HandshakeAEADCtSize)
	rand.Read(aeadCt)

	buf, err := BuildHandshakeInner(ephKey, mlkemCt, aeadCt)
	if err != nil {
		t.Fatal(err)
	}

	if len(buf) != wire.InnerEnvelopeSize {
		t.Fatalf("size = %d, want %d", len(buf), wire.InnerEnvelopeSize)
	}

	parsed, err := ParseInner(buf)
	if err != nil {
		t.Fatal(err)
	}

	h, ok := parsed.(*HandshakeInner)
	if !ok {
		t.Fatalf("expected *HandshakeInner, got %T", parsed)
	}
	if h.Type() != wire.TypeHandshake {
		t.Fatalf("type = 0x%02x, want 0x%02x", h.Type(), wire.TypeHandshake)
	}
	if !bytes.Equal(h.EphX25519Pub[:], ephKey) {
		t.Fatal("ephemeral key mismatch")
	}
	if !bytes.Equal(h.MLKEMCiphertext[:], mlkemCt) {
		t.Fatal("ML-KEM ciphertext mismatch")
	}
	if !bytes.Equal(h.AEADCiphertext, aeadCt) {
		t.Fatal("AEAD ciphertext mismatch")
	}
}

func TestBuildParseRatchet(t *testing.T) {
	ratchetPub := make([]byte, 32)
	rand.Read(ratchetPub)

	aeadCt := make([]byte, wire.RatchetAEADCtSize)
	rand.Read(aeadCt)

	buf, err := BuildRatchetInner(ratchetPub, 42, 7, aeadCt)
	if err != nil {
		t.Fatal(err)
	}

	if len(buf) != wire.InnerEnvelopeSize {
		t.Fatalf("size = %d, want %d", len(buf), wire.InnerEnvelopeSize)
	}

	parsed, err := ParseInner(buf)
	if err != nil {
		t.Fatal(err)
	}

	r, ok := parsed.(*RatchetInner)
	if !ok {
		t.Fatalf("expected *RatchetInner, got %T", parsed)
	}
	if r.Type() != wire.TypeRatchet {
		t.Fatalf("type = 0x%02x, want 0x%02x", r.Type(), wire.TypeRatchet)
	}
	if !bytes.Equal(r.RatchetPub[:], ratchetPub) {
		t.Fatal("ratchet pub mismatch")
	}
	if r.MessageNumber != 42 {
		t.Fatalf("message number = %d, want 42", r.MessageNumber)
	}
	if r.PrevChainLen != 7 {
		t.Fatalf("prev chain len = %d, want 7", r.PrevChainLen)
	}
	if !bytes.Equal(r.AEADCiphertext, aeadCt) {
		t.Fatal("AEAD ciphertext mismatch")
	}
}

func TestParseInner_UnknownType(t *testing.T) {
	var buf [wire.InnerEnvelopeSize]byte
	buf[0] = 0xff
	_, err := ParseInner(buf)
	if err == nil {
		t.Fatal("expected error for unknown type")
	}
}

func TestBuildHandshake_WrongEphKeySize(t *testing.T) {
	_, err := BuildHandshakeInner(make([]byte, 16), make([]byte, 1088), make([]byte, wire.HandshakeAEADCtSize))
	if err == nil {
		t.Fatal("expected error for wrong eph key size")
	}
}

func TestBuildHandshake_WrongMLKEMSize(t *testing.T) {
	_, err := BuildHandshakeInner(make([]byte, 32), make([]byte, 100), make([]byte, wire.HandshakeAEADCtSize))
	if err == nil {
		t.Fatal("expected error for wrong ML-KEM size")
	}
}

func TestBuildRatchet_WrongPubSize(t *testing.T) {
	_, err := BuildRatchetInner(make([]byte, 16), 0, 0, make([]byte, wire.RatchetAEADCtSize))
	if err == nil {
		t.Fatal("expected error for wrong ratchet pub size")
	}
}
