package envelope

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/kallja/ai-sandbox/secure-message-exchange/crypto"
	"github.com/kallja/ai-sandbox/secure-message-exchange/wire"
)

func TestRoutingHeader_MarshalParse(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	recipientFP := crypto.Fingerprint(pub) // using self as recipient for simplicity
	inner := make([]byte, wire.InnerEnvelopeSize)
	rand.Read(inner)

	rh, err := NewRoutingHeader(priv, recipientFP, inner)
	if err != nil {
		t.Fatal(err)
	}

	buf := rh.Marshal()
	parsed := ParseRoutingHeader(buf)

	if parsed.MessageID != rh.MessageID {
		t.Fatal("MessageID mismatch")
	}
	if parsed.SenderFingerprint != rh.SenderFingerprint {
		t.Fatal("SenderFingerprint mismatch")
	}
	if parsed.RecipientFingerprint != rh.RecipientFingerprint {
		t.Fatal("RecipientFingerprint mismatch")
	}
	if parsed.Signature != rh.Signature {
		t.Fatal("Signature mismatch")
	}
}

func TestRoutingHeader_Verify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	recipientFP := [32]byte{0x01}
	inner := []byte("test inner envelope data")

	rh, err := NewRoutingHeader(priv, recipientFP, inner)
	if err != nil {
		t.Fatal(err)
	}

	if !rh.Verify(pub, inner) {
		t.Fatal("valid signature failed verification")
	}
}

func TestRoutingHeader_VerifyTamperedHeader(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	inner := []byte("test inner")

	rh, _ := NewRoutingHeader(priv, [32]byte{}, inner)

	// Tamper with the message ID.
	rh.MessageID[0] ^= 0xff
	if rh.Verify(pub, inner) {
		t.Fatal("tampered header should fail verification")
	}
}

func TestRoutingHeader_VerifyTamperedInner(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	inner := []byte("original")

	rh, _ := NewRoutingHeader(priv, [32]byte{}, inner)

	if rh.Verify(pub, []byte("tampered")) {
		t.Fatal("tampered inner envelope should fail verification")
	}
}

func TestRoutingHeader_VerifyWrongKey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	wrongPub, _, _ := ed25519.GenerateKey(rand.Reader)
	inner := []byte("test")

	rh, _ := NewRoutingHeader(priv, [32]byte{}, inner)

	if rh.Verify(wrongPub, inner) {
		t.Fatal("wrong public key should fail verification")
	}
}

func TestRoutingHeader_UniqueMessageID(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	inner := []byte("test")

	rh1, _ := NewRoutingHeader(priv, [32]byte{}, inner)
	rh2, _ := NewRoutingHeader(priv, [32]byte{}, inner)

	if rh1.MessageID == rh2.MessageID {
		t.Fatal("two routing headers have the same MessageID")
	}
}

func TestRoutingHeader_MarshalSize(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	rh, _ := NewRoutingHeader(priv, [32]byte{}, []byte("test"))
	buf := rh.Marshal()
	if len(buf) != wire.RoutingHeaderSize {
		t.Fatalf("marshal size = %d, want %d", len(buf), wire.RoutingHeaderSize)
	}
}
