package envelope

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	ecrypto "github.com/kallja/ai-sandbox/secure-message-exchange/crypto"
	"github.com/kallja/ai-sandbox/secure-message-exchange/wire"
)

func TestOuterEnvelope_RoundTrip(t *testing.T) {
	serverPriv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	_, senderPriv, _ := ed25519.GenerateKey(rand.Reader)

	// Build inner envelope and routing header.
	var inner [wire.InnerEnvelopeSize]byte
	rand.Read(inner[:])

	recipientFP := ecrypto.Fingerprint(senderPriv.Public().(ed25519.PublicKey))
	rh, err := NewRoutingHeader(senderPriv, recipientFP, inner[:])
	if err != nil {
		t.Fatal(err)
	}
	rhBytes := rh.Marshal()

	// Seal.
	envelope, err := SealOuterEnvelope(rhBytes, inner, serverPriv.PublicKey())
	if err != nil {
		t.Fatal(err)
	}

	if len(envelope) != wire.OuterEnvelopeSize {
		t.Fatalf("envelope size = %d, want %d", len(envelope), wire.OuterEnvelopeSize)
	}

	// Open.
	gotRH, gotInner, _, err := OpenOuterEnvelope(envelope, serverPriv)
	if err != nil {
		t.Fatal(err)
	}

	if gotRH != rhBytes {
		t.Fatal("routing header mismatch after round-trip")
	}
	if gotInner != inner {
		t.Fatal("inner envelope mismatch after round-trip")
	}
}

func TestOuterEnvelope_WrongServerKey(t *testing.T) {
	serverPriv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	wrongPriv, _ := ecdh.X25519().GenerateKey(rand.Reader)

	var rh [wire.RoutingHeaderSize]byte
	var inner [wire.InnerEnvelopeSize]byte

	envelope, err := SealOuterEnvelope(rh, inner, serverPriv.PublicKey())
	if err != nil {
		t.Fatal(err)
	}

	_, _, _, err = OpenOuterEnvelope(envelope, wrongPriv)
	if err == nil {
		t.Fatal("expected decryption to fail with wrong server key")
	}
}

func TestOuterEnvelope_ExactSize(t *testing.T) {
	serverPriv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	var rh [wire.RoutingHeaderSize]byte
	var inner [wire.InnerEnvelopeSize]byte

	envelope, err := SealOuterEnvelope(rh, inner, serverPriv.PublicKey())
	if err != nil {
		t.Fatal(err)
	}

	if len(envelope) != 4096 {
		t.Fatalf("envelope size = %d, want 4096", len(envelope))
	}
}

func TestResponse_RoundTrip_DataFollows(t *testing.T) {
	serverPriv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	clientPriv, _ := ecdh.X25519().GenerateKey(rand.Reader)

	var ephPub [wire.EphKeySize]byte
	copy(ephPub[:], clientPriv.PublicKey().Bytes())

	payload := []byte("here is the inner envelope data for you")

	resp, err := SealResponse(wire.StatusDataFollows, payload, serverPriv, ephPub)
	if err != nil {
		t.Fatal(err)
	}

	if len(resp) != wire.ResponseSize {
		t.Fatalf("response size = %d, want %d", len(resp), wire.ResponseSize)
	}

	status, gotPayload, err := OpenResponse(resp, clientPriv, serverPriv.PublicKey())
	if err != nil {
		t.Fatal(err)
	}

	if status != wire.StatusDataFollows {
		t.Fatalf("status = 0x%02x, want 0x%02x", status, wire.StatusDataFollows)
	}
	if !bytes.Equal(gotPayload[:len(payload)], payload) {
		t.Fatal("payload mismatch")
	}
}

func TestResponse_RoundTrip_QueueEmpty(t *testing.T) {
	serverPriv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	clientPriv, _ := ecdh.X25519().GenerateKey(rand.Reader)

	var ephPub [wire.EphKeySize]byte
	copy(ephPub[:], clientPriv.PublicKey().Bytes())

	resp, err := SealResponse(wire.StatusQueueEmpty, nil, serverPriv, ephPub)
	if err != nil {
		t.Fatal(err)
	}

	status, _, err := OpenResponse(resp, clientPriv, serverPriv.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if status != wire.StatusQueueEmpty {
		t.Fatalf("status = 0x%02x, want 0x%02x", status, wire.StatusQueueEmpty)
	}
}

func TestResponse_RoundTrip_ErrAuthFail(t *testing.T) {
	serverPriv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	clientPriv, _ := ecdh.X25519().GenerateKey(rand.Reader)

	var ephPub [wire.EphKeySize]byte
	copy(ephPub[:], clientPriv.PublicKey().Bytes())

	resp, err := SealResponse(wire.StatusErrAuthFail, nil, serverPriv, ephPub)
	if err != nil {
		t.Fatal(err)
	}

	status, _, err := OpenResponse(resp, clientPriv, serverPriv.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if status != wire.StatusErrAuthFail {
		t.Fatalf("status = 0x%02x, want 0x%02x", status, wire.StatusErrAuthFail)
	}
}

func TestResponse_ExactSize(t *testing.T) {
	serverPriv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	clientPriv, _ := ecdh.X25519().GenerateKey(rand.Reader)

	var ephPub [wire.EphKeySize]byte
	copy(ephPub[:], clientPriv.PublicKey().Bytes())

	for _, status := range []byte{wire.StatusDataFollows, wire.StatusQueueEmpty, wire.StatusErrAuthFail} {
		resp, err := SealResponse(status, []byte("test"), serverPriv, ephPub)
		if err != nil {
			t.Fatal(err)
		}
		if len(resp) != 4096 {
			t.Fatalf("status 0x%02x: response size = %d, want 4096", status, len(resp))
		}
	}
}

func TestResponse_WrongClientKey(t *testing.T) {
	serverPriv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	clientPriv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	wrongPriv, _ := ecdh.X25519().GenerateKey(rand.Reader)

	var ephPub [wire.EphKeySize]byte
	copy(ephPub[:], clientPriv.PublicKey().Bytes())

	resp, err := SealResponse(wire.StatusQueueEmpty, nil, serverPriv, ephPub)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = OpenResponse(resp, wrongPriv, serverPriv.PublicKey())
	if err == nil {
		t.Fatal("expected decryption to fail with wrong client key")
	}
}
