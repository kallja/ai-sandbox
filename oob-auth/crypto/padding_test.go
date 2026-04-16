package crypto

import (
	"bytes"
	"testing"
)

func TestPad_Basic(t *testing.T) {
	msg := []byte("hello")
	padded, err := Pad(msg, 16)
	if err != nil {
		t.Fatalf("Pad: %v", err)
	}
	if len(padded) != 16 {
		t.Fatalf("len = %d, want 16", len(padded))
	}
	// First 5 bytes are the message.
	if !bytes.Equal(padded[:5], msg) {
		t.Errorf("message portion = %v, want %v", padded[:5], msg)
	}
	// Byte 5 is the 0x01 marker.
	if padded[5] != 0x01 {
		t.Errorf("marker byte = 0x%02x, want 0x01", padded[5])
	}
	// Remaining bytes are 0x00.
	for i := 6; i < 16; i++ {
		if padded[i] != 0x00 {
			t.Errorf("padded[%d] = 0x%02x, want 0x00", i, padded[i])
		}
	}
}

func TestPad_EmptyMessage(t *testing.T) {
	padded, err := Pad([]byte{}, 8)
	if err != nil {
		t.Fatalf("Pad: %v", err)
	}
	if padded[0] != 0x01 {
		t.Errorf("padded[0] = 0x%02x, want 0x01", padded[0])
	}
	for i := 1; i < 8; i++ {
		if padded[i] != 0x00 {
			t.Errorf("padded[%d] = 0x%02x, want 0x00", i, padded[i])
		}
	}
}

func TestPad_MaxMessage(t *testing.T) {
	// Message fills all but the last byte (which becomes the marker).
	msg := bytes.Repeat([]byte{0xFF}, 15)
	padded, err := Pad(msg, 16)
	if err != nil {
		t.Fatalf("Pad: %v", err)
	}
	if !bytes.Equal(padded[:15], msg) {
		t.Error("message portion mismatch")
	}
	if padded[15] != 0x01 {
		t.Errorf("marker byte = 0x%02x, want 0x01", padded[15])
	}
}

func TestPad_MessageTooLarge(t *testing.T) {
	msg := make([]byte, 16)
	_, err := Pad(msg, 16)
	if err == nil {
		t.Error("expected error for message that fills entire buffer")
	}
}

func TestPad_MessageLargerThanSize(t *testing.T) {
	msg := make([]byte, 20)
	_, err := Pad(msg, 16)
	if err == nil {
		t.Error("expected error for oversized message")
	}
}

func TestUnpad_Basic(t *testing.T) {
	padded := []byte{'h', 'e', 'l', 'l', 'o', 0x01, 0x00, 0x00}
	msg, err := Unpad(padded)
	if err != nil {
		t.Fatalf("Unpad: %v", err)
	}
	if !bytes.Equal(msg, []byte("hello")) {
		t.Errorf("msg = %q, want %q", msg, "hello")
	}
}

func TestUnpad_EmptyMessage(t *testing.T) {
	padded := []byte{0x01, 0x00, 0x00, 0x00}
	msg, err := Unpad(padded)
	if err != nil {
		t.Fatalf("Unpad: %v", err)
	}
	if len(msg) != 0 {
		t.Errorf("len = %d, want 0", len(msg))
	}
}

func TestUnpad_MarkerAtEnd(t *testing.T) {
	padded := []byte{'a', 'b', 'c', 0x01}
	msg, err := Unpad(padded)
	if err != nil {
		t.Fatalf("Unpad: %v", err)
	}
	if !bytes.Equal(msg, []byte("abc")) {
		t.Errorf("msg = %q, want %q", msg, "abc")
	}
}

func TestUnpad_InvalidPadding(t *testing.T) {
	// No marker byte — all non-zero, non-marker data.
	padded := []byte{'h', 'e', 'l', 'l', 'o'}
	_, err := Unpad(padded)
	if err == nil {
		t.Error("expected error for invalid padding")
	}
}

func TestUnpad_NoMarker(t *testing.T) {
	padded := []byte{0x00, 0x00, 0x00, 0x00}
	_, err := Unpad(padded)
	if err == nil {
		t.Error("expected error when no marker found")
	}
}

func TestPadUnpad_RoundTrip(t *testing.T) {
	messages := [][]byte{
		[]byte("hello, world"),
		[]byte{},
		[]byte{0xFF, 0xFE, 0xFD},
		bytes.Repeat([]byte("A"), 2950),
	}

	for _, msg := range messages {
		padded, err := Pad(msg, 2951)
		if err != nil {
			t.Fatalf("Pad(%d bytes): %v", len(msg), err)
		}
		got, err := Unpad(padded)
		if err != nil {
			t.Fatalf("Unpad: %v", err)
		}
		if !bytes.Equal(got, msg) {
			t.Errorf("round-trip failed for %d-byte message", len(msg))
		}
	}
}

func TestPadUnpad_BinaryContent(t *testing.T) {
	// Ensure padding works with content that contains 0x00 and 0x01 bytes.
	msg := []byte{0x00, 0x01, 0x00, 0x01, 0x00}
	padded, err := Pad(msg, 16)
	if err != nil {
		t.Fatalf("Pad: %v", err)
	}
	got, err := Unpad(padded)
	if err != nil {
		t.Fatalf("Unpad: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Errorf("round-trip failed: got %v, want %v", got, msg)
	}
}
