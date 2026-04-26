package crypto

import "testing"

func TestZero(t *testing.T) {
	b := []byte{0x01, 0x02, 0x03, 0xff}
	Zero(b)
	for i, v := range b {
		if v != 0 {
			t.Fatalf("byte %d = 0x%02x after Zero, want 0x00", i, v)
		}
	}
}

func TestZero_Empty(t *testing.T) {
	// Should not panic on empty or nil slices.
	Zero(nil)
	Zero([]byte{})
}
