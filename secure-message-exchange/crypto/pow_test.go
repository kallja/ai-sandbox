package crypto

import (
	"testing"
)

func TestPoW_RoundTrip(t *testing.T) {
	body := []byte("test body for proof of work")
	nonce, err := ComputePoW(body, 8)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPoW(nonce, body, 8) {
		t.Fatal("valid PoW nonce failed verification")
	}
}

func TestPoW_WrongNonce(t *testing.T) {
	body := []byte("test body")
	if VerifyPoW("0000000000000000", body, 20) {
		t.Fatal("arbitrary nonce should not pass difficulty=20")
	}
}

func TestPoW_DifficultyZero(t *testing.T) {
	// Difficulty 0 means no leading zeros required — always passes.
	if !VerifyPoW("deadbeef", []byte("anything"), 0) {
		t.Fatal("difficulty=0 should always pass")
	}
}

func TestPoW_WrongBody(t *testing.T) {
	body := []byte("correct body")
	nonce, err := ComputePoW(body, 8)
	if err != nil {
		t.Fatal(err)
	}
	if VerifyPoW(nonce, []byte("wrong body"), 8) {
		t.Fatal("PoW should fail with different body")
	}
}

func TestPoW_InvalidHexNonce(t *testing.T) {
	if VerifyPoW("not-hex!!", []byte("body"), 8) {
		t.Fatal("invalid hex should fail verification")
	}
}

func TestPoW_Difficulty20(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping difficulty=20 PoW test in short mode")
	}
	body := []byte("high difficulty test")
	nonce, err := ComputePoW(body, 20)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPoW(nonce, body, 20) {
		t.Fatal("valid PoW nonce failed verification at difficulty=20")
	}
}

func TestHasLeadingZeroBits(t *testing.T) {
	tests := []struct {
		hash [32]byte
		bits int
		want bool
	}{
		{[32]byte{0x00, 0x00, 0xff}, 16, true},
		{[32]byte{0x00, 0x00, 0xff}, 17, false},
		{[32]byte{0x00, 0x00, 0x00}, 24, true},
		{[32]byte{0x00, 0x01}, 15, true},
		{[32]byte{0x00, 0x01}, 16, false},
		{[32]byte{0xff}, 0, true},
		{[32]byte{0x00}, 8, true},
	}
	for _, tc := range tests {
		got := hasLeadingZeroBits(tc.hash, tc.bits)
		if got != tc.want {
			t.Errorf("hasLeadingZeroBits(%x, %d) = %v, want %v", tc.hash[:3], tc.bits, got, tc.want)
		}
	}
}
