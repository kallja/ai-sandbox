package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestFingerprint_Deterministic(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fp1 := Fingerprint(pub)
	fp2 := Fingerprint(pub)
	if fp1 != fp2 {
		t.Fatal("fingerprint is not deterministic")
	}
}

func TestFingerprint_Size(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fp := Fingerprint(pub)
	if len(fp) != 32 {
		t.Fatalf("fingerprint length = %d, want 32", len(fp))
	}
}

func TestFingerprint_DifferentKeys(t *testing.T) {
	pub1, _, _ := ed25519.GenerateKey(rand.Reader)
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)
	fp1 := Fingerprint(pub1)
	fp2 := Fingerprint(pub2)
	if fp1 == fp2 {
		t.Fatal("different keys produced the same fingerprint")
	}
}

func TestFingerprintHex(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	h := FingerprintHex(pub)
	if len(h) != 64 {
		t.Fatalf("hex fingerprint length = %d, want 64", len(h))
	}
}
