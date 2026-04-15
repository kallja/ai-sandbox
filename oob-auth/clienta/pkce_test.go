package clienta

import (
	"encoding/base64"
	"testing"
)

func TestGeneratePKCE_VerifierLength(t *testing.T) {
	verifier, _, err := GeneratePKCE()
	if err != nil {
		t.Fatalf("GeneratePKCE: %v", err)
	}
	// 32 random bytes → 43 base64url characters (no padding).
	if len(verifier) != 43 {
		t.Errorf("verifier length = %d, want 43", len(verifier))
	}
}

func TestGeneratePKCE_ChallengeLength(t *testing.T) {
	_, challenge, err := GeneratePKCE()
	if err != nil {
		t.Fatalf("GeneratePKCE: %v", err)
	}
	// SHA-256 → 32 bytes → 43 base64url characters (no padding).
	if len(challenge) != 43 {
		t.Errorf("challenge length = %d, want 43", len(challenge))
	}
}

func TestGeneratePKCE_Unique(t *testing.T) {
	v1, _, _ := GeneratePKCE()
	v2, _, _ := GeneratePKCE()
	if v1 == v2 {
		t.Error("two PKCE generations produced identical verifiers")
	}
}

func TestGeneratePKCE_ChallengeMatchesVerifier(t *testing.T) {
	verifier, challenge, _ := GeneratePKCE()
	expected := computeS256Challenge(verifier)
	if challenge != expected {
		t.Errorf("challenge = %q, want %q", challenge, expected)
	}
}

func TestGeneratePKCE_Base64URLEncoded(t *testing.T) {
	verifier, challenge, _ := GeneratePKCE()
	// Verify both are valid base64url (no padding).
	if _, err := base64.RawURLEncoding.DecodeString(verifier); err != nil {
		t.Errorf("verifier is not valid base64url: %v", err)
	}
	if _, err := base64.RawURLEncoding.DecodeString(challenge); err != nil {
		t.Errorf("challenge is not valid base64url: %v", err)
	}
}

func TestComputeS256Challenge_Deterministic(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	c1 := computeS256Challenge(verifier)
	c2 := computeS256Challenge(verifier)
	if c1 != c2 {
		t.Error("S256 challenge not deterministic")
	}
}

func TestComputeS256Challenge_DifferentVerifiers(t *testing.T) {
	c1 := computeS256Challenge("verifier-one")
	c2 := computeS256Challenge("verifier-two")
	if c1 == c2 {
		t.Error("different verifiers produced same challenge")
	}
}
