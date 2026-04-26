package crypto

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"testing"
)

func TestSealedBox_RoundTrip(t *testing.T) {
	recipientPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("hello, sealed box!")
	ephPub, nonce, ct, err := SealedBoxSeal(plaintext, recipientPriv.PublicKey())
	if err != nil {
		t.Fatal(err)
	}

	got, err := SealedBoxOpen(ct, nonce, ephPub, recipientPriv)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got, plaintext) {
		t.Fatalf("got %q, want %q", got, plaintext)
	}
}

func TestSealedBox_WrongKey(t *testing.T) {
	recipientPriv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	wrongPriv, _ := ecdh.X25519().GenerateKey(rand.Reader)

	plaintext := []byte("secret")
	ephPub, nonce, ct, err := SealedBoxSeal(plaintext, recipientPriv.PublicKey())
	if err != nil {
		t.Fatal(err)
	}

	_, err = SealedBoxOpen(ct, nonce, ephPub, wrongPriv)
	if err == nil {
		t.Fatal("expected decryption to fail with wrong key")
	}
}

func TestSealedBox_TamperedCiphertext(t *testing.T) {
	recipientPriv, _ := ecdh.X25519().GenerateKey(rand.Reader)

	plaintext := []byte("don't tamper with me")
	ephPub, nonce, ct, err := SealedBoxSeal(plaintext, recipientPriv.PublicKey())
	if err != nil {
		t.Fatal(err)
	}

	ct[0] ^= 0xff // Flip a byte.
	_, err = SealedBoxOpen(ct, nonce, ephPub, recipientPriv)
	if err == nil {
		t.Fatal("expected decryption to fail with tampered ciphertext")
	}
}

func TestSealedBox_UniqueNonces(t *testing.T) {
	recipientPriv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	plaintext := []byte("same plaintext")

	_, nonce1, _, _ := SealedBoxSeal(plaintext, recipientPriv.PublicKey())
	_, nonce2, _, _ := SealedBoxSeal(plaintext, recipientPriv.PublicKey())

	if nonce1 == nonce2 {
		t.Fatal("two seals produced the same nonce")
	}
}

func TestSealedBox_UniqueCiphertexts(t *testing.T) {
	recipientPriv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	plaintext := []byte("same plaintext")

	_, _, ct1, _ := SealedBoxSeal(plaintext, recipientPriv.PublicKey())
	_, _, ct2, _ := SealedBoxSeal(plaintext, recipientPriv.PublicKey())

	if bytes.Equal(ct1, ct2) {
		t.Fatal("two seals of the same plaintext produced identical ciphertexts")
	}
}

func TestSealedBox_EphPubSize(t *testing.T) {
	recipientPriv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	ephPub, _, _, err := SealedBoxSeal([]byte("test"), recipientPriv.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if len(ephPub) != 32 {
		t.Fatalf("ephemeral public key length = %d, want 32", len(ephPub))
	}
}

func TestDeriveResponseKey_DomainSeparation(t *testing.T) {
	priv1, _ := ecdh.X25519().GenerateKey(rand.Reader)
	priv2, _ := ecdh.X25519().GenerateKey(rand.Reader)

	// Derive sealed box key (via deriveSymKey with sealedBoxInfo).
	sealKey, err := deriveSymKey(priv1, priv2.PublicKey(), sealedBoxInfo)
	if err != nil {
		t.Fatal(err)
	}

	// Derive response key (different info string).
	respKey, err := DeriveResponseKey(priv1, priv2.PublicKey())
	if err != nil {
		t.Fatal(err)
	}

	if sealKey == respKey {
		t.Fatal("sealed box key and response key are identical — domain separation failed")
	}
}
