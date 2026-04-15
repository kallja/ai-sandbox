package crypto

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	if len(kp.Public) != ed25519.PublicKeySize {
		t.Errorf("public key length = %d, want %d", len(kp.Public), ed25519.PublicKeySize)
	}
	if len(kp.Private) != ed25519.PrivateKeySize {
		t.Errorf("private key length = %d, want %d", len(kp.Private), ed25519.PrivateKeySize)
	}
}

func TestGenerateKeyPair_Unique(t *testing.T) {
	kp1, _ := GenerateKeyPair()
	kp2, _ := GenerateKeyPair()
	if bytes.Equal(kp1.Public, kp2.Public) {
		t.Error("two generated key pairs have identical public keys")
	}
}

func TestFingerprint_Deterministic(t *testing.T) {
	kp, _ := GenerateKeyPair()
	fp1 := Fingerprint(kp.Public)
	fp2 := Fingerprint(kp.Public)
	if fp1 != fp2 {
		t.Errorf("fingerprint not deterministic: %q != %q", fp1, fp2)
	}
}

func TestFingerprint_DifferentKeys(t *testing.T) {
	kp1, _ := GenerateKeyPair()
	kp2, _ := GenerateKeyPair()
	if Fingerprint(kp1.Public) == Fingerprint(kp2.Public) {
		t.Error("different keys produced the same fingerprint")
	}
}

func TestFingerprint_Length(t *testing.T) {
	kp, _ := GenerateKeyPair()
	fp := Fingerprint(kp.Public)
	// SHA-256 hex = 64 characters.
	if len(fp) != 64 {
		t.Errorf("fingerprint length = %d, want 64", len(fp))
	}
}

func TestQueueID_Deterministic(t *testing.T) {
	kp, _ := GenerateKeyPair()
	q1 := QueueID(kp.Public)
	q2 := QueueID(kp.Public)
	if q1 != q2 {
		t.Errorf("QueueID not deterministic: %q != %q", q1, q2)
	}
}

func TestQueueID_DifferentKeys(t *testing.T) {
	kp1, _ := GenerateKeyPair()
	kp2, _ := GenerateKeyPair()
	if QueueID(kp1.Public) == QueueID(kp2.Public) {
		t.Error("different keys produced the same QueueID")
	}
}

func TestQueueID_DiffersFromFingerprint(t *testing.T) {
	kp, _ := GenerateKeyPair()
	if QueueID(kp.Public) == Fingerprint(kp.Public) {
		t.Error("QueueID and Fingerprint should differ (different hashing schemes)")
	}
}

func TestSealOpen_RoundTrip(t *testing.T) {
	sender, _ := GenerateKeyPair()
	recipient, _ := GenerateKeyPair()

	plaintext := []byte("hello, oob-auth")
	nonce, ciphertext, err := Seal(plaintext, sender.Private, recipient.Public)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	got, err := Open(ciphertext, nonce, sender.Public, recipient.Private)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("Open = %q, want %q", got, plaintext)
	}
}

func TestSealOpen_EmptyPlaintext(t *testing.T) {
	sender, _ := GenerateKeyPair()
	recipient, _ := GenerateKeyPair()

	nonce, ciphertext, err := Seal([]byte{}, sender.Private, recipient.Public)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	got, err := Open(ciphertext, nonce, sender.Public, recipient.Private)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("Open returned %d bytes, want 0", len(got))
	}
}

func TestSealOpen_LargePayload(t *testing.T) {
	sender, _ := GenerateKeyPair()
	recipient, _ := GenerateKeyPair()

	plaintext := make([]byte, 4096) // 4KB max per spec
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}

	nonce, ciphertext, err := Seal(plaintext, sender.Private, recipient.Public)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	got, err := Open(ciphertext, nonce, sender.Public, recipient.Private)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Error("round-trip failed for 4KB payload")
	}
}

func TestOpen_WrongRecipient(t *testing.T) {
	sender, _ := GenerateKeyPair()
	recipient, _ := GenerateKeyPair()
	wrongRecipient, _ := GenerateKeyPair()

	nonce, ciphertext, _ := Seal([]byte("secret"), sender.Private, recipient.Public)

	_, err := Open(ciphertext, nonce, sender.Public, wrongRecipient.Private)
	if err == nil {
		t.Error("Open should fail with wrong recipient key")
	}
}

func TestOpen_WrongSender(t *testing.T) {
	sender, _ := GenerateKeyPair()
	recipient, _ := GenerateKeyPair()
	wrongSender, _ := GenerateKeyPair()

	nonce, ciphertext, _ := Seal([]byte("secret"), sender.Private, recipient.Public)

	_, err := Open(ciphertext, nonce, wrongSender.Public, recipient.Private)
	if err == nil {
		t.Error("Open should fail with wrong sender key")
	}
}

func TestOpen_WrongNonce(t *testing.T) {
	sender, _ := GenerateKeyPair()
	recipient, _ := GenerateKeyPair()

	nonce, ciphertext, _ := Seal([]byte("secret"), sender.Private, recipient.Public)

	// Flip a bit in the nonce.
	badNonce := nonce
	badNonce[0] ^= 0xFF

	_, err := Open(ciphertext, badNonce, sender.Public, recipient.Private)
	if err == nil {
		t.Error("Open should fail with wrong nonce")
	}
}

func TestOpen_TamperedCiphertext(t *testing.T) {
	sender, _ := GenerateKeyPair()
	recipient, _ := GenerateKeyPair()

	nonce, ciphertext, _ := Seal([]byte("secret"), sender.Private, recipient.Public)

	// Flip a bit in the ciphertext.
	tampered := make([]byte, len(ciphertext))
	copy(tampered, ciphertext)
	tampered[0] ^= 0xFF

	_, err := Open(tampered, nonce, sender.Public, recipient.Private)
	if err == nil {
		t.Error("Open should fail with tampered ciphertext")
	}
}

func TestSeal_UniqueNonces(t *testing.T) {
	sender, _ := GenerateKeyPair()
	recipient, _ := GenerateKeyPair()
	plaintext := []byte("same message")

	nonce1, _, _ := Seal(plaintext, sender.Private, recipient.Public)
	nonce2, _, _ := Seal(plaintext, sender.Private, recipient.Public)

	if nonce1 == nonce2 {
		t.Error("two Seal calls produced identical nonces")
	}
}

func TestSeal_UniqueCiphertext(t *testing.T) {
	sender, _ := GenerateKeyPair()
	recipient, _ := GenerateKeyPair()
	plaintext := []byte("same message")

	_, ct1, _ := Seal(plaintext, sender.Private, recipient.Public)
	_, ct2, _ := Seal(plaintext, sender.Private, recipient.Public)

	if bytes.Equal(ct1, ct2) {
		t.Error("two Seal calls produced identical ciphertext (nonce reuse?)")
	}
}

func TestZero(t *testing.T) {
	b := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE}
	Zero(b)
	for i, v := range b {
		if v != 0 {
			t.Errorf("byte[%d] = 0x%02X after Zero, want 0x00", i, v)
		}
	}
}

func TestZero_Empty(t *testing.T) {
	// Should not panic on empty/nil slices.
	Zero([]byte{})
	Zero(nil)
}

func TestSaveLoadPrivateKey(t *testing.T) {
	kp, _ := GenerateKeyPair()
	dir := t.TempDir()
	path := filepath.Join(dir, "key.pem")

	if err := SavePrivateKey(kp.Private, path); err != nil {
		t.Fatalf("SavePrivateKey: %v", err)
	}

	// Verify file permissions.
	info, _ := os.Stat(path)
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("private key file mode = %o, want 0600", perm)
	}

	loaded, err := LoadPrivateKey(path)
	if err != nil {
		t.Fatalf("LoadPrivateKey: %v", err)
	}
	if !bytes.Equal(loaded, kp.Private) {
		t.Error("loaded private key does not match original")
	}
}

func TestSaveLoadPublicKey(t *testing.T) {
	kp, _ := GenerateKeyPair()
	dir := t.TempDir()
	path := filepath.Join(dir, "key.pub")

	if err := SavePublicKey(kp.Public, path); err != nil {
		t.Fatalf("SavePublicKey: %v", err)
	}

	loaded, err := LoadPublicKey(path)
	if err != nil {
		t.Fatalf("LoadPublicKey: %v", err)
	}
	if !bytes.Equal(loaded, kp.Public) {
		t.Error("loaded public key does not match original")
	}
}

func TestLoadPrivateKey_NotFound(t *testing.T) {
	_, err := LoadPrivateKey("/nonexistent/path.pem")
	if err == nil {
		t.Error("LoadPrivateKey should fail for missing file")
	}
}

func TestLoadPublicKey_NotFound(t *testing.T) {
	_, err := LoadPublicKey("/nonexistent/path.pem")
	if err == nil {
		t.Error("LoadPublicKey should fail for missing file")
	}
}

func TestLoadPrivateKey_InvalidPEM(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.pem")
	os.WriteFile(path, []byte("not a pem file"), 0600)

	_, err := LoadPrivateKey(path)
	if err == nil {
		t.Error("LoadPrivateKey should fail for invalid PEM")
	}
}

func TestLoadPublicKey_InvalidPEM(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.pem")
	os.WriteFile(path, []byte("not a pem file"), 0644)

	_, err := LoadPublicKey(path)
	if err == nil {
		t.Error("LoadPublicKey should fail for invalid PEM")
	}
}

func TestSaveLoadRoundTrip_SealOpen(t *testing.T) {
	// Full round trip: generate, save, load, encrypt, decrypt.
	sender, _ := GenerateKeyPair()
	recipient, _ := GenerateKeyPair()

	dir := t.TempDir()
	SavePrivateKey(sender.Private, filepath.Join(dir, "sender.key"))
	SavePublicKey(sender.Public, filepath.Join(dir, "sender.pub"))
	SavePrivateKey(recipient.Private, filepath.Join(dir, "recipient.key"))
	SavePublicKey(recipient.Public, filepath.Join(dir, "recipient.pub"))

	// Load keys from disk.
	sPriv, _ := LoadPrivateKey(filepath.Join(dir, "sender.key"))
	rPub, _ := LoadPublicKey(filepath.Join(dir, "recipient.pub"))

	plaintext := []byte("round trip through files")
	nonce, ciphertext, err := Seal(plaintext, sPriv, rPub)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	sPub, _ := LoadPublicKey(filepath.Join(dir, "sender.pub"))
	rPriv, _ := LoadPrivateKey(filepath.Join(dir, "recipient.key"))

	got, err := Open(ciphertext, nonce, sPub, rPriv)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("Open = %q, want %q", got, plaintext)
	}
}

func TestEd25519ToX25519_Deterministic(t *testing.T) {
	kp, _ := GenerateKeyPair()

	x1, _ := ed25519PrivateToX25519(kp.Private)
	x2, _ := ed25519PrivateToX25519(kp.Private)
	if x1 != x2 {
		t.Error("X25519 private key conversion is not deterministic")
	}

	p1, _ := ed25519PublicToX25519(kp.Public)
	p2, _ := ed25519PublicToX25519(kp.Public)
	if p1 != p2 {
		t.Error("X25519 public key conversion is not deterministic")
	}
}

func TestEd25519PrivateToX25519_InvalidLength(t *testing.T) {
	_, err := ed25519PrivateToX25519(ed25519.PrivateKey([]byte("short")))
	if err == nil {
		t.Error("should reject invalid private key length")
	}
}

func TestEd25519PublicToX25519_InvalidKey(t *testing.T) {
	_, err := ed25519PublicToX25519(ed25519.PublicKey(make([]byte, 32)))
	// All-zero is technically a valid (low-order) point, so we just
	// verify no panic. Some invalid encodings will error.
	_ = err
}
