package crypto

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEd25519_RoundTrip(t *testing.T) {
	pub, priv, err := GenerateEd25519()
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	privPath := filepath.Join(dir, "ed25519.pem")
	pubPath := filepath.Join(dir, "ed25519.pub")

	if err := SaveEd25519Private(priv, privPath); err != nil {
		t.Fatal(err)
	}
	if err := SaveEd25519Public(pub, pubPath); err != nil {
		t.Fatal(err)
	}

	loadedPriv, err := LoadEd25519Private(privPath)
	if err != nil {
		t.Fatal(err)
	}
	if !priv.Equal(loadedPriv) {
		t.Fatal("loaded private key does not match original")
	}

	loadedPub, err := LoadEd25519Public(pubPath)
	if err != nil {
		t.Fatal(err)
	}
	if !pub.Equal(loadedPub) {
		t.Fatal("loaded public key does not match original")
	}
}

func TestX25519_RoundTrip(t *testing.T) {
	priv, err := GenerateX25519()
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	privPath := filepath.Join(dir, "x25519.pem")
	pubPath := filepath.Join(dir, "x25519.pub")

	if err := SaveX25519Private(priv, privPath); err != nil {
		t.Fatal(err)
	}
	if err := SaveX25519Public(priv.PublicKey(), pubPath); err != nil {
		t.Fatal(err)
	}

	loadedPriv, err := LoadX25519Private(privPath)
	if err != nil {
		t.Fatal(err)
	}
	if !priv.Equal(loadedPriv) {
		t.Fatal("loaded x25519 private key does not match original")
	}

	loadedPub, err := LoadX25519Public(pubPath)
	if err != nil {
		t.Fatal(err)
	}
	if !priv.PublicKey().Equal(loadedPub) {
		t.Fatal("loaded x25519 public key does not match original")
	}
}

func TestMLKEM768_RoundTrip(t *testing.T) {
	dk, err := GenerateMLKEM768()
	if err != nil {
		t.Fatal(err)
	}
	ek := dk.EncapsulationKey()

	dir := t.TempDir()
	privPath := filepath.Join(dir, "mlkem768.key")
	pubPath := filepath.Join(dir, "mlkem768.pub")

	if err := SaveMLKEM768Private(dk, privPath); err != nil {
		t.Fatal(err)
	}
	if err := SaveMLKEM768Public(ek, pubPath); err != nil {
		t.Fatal(err)
	}

	loadedDK, err := LoadMLKEM768Private(privPath)
	if err != nil {
		t.Fatal(err)
	}
	// Verify by doing encapsulate/decapsulate round-trip.
	loadedEK, err := LoadMLKEM768Public(pubPath)
	if err != nil {
		t.Fatal(err)
	}

	sharedKey, ct := loadedEK.Encapsulate()
	decapsulated, err := loadedDK.Decapsulate(ct)
	if err != nil {
		t.Fatal(err)
	}
	if len(sharedKey) != len(decapsulated) {
		t.Fatalf("ML-KEM-768 shared key length mismatch: %d vs %d", len(sharedKey), len(decapsulated))
	}
	for i := range sharedKey {
		if sharedKey[i] != decapsulated[i] {
			t.Fatal("ML-KEM-768 encapsulate/decapsulate mismatch after round-trip")
		}
	}
}

func TestEd25519Private_PermissionCheck(t *testing.T) {
	_, priv, err := GenerateEd25519()
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "ed25519.pem")

	if err := SaveEd25519Private(priv, path); err != nil {
		t.Fatal(err)
	}

	// Make permissions too open.
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}

	_, err = LoadEd25519Private(path)
	if err == nil {
		t.Fatal("expected error for permissive file, got nil")
	}
}

func TestX25519Private_PermissionCheck(t *testing.T) {
	priv, err := GenerateX25519()
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "x25519.pem")

	if err := SaveX25519Private(priv, path); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(path, 0640); err != nil {
		t.Fatal(err)
	}

	_, err = LoadX25519Private(path)
	if err == nil {
		t.Fatal("expected error for permissive file, got nil")
	}
}

func TestMLKEM768Private_PermissionCheck(t *testing.T) {
	dk, err := GenerateMLKEM768()
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "mlkem768.key")

	if err := SaveMLKEM768Private(dk, path); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(path, 0666); err != nil {
		t.Fatal(err)
	}

	_, err = LoadMLKEM768Private(path)
	if err == nil {
		t.Fatal("expected error for permissive file, got nil")
	}
}

func TestLoadEd25519Private_InvalidPEM(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.pem")
	os.WriteFile(path, []byte("not a pem file"), 0600)

	_, err := LoadEd25519Private(path)
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}

func TestEd25519Private_SavedPermissions(t *testing.T) {
	_, priv, _ := GenerateEd25519()
	dir := t.TempDir()
	path := filepath.Join(dir, "ed25519.pem")

	if err := SaveEd25519Private(priv, path); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Fatalf("saved private key has perms %04o, want 0600", perm)
	}
}
