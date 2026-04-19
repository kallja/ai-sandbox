package client

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	ecrypto "github.com/kallja/ai-sandbox/secure-message-exchange/crypto"
)

func TestLoadConfig(t *testing.T) {
	// Generate test keys.
	alicePub, _, _ := ed25519.GenerateKey(rand.Reader)
	aliceX25519, _ := ecdh.X25519().GenerateKey(rand.Reader)
	aliceMLKEM, _ := mlkem.GenerateKey768()

	relayX25519, _ := ecdh.X25519().GenerateKey(rand.Reader)
	relayEdPub, _, _ := ed25519.GenerateKey(rand.Reader)

	cfg := configJSON{
		Peers: map[string]peerJSON{
			"alice": {
				Ed25519:  base64.StdEncoding.EncodeToString(alicePub),
				X25519:   base64.StdEncoding.EncodeToString(aliceX25519.PublicKey().Bytes()),
				MLKEM768: base64.StdEncoding.EncodeToString(aliceMLKEM.EncapsulationKey().Bytes()),
			},
		},
		Relay: relayJSON{
			URL:     "http://localhost:8080",
			X25519:  base64.StdEncoding.EncodeToString(relayX25519.PublicKey().Bytes()),
			Ed25519: base64.StdEncoding.EncodeToString(relayEdPub),
		},
	}

	data, _ := json.Marshal(cfg)
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	os.WriteFile(path, data, 0644)

	loaded, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := loaded.Peers["alice"]; !ok {
		t.Fatal("alice not found in peers")
	}
	if loaded.Relay.URL != "http://localhost:8080" {
		t.Fatalf("relay URL = %q, want %q", loaded.Relay.URL, "http://localhost:8080")
	}
}

func TestLoadConfig_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	os.WriteFile(path, []byte("not json"), 0644)

	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestLoadConfig_MissingFile(t *testing.T) {
	_, err := LoadConfig("/nonexistent/path.json")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadIdentity(t *testing.T) {
	dir := t.TempDir()

	// Generate and save keys.
	edPub, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	ecrypto.SaveEd25519Private(edPriv, filepath.Join(dir, "ed25519.pem"))
	ecrypto.SaveEd25519Public(edPub, filepath.Join(dir, "ed25519.pub"))

	x25519Priv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	ecrypto.SaveX25519Private(x25519Priv, filepath.Join(dir, "x25519.pem"))

	mlkemDK, _ := mlkem.GenerateKey768()
	ecrypto.SaveMLKEM768Private(mlkemDK, filepath.Join(dir, "mlkem768.key"))

	id, err := LoadIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}

	if !edPriv.Equal(id.Ed25519Priv) {
		t.Fatal("Ed25519 private key mismatch")
	}
	if !x25519Priv.Equal(id.X25519Priv) {
		t.Fatal("X25519 private key mismatch")
	}
}
