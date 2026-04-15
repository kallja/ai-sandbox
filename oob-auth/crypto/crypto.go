// Package crypto provides end-to-end encryption primitives for the OOB-Auth
// protocol. It handles Ed25519 key management, NaCl box encryption, blind
// queue ID derivation, and secure memory wiping.
package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/nacl/box"
)

const routingSalt = "static_routing_salt"

// KeyPair holds an Ed25519 identity key pair.
type KeyPair struct {
	Public  ed25519.PublicKey
	Private ed25519.PrivateKey
}

// GenerateKeyPair creates a new Ed25519 key pair.
func GenerateKeyPair() (*KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519 key: %w", err)
	}
	return &KeyPair{Public: pub, Private: priv}, nil
}

// SavePrivateKey writes an Ed25519 private key to a PEM file (PKCS#8, mode 0600).
func SavePrivateKey(priv ed25519.PrivateKey, path string) error {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("marshal private key: %w", err)
	}
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	return os.WriteFile(path, pem.EncodeToMemory(block), 0600)
}

// SavePublicKey writes an Ed25519 public key to a PEM file (PKIX).
func SavePublicKey(pub ed25519.PublicKey, path string) error {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return fmt.Errorf("marshal public key: %w", err)
	}
	block := &pem.Block{Type: "PUBLIC KEY", Bytes: der}
	return os.WriteFile(path, pem.EncodeToMemory(block), 0644)
}

// LoadPrivateKey reads an Ed25519 private key from a PEM file.
func LoadPrivateKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read private key file: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	edKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not Ed25519: got %T", key)
	}
	return edKey, nil
}

// LoadPublicKey reads an Ed25519 public key from a PEM file.
func LoadPublicKey(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read public key file: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	edKey, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is not Ed25519: got %T", key)
	}
	return edKey, nil
}

// Fingerprint returns the hex-encoded SHA-256 hash of a public key,
// used as SenderID in the E2EE envelope.
func Fingerprint(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return hex.EncodeToString(h[:])
}

// QueueID computes the blind routing index for a recipient:
// hex(SHA-256(recipientPublicKey || routingSalt)).
// Both clients derive the same value independently.
func QueueID(recipientPub ed25519.PublicKey) string {
	h := sha256.New()
	h.Write(recipientPub)
	h.Write([]byte(routingSalt))
	return hex.EncodeToString(h.Sum(nil))
}

// Seal encrypts plaintext for a recipient using NaCl box
// (Curve25519 + XSalsa20 + Poly1305). Ed25519 keys are converted
// to Curve25519 internally.
func Seal(plaintext []byte, senderPriv ed25519.PrivateKey, recipientPub ed25519.PublicKey) ([24]byte, []byte, error) {
	senderX, err := ed25519PrivateToX25519(senderPriv)
	if err != nil {
		return [24]byte{}, nil, fmt.Errorf("convert sender key: %w", err)
	}
	defer Zero(senderX[:])

	recipientX, err := ed25519PublicToX25519(recipientPub)
	if err != nil {
		return [24]byte{}, nil, fmt.Errorf("convert recipient key: %w", err)
	}

	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return [24]byte{}, nil, fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := box.Seal(nil, plaintext, &nonce, &recipientX, &senderX)
	return nonce, ciphertext, nil
}

// Open decrypts a NaCl box ciphertext from a known sender.
func Open(ciphertext []byte, nonce [24]byte, senderPub ed25519.PublicKey, recipientPriv ed25519.PrivateKey) ([]byte, error) {
	recipientX, err := ed25519PrivateToX25519(recipientPriv)
	if err != nil {
		return nil, fmt.Errorf("convert recipient key: %w", err)
	}
	defer Zero(recipientX[:])

	senderX, err := ed25519PublicToX25519(senderPub)
	if err != nil {
		return nil, fmt.Errorf("convert sender key: %w", err)
	}

	plaintext, ok := box.Open(nil, ciphertext, &nonce, &senderX, &recipientX)
	if !ok {
		return nil, fmt.Errorf("decryption failed: invalid ciphertext or wrong keys")
	}
	return plaintext, nil
}

// Zero overwrites a byte slice with zeroes to limit exposure of secrets in memory.
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// ed25519PrivateToX25519 derives a Curve25519 private key from an Ed25519
// private key by hashing the seed and clamping per RFC 7748.
func ed25519PrivateToX25519(priv ed25519.PrivateKey) ([32]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return [32]byte{}, fmt.Errorf("invalid private key length: %d", len(priv))
	}

	h := sha512.Sum512(priv.Seed())
	var curve [32]byte
	copy(curve[:], h[:32])
	Zero(h[:])

	// Clamp per RFC 7748 §5.
	curve[0] &= 248
	curve[31] &= 127
	curve[31] |= 64

	return curve, nil
}

// ed25519PublicToX25519 converts an Ed25519 public key (Edwards form) to
// its Curve25519 equivalent (Montgomery form).
func ed25519PublicToX25519(pub ed25519.PublicKey) ([32]byte, error) {
	point, err := new(edwards25519.Point).SetBytes(pub)
	if err != nil {
		return [32]byte{}, fmt.Errorf("invalid ed25519 public key: %w", err)
	}
	montgomery := point.BytesMontgomery()
	return [32]byte(montgomery), nil
}
