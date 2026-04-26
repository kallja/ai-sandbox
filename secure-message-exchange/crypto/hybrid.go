package crypto

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

var hybridInfo = []byte("E2EE-Relay-Hybrid-V1")

// HybridEncapsulate performs a hybrid key encapsulation using X25519 + ML-KEM-768.
// It generates ephemeral keys, computes shared secrets from both KEMs, and
// combines them via HKDF-SHA256 to produce a 32-byte root key.
//
// Returns the ephemeral X25519 public key (32 bytes), ML-KEM ciphertext
// (1088 bytes), and the derived root key.
func HybridEncapsulate(
	recipientX25519Pub *ecdh.PublicKey,
	recipientMLKEMPub *mlkem.EncapsulationKey768,
) (ephX25519Pub []byte, mlkemCiphertext []byte, rootKey [32]byte, err error) {
	// X25519 ECDH with ephemeral key.
	ephPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, rootKey, fmt.Errorf("generate ephemeral X25519: %w", err)
	}

	ssX25519, err := ephPriv.ECDH(recipientX25519Pub)
	if err != nil {
		return nil, nil, rootKey, fmt.Errorf("X25519 ECDH: %w", err)
	}
	defer Zero(ssX25519)

	// ML-KEM-768 encapsulation.
	ssMLKEM, mlkemCt := recipientMLKEMPub.Encapsulate()
	defer Zero(ssMLKEM)

	// Combine shared secrets via HKDF.
	rootKey, err = combineSharedSecrets(ssX25519, ssMLKEM)
	if err != nil {
		return nil, nil, rootKey, err
	}

	return ephPriv.PublicKey().Bytes(), mlkemCt, rootKey, nil
}

// HybridDecapsulate performs the recipient side of the hybrid KEM.
// It takes the sender's ephemeral X25519 public key and ML-KEM ciphertext,
// computes shared secrets using the recipient's private keys, and derives
// the same root key.
func HybridDecapsulate(
	ephX25519PubBytes []byte,
	mlkemCiphertext []byte,
	recipientX25519Priv *ecdh.PrivateKey,
	recipientMLKEMPriv *mlkem.DecapsulationKey768,
) ([32]byte, error) {
	var rootKey [32]byte

	// Parse ephemeral X25519 public key.
	ephPub, err := ecdh.X25519().NewPublicKey(ephX25519PubBytes)
	if err != nil {
		return rootKey, fmt.Errorf("parse ephemeral X25519 key: %w", err)
	}

	// X25519 ECDH.
	ssX25519, err := recipientX25519Priv.ECDH(ephPub)
	if err != nil {
		return rootKey, fmt.Errorf("X25519 ECDH: %w", err)
	}
	defer Zero(ssX25519)

	// ML-KEM-768 decapsulation.
	ssMLKEM, err := recipientMLKEMPriv.Decapsulate(mlkemCiphertext)
	if err != nil {
		return rootKey, fmt.Errorf("ML-KEM decapsulate: %w", err)
	}
	defer Zero(ssMLKEM)

	return combineSharedSecrets(ssX25519, ssMLKEM)
}

// combineSharedSecrets concatenates two shared secrets and derives a
// 32-byte root key via HKDF-SHA256.
func combineSharedSecrets(ssX25519, ssMLKEM []byte) ([32]byte, error) {
	var rootKey [32]byte

	ikm := make([]byte, len(ssX25519)+len(ssMLKEM))
	copy(ikm, ssX25519)
	copy(ikm[len(ssX25519):], ssMLKEM)
	defer Zero(ikm)

	hk := hkdf.New(sha256.New, ikm, nil, hybridInfo)
	if _, err := io.ReadFull(hk, rootKey[:]); err != nil {
		return rootKey, fmt.Errorf("HKDF: %w", err)
	}
	return rootKey, nil
}
