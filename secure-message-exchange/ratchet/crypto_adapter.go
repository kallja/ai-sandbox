// Package ratchet wraps the Double Ratchet algorithm for the E2EE Relay Protocol.
package ratchet

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	dr "github.com/status-im/doubleratchet"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// cryptoAdapter implements dr.Crypto using X25519 for DH and
// XChaCha20-Poly1305 for AEAD, with HKDF-SHA256 for KDF chains.
type cryptoAdapter struct{}

var _ dr.Crypto = cryptoAdapter{}

// dhPair wraps an ecdh.PrivateKey to implement dr.DHPair.
type dhPair struct {
	priv *ecdh.PrivateKey
}

func (p dhPair) PrivateKey() dr.Key { return p.priv.Bytes() }
func (p dhPair) PublicKey() dr.Key  { return p.priv.PublicKey().Bytes() }

// GenerateDH creates a new X25519 key pair.
func (c cryptoAdapter) GenerateDH() (dr.DHPair, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate X25519 DH: %w", err)
	}
	return dhPair{priv: priv}, nil
}

// DH performs X25519 ECDH.
func (c cryptoAdapter) DH(pair dr.DHPair, pub dr.Key) (dr.Key, error) {
	privKey, err := ecdh.X25519().NewPrivateKey(pair.PrivateKey())
	if err != nil {
		return nil, fmt.Errorf("parse DH private key: %w", err)
	}
	pubKey, err := ecdh.X25519().NewPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("parse DH public key: %w", err)
	}
	shared, err := privKey.ECDH(pubKey)
	if err != nil {
		return nil, fmt.Errorf("ECDH: %w", err)
	}
	return shared, nil
}

// Encrypt uses XChaCha20-Poly1305 with a nonce derived from the message key.
func (c cryptoAdapter) Encrypt(mk dr.Key, plaintext, ad []byte) ([]byte, error) {
	key, nonce, err := deriveKeyAndNonce(mk)
	if err != nil {
		return nil, err
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("create AEAD: %w", err)
	}

	return aead.Seal(nil, nonce, plaintext, ad), nil
}

// Decrypt uses XChaCha20-Poly1305 with a nonce derived from the message key.
func (c cryptoAdapter) Decrypt(mk dr.Key, ciphertext, ad []byte) ([]byte, error) {
	key, nonce, err := deriveKeyAndNonce(mk)
	if err != nil {
		return nil, err
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("create AEAD: %w", err)
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, ad)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return plaintext, nil
}

// KdfRK derives a new root key, chain key, and header key from a root key
// and DH output using HKDF-SHA256.
func (c cryptoAdapter) KdfRK(rk, dhOut dr.Key) (rootKey, chainKey, headerKey dr.Key) {
	hk := hkdf.New(sha256.New, dhOut, rk, []byte("E2EE-Relay-RatchetRK-V1"))

	rootKey = make(dr.Key, 32)
	io.ReadFull(hk, rootKey)

	chainKey = make(dr.Key, 32)
	io.ReadFull(hk, chainKey)

	// Header key — not used in our protocol but the interface requires it.
	headerKey = make(dr.Key, 32)
	io.ReadFull(hk, headerKey)

	return rootKey, chainKey, headerKey
}

// KdfCK derives a new chain key and message key from a chain key.
func (c cryptoAdapter) KdfCK(ck dr.Key) (chainKey, msgKey dr.Key) {
	// Chain key: HMAC-SHA256(ck, 0x01)
	hk1 := hkdf.New(sha256.New, ck, nil, []byte("E2EE-Relay-ChainKey-V1"))
	chainKey = make(dr.Key, 32)
	io.ReadFull(hk1, chainKey)

	// Message key: HMAC-SHA256(ck, 0x02)
	hk2 := hkdf.New(sha256.New, ck, nil, []byte("E2EE-Relay-MsgKey-V1"))
	msgKey = make(dr.Key, 32)
	io.ReadFull(hk2, msgKey)

	return chainKey, msgKey
}

// deriveKeyAndNonce derives a 32-byte encryption key and 24-byte nonce
// from a message key using HKDF-SHA256.
func deriveKeyAndNonce(mk dr.Key) ([]byte, []byte, error) {
	hk := hkdf.New(sha256.New, mk, nil, []byte("E2EE-Relay-AEAD-V1"))
	key := make([]byte, 32)
	nonce := make([]byte, 24)

	if _, err := io.ReadFull(hk, key); err != nil {
		return nil, nil, fmt.Errorf("derive encryption key: %w", err)
	}
	if _, err := io.ReadFull(hk, nonce); err != nil {
		return nil, nil, fmt.Errorf("derive nonce: %w", err)
	}
	return key, nonce, nil
}
