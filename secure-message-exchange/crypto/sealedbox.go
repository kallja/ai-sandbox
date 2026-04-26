package crypto

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

var sealedBoxInfo = []byte("E2EE-Relay-SealedBox-V1")

// SealedBoxSeal encrypts plaintext for a recipient using an ephemeral
// X25519 key exchange + HKDF-SHA256 + XChaCha20-Poly1305.
//
// Returns the ephemeral public key, nonce, and ciphertext.
func SealedBoxSeal(plaintext []byte, recipientPub *ecdh.PublicKey) (ephPub []byte, nonce [24]byte, ciphertext []byte, err error) {
	ephPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nonce, nil, fmt.Errorf("generate ephemeral key: %w", err)
	}

	symKey, err := deriveSymKey(ephPriv, recipientPub, sealedBoxInfo)
	if err != nil {
		return nil, nonce, nil, err
	}
	defer Zero(symKey[:])

	aead, err := chacha20poly1305.NewX(symKey[:])
	if err != nil {
		return nil, nonce, nil, fmt.Errorf("create AEAD: %w", err)
	}

	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, nonce, nil, fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext = aead.Seal(nil, nonce[:], plaintext, nil)
	return ephPriv.PublicKey().Bytes(), nonce, ciphertext, nil
}

// SealedBoxOpen decrypts a sealed box using the recipient's private key
// and the sender's ephemeral public key.
func SealedBoxOpen(ciphertext []byte, nonce [24]byte, ephPubBytes []byte, recipientPriv *ecdh.PrivateKey) ([]byte, error) {
	ephPub, err := ecdh.X25519().NewPublicKey(ephPubBytes)
	if err != nil {
		return nil, fmt.Errorf("parse ephemeral public key: %w", err)
	}

	symKey, err := deriveSymKey(recipientPriv, ephPub, sealedBoxInfo)
	if err != nil {
		return nil, err
	}
	defer Zero(symKey[:])

	aead, err := chacha20poly1305.NewX(symKey[:])
	if err != nil {
		return nil, fmt.Errorf("create AEAD: %w", err)
	}

	plaintext, err := aead.Open(nil, nonce[:], ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return plaintext, nil
}

// deriveSymKey performs X25519 ECDH and derives a 32-byte symmetric key via HKDF-SHA256.
func deriveSymKey(priv *ecdh.PrivateKey, pub *ecdh.PublicKey, info []byte) ([32]byte, error) {
	var symKey [32]byte

	shared, err := priv.ECDH(pub)
	if err != nil {
		return symKey, fmt.Errorf("ECDH: %w", err)
	}
	defer Zero(shared)

	hk := hkdf.New(sha256.New, shared, nil, info)
	if _, err := io.ReadFull(hk, symKey[:]); err != nil {
		return symKey, fmt.Errorf("HKDF expand: %w", err)
	}
	return symKey, nil
}

// DeriveRequestKey derives a symmetric key for encrypting/decrypting
// request bodies (the same key used by SealedBoxSeal/Open).
func DeriveRequestKey(priv *ecdh.PrivateKey, pub *ecdh.PublicKey) ([32]byte, error) {
	return deriveSymKey(priv, pub, sealedBoxInfo)
}

// DeriveResponseKey derives a symmetric key for encrypting/decrypting
// server responses, using a distinct HKDF info string for domain separation.
func DeriveResponseKey(priv *ecdh.PrivateKey, pub *ecdh.PublicKey) ([32]byte, error) {
	return deriveSymKey(priv, pub, []byte("E2EE-Relay-Response-V1"))
}
