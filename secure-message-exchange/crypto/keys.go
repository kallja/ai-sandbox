package crypto

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// --- Ed25519 ---

// GenerateEd25519 creates a new Ed25519 key pair.
func GenerateEd25519() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// SaveEd25519Private writes an Ed25519 private key to a PEM file (PKCS#8, mode 0600).
func SaveEd25519Private(priv ed25519.PrivateKey, path string) error {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("marshal ed25519 private key: %w", err)
	}
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	return os.WriteFile(path, pem.EncodeToMemory(block), 0600)
}

// SaveEd25519Public writes an Ed25519 public key to a PEM file (PKIX).
func SaveEd25519Public(pub ed25519.PublicKey, path string) error {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return fmt.Errorf("marshal ed25519 public key: %w", err)
	}
	block := &pem.Block{Type: "PUBLIC KEY", Bytes: der}
	return os.WriteFile(path, pem.EncodeToMemory(block), 0644)
}

// LoadEd25519Private reads an Ed25519 private key from a PEM file.
// It refuses to load files with permissions more permissive than 0600.
func LoadEd25519Private(path string) (ed25519.PrivateKey, error) {
	if err := checkPermissions(path); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read ed25519 private key: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse ed25519 private key: %w", err)
	}
	edKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not Ed25519: got %T", key)
	}
	return edKey, nil
}

// LoadEd25519Public reads an Ed25519 public key from a PEM file.
func LoadEd25519Public(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read ed25519 public key: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse ed25519 public key: %w", err)
	}
	edKey, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is not Ed25519: got %T", key)
	}
	return edKey, nil
}

// --- X25519 ---

// GenerateX25519 creates a new X25519 key pair.
func GenerateX25519() (*ecdh.PrivateKey, error) {
	return ecdh.X25519().GenerateKey(rand.Reader)
}

// SaveX25519Private writes an X25519 private key to a PEM file (PKCS#8, mode 0600).
func SaveX25519Private(priv *ecdh.PrivateKey, path string) error {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("marshal x25519 private key: %w", err)
	}
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	return os.WriteFile(path, pem.EncodeToMemory(block), 0600)
}

// SaveX25519Public writes an X25519 public key raw bytes to a file.
func SaveX25519Public(pub *ecdh.PublicKey, path string) error {
	return os.WriteFile(path, pub.Bytes(), 0644)
}

// LoadX25519Private reads an X25519 private key from a PEM file.
// It refuses to load files with permissions more permissive than 0600.
func LoadX25519Private(path string) (*ecdh.PrivateKey, error) {
	if err := checkPermissions(path); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read x25519 private key: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse x25519 private key: %w", err)
	}
	ecdhKey, ok := key.(*ecdh.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not X25519: got %T", key)
	}
	return ecdhKey, nil
}

// LoadX25519Public reads an X25519 public key from raw bytes file.
func LoadX25519Public(path string) (*ecdh.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read x25519 public key: %w", err)
	}
	return ecdh.X25519().NewPublicKey(data)
}

// --- ML-KEM-768 ---

// GenerateMLKEM768 creates a new ML-KEM-768 key pair.
func GenerateMLKEM768() (*mlkem.DecapsulationKey768, error) {
	return mlkem.GenerateKey768()
}

// SaveMLKEM768Private writes an ML-KEM-768 decapsulation key to a file (mode 0600).
// Uses the raw seed bytes for serialization.
func SaveMLKEM768Private(dk *mlkem.DecapsulationKey768, path string) error {
	return os.WriteFile(path, dk.Bytes(), 0600)
}

// SaveMLKEM768Public writes an ML-KEM-768 encapsulation key to a file.
func SaveMLKEM768Public(ek *mlkem.EncapsulationKey768, path string) error {
	return os.WriteFile(path, ek.Bytes(), 0644)
}

// LoadMLKEM768Private reads an ML-KEM-768 decapsulation key from raw bytes.
// It refuses to load files with permissions more permissive than 0600.
func LoadMLKEM768Private(path string) (*mlkem.DecapsulationKey768, error) {
	if err := checkPermissions(path); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read mlkem768 private key: %w", err)
	}
	return mlkem.NewDecapsulationKey768(data)
}

// LoadMLKEM768Public reads an ML-KEM-768 encapsulation key from raw bytes.
func LoadMLKEM768Public(path string) (*mlkem.EncapsulationKey768, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read mlkem768 public key: %w", err)
	}
	return mlkem.NewEncapsulationKey768(data)
}

// --- Permission checking ---

func checkPermissions(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}
	perm := info.Mode().Perm()
	if perm&0077 != 0 {
		return fmt.Errorf("private key %s has permissions %04o; must be 0600 (owner read/write only)", path, perm)
	}
	return nil
}
