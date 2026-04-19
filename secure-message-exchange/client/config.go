// Package client implements the E2EE Relay Protocol CLI client library.
package client

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/mlkem"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	ecrypto "github.com/kallja/ai-sandbox/secure-message-exchange/crypto"
)

// PeerConfig holds a peer's public keys.
type PeerConfig struct {
	Ed25519Pub  ed25519.PublicKey
	X25519Pub   *ecdh.PublicKey
	MLKEM768Pub *mlkem.EncapsulationKey768
}

// RelayConfig holds the relay server's connection info and public keys.
type RelayConfig struct {
	URL        string
	X25519Pub  *ecdh.PublicKey
	Ed25519Pub ed25519.PublicKey
}

// Config holds the full client configuration.
type Config struct {
	Peers map[string]*PeerConfig
	Relay *RelayConfig
}

// Identity holds the client's own private keys.
type Identity struct {
	Ed25519Priv  ed25519.PrivateKey
	X25519Priv   *ecdh.PrivateKey
	MLKEM768Priv *mlkem.DecapsulationKey768
}

// configJSON is the JSON representation of the config file.
type configJSON struct {
	Peers map[string]peerJSON `json:"peers"`
	Relay relayJSON           `json:"relay"`
}

type peerJSON struct {
	Ed25519  string `json:"ed25519"`
	X25519   string `json:"x25519"`
	MLKEM768 string `json:"mlkem768"`
}

type relayJSON struct {
	URL     string `json:"url"`
	X25519  string `json:"x25519"`
	Ed25519 string `json:"ed25519"`
}

// LoadConfig loads a peer configuration from a JSON file.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var raw configJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	cfg := &Config{
		Peers: make(map[string]*PeerConfig),
	}

	for name, pj := range raw.Peers {
		pc, err := parsePeerConfig(pj)
		if err != nil {
			return nil, fmt.Errorf("peer %q: %w", name, err)
		}
		cfg.Peers[name] = pc
	}

	relay, err := parseRelayConfig(raw.Relay)
	if err != nil {
		return nil, fmt.Errorf("relay: %w", err)
	}
	cfg.Relay = relay

	return cfg, nil
}

func parsePeerConfig(pj peerJSON) (*PeerConfig, error) {
	ed25519Bytes, err := base64.StdEncoding.DecodeString(pj.Ed25519)
	if err != nil {
		return nil, fmt.Errorf("decode ed25519: %w", err)
	}

	x25519Bytes, err := base64.StdEncoding.DecodeString(pj.X25519)
	if err != nil {
		return nil, fmt.Errorf("decode x25519: %w", err)
	}
	x25519Pub, err := ecdh.X25519().NewPublicKey(x25519Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse x25519: %w", err)
	}

	mlkemBytes, err := base64.StdEncoding.DecodeString(pj.MLKEM768)
	if err != nil {
		return nil, fmt.Errorf("decode mlkem768: %w", err)
	}
	mlkemPub, err := mlkem.NewEncapsulationKey768(mlkemBytes)
	if err != nil {
		return nil, fmt.Errorf("parse mlkem768: %w", err)
	}

	return &PeerConfig{
		Ed25519Pub:  ed25519.PublicKey(ed25519Bytes),
		X25519Pub:   x25519Pub,
		MLKEM768Pub: mlkemPub,
	}, nil
}

func parseRelayConfig(rj relayJSON) (*RelayConfig, error) {
	x25519Bytes, err := base64.StdEncoding.DecodeString(rj.X25519)
	if err != nil {
		return nil, fmt.Errorf("decode x25519: %w", err)
	}
	x25519Pub, err := ecdh.X25519().NewPublicKey(x25519Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse x25519: %w", err)
	}

	ed25519Bytes, err := base64.StdEncoding.DecodeString(rj.Ed25519)
	if err != nil {
		return nil, fmt.Errorf("decode ed25519: %w", err)
	}

	return &RelayConfig{
		URL:        rj.URL,
		X25519Pub:  x25519Pub,
		Ed25519Pub: ed25519.PublicKey(ed25519Bytes),
	}, nil
}

// LoadIdentity loads identity keys from a directory.
// Expects: ed25519.pem, x25519.pem, mlkem768.key
func LoadIdentity(keyDir string) (*Identity, error) {
	edPriv, err := ecrypto.LoadEd25519Private(filepath.Join(keyDir, "ed25519.pem"))
	if err != nil {
		return nil, fmt.Errorf("load ed25519: %w", err)
	}

	x25519Priv, err := ecrypto.LoadX25519Private(filepath.Join(keyDir, "x25519.pem"))
	if err != nil {
		return nil, fmt.Errorf("load x25519: %w", err)
	}

	mlkemPriv, err := ecrypto.LoadMLKEM768Private(filepath.Join(keyDir, "mlkem768.key"))
	if err != nil {
		return nil, fmt.Errorf("load mlkem768: %w", err)
	}

	return &Identity{
		Ed25519Priv:  edPriv,
		X25519Priv:   x25519Priv,
		MLKEM768Priv: mlkemPriv,
	}, nil
}
