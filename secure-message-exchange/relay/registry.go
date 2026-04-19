package relay

import "crypto/ed25519"

// ClientRegistry allows the server to look up client Ed25519 public keys
// by their fingerprint. This is needed for signature verification.
type ClientRegistry interface {
	LookupByFingerprint(fp [32]byte) (ed25519.PublicKey, bool)
}

// StaticRegistry is a ClientRegistry backed by a pre-configured map.
type StaticRegistry struct {
	clients map[[32]byte]ed25519.PublicKey
}

// NewStaticRegistry creates a registry from a map of fingerprint → public key.
func NewStaticRegistry(clients map[[32]byte]ed25519.PublicKey) *StaticRegistry {
	return &StaticRegistry{clients: clients}
}

func (r *StaticRegistry) LookupByFingerprint(fp [32]byte) (ed25519.PublicKey, bool) {
	pub, ok := r.clients[fp]
	return pub, ok
}
