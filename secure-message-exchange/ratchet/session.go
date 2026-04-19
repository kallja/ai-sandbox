package ratchet

import (
	"crypto/ecdh"
	"fmt"
	"sync"

	dr "github.com/status-im/doubleratchet"
)

// Session wraps a doubleratchet.Session and exposes methods that return
// the individual wire-format fields instead of the library's Message type.
type Session struct {
	inner dr.Session
}

// EncryptResult holds the fields needed to build an inner envelope.
type EncryptResult struct {
	RatchetPub     []byte // 32-byte X25519 ratchet public key
	MessageNumber  uint32
	PrevChainLen   uint32
	Ciphertext     []byte
}

// NewInitiatorSession creates a session for the party that sends the
// first ratcheted message. The rootKey is from HybridEncapsulate and
// keyPair is the initiator's ratchet key (typically freshly generated).
func NewInitiatorSession(id []byte, rootKey [32]byte, keyPair *ecdh.PrivateKey, store dr.SessionStorage) (*Session, error) {
	pair := dhPair{priv: keyPair}
	sess, err := dr.New(id, rootKey[:], pair, store, dr.WithCrypto(cryptoAdapter{}))
	if err != nil {
		return nil, fmt.Errorf("create initiator session: %w", err)
	}
	return &Session{inner: sess}, nil
}

// NewResponderSession creates a session for the party that receives the
// first ratcheted message. remoteRatchetPub is the initiator's ratchet
// public key extracted from the first ratcheted message header.
func NewResponderSession(id []byte, rootKey [32]byte, remoteRatchetPub []byte, store dr.SessionStorage) (*Session, error) {
	sess, err := dr.NewWithRemoteKey(id, rootKey[:], remoteRatchetPub, store, dr.WithCrypto(cryptoAdapter{}))
	if err != nil {
		return nil, fmt.Errorf("create responder session: %w", err)
	}
	return &Session{inner: sess}, nil
}

// Encrypt performs a ratchet step and encrypts plaintext.
func (s *Session) Encrypt(plaintext, ad []byte) (*EncryptResult, error) {
	msg, err := s.inner.RatchetEncrypt(plaintext, ad)
	if err != nil {
		return nil, fmt.Errorf("ratchet encrypt: %w", err)
	}
	return &EncryptResult{
		RatchetPub:    []byte(msg.Header.DH),
		MessageNumber: msg.Header.N,
		PrevChainLen:  msg.Header.PN,
		Ciphertext:    msg.Ciphertext,
	}, nil
}

// Decrypt decrypts a ratcheted message using the provided header fields.
func (s *Session) Decrypt(ratchetPub []byte, msgNum, prevChain uint32, ciphertext, ad []byte) ([]byte, error) {
	msg := dr.Message{
		Header: dr.MessageHeader{
			DH: ratchetPub,
			N:  msgNum,
			PN: prevChain,
		},
		Ciphertext: ciphertext,
	}
	plaintext, err := s.inner.RatchetDecrypt(msg, ad)
	if err != nil {
		return nil, fmt.Errorf("ratchet decrypt: %w", err)
	}
	return plaintext, nil
}

// InMemorySessionStorage implements dr.SessionStorage for testing and V1.
type InMemorySessionStorage struct {
	mu     sync.Mutex
	states map[string]*dr.State
}

// NewInMemorySessionStorage creates a new in-memory session store.
func NewInMemorySessionStorage() *InMemorySessionStorage {
	return &InMemorySessionStorage{states: make(map[string]*dr.State)}
}

func (s *InMemorySessionStorage) Save(id []byte, state *dr.State) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.states[string(id)] = state
	return nil
}

func (s *InMemorySessionStorage) Load(id []byte) (*dr.State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, ok := s.states[string(id)]
	if !ok {
		return nil, fmt.Errorf("session %x not found", id)
	}
	return state, nil
}
