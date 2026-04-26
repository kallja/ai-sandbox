package ratchet

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"testing"

	dr "github.com/status-im/doubleratchet"
)

func makeRootKey() [32]byte {
	var rk [32]byte
	rand.Read(rk[:])
	return rk
}

func TestSession_Bidirectional(t *testing.T) {
	rk := makeRootKey()
	store := NewInMemorySessionStorage()

	// Alice is initiator — generates a ratchet keypair.
	aliceRatchetKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	alice, err := NewInitiatorSession([]byte("alice"), rk, aliceRatchetKey, store)
	if err != nil {
		t.Fatal(err)
	}

	// Alice encrypts first message.
	msg1, err := alice.Encrypt([]byte("hello bob"), nil)
	if err != nil {
		t.Fatal(err)
	}

	// Bob creates responder session using Alice's ratchet pub from the first message.
	bob, err := NewResponderSession([]byte("bob"), rk, msg1.RatchetPub, store)
	if err != nil {
		t.Fatal(err)
	}

	// Bob decrypts.
	pt1, err := bob.Decrypt(msg1.RatchetPub, msg1.MessageNumber, msg1.PrevChainLen, msg1.Ciphertext, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt1, []byte("hello bob")) {
		t.Fatalf("got %q, want %q", pt1, "hello bob")
	}

	// Bob sends a reply.
	msg2, err := bob.Encrypt([]byte("hello alice"), nil)
	if err != nil {
		t.Fatal(err)
	}

	// Alice decrypts Bob's reply.
	pt2, err := alice.Decrypt(msg2.RatchetPub, msg2.MessageNumber, msg2.PrevChainLen, msg2.Ciphertext, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt2, []byte("hello alice")) {
		t.Fatalf("got %q, want %q", pt2, "hello alice")
	}
}

func TestSession_MultipleMessages(t *testing.T) {
	rk := makeRootKey()
	store := NewInMemorySessionStorage()

	aliceKey, _ := ecdh.X25519().GenerateKey(rand.Reader)
	alice, err := NewInitiatorSession([]byte("alice-multi"), rk, aliceKey, store)
	if err != nil {
		t.Fatal(err)
	}

	// Alice sends 3 messages.
	var msgs []*EncryptResult
	for i := 0; i < 3; i++ {
		msg, err := alice.Encrypt([]byte("msg-"+string(rune('A'+i))), nil)
		if err != nil {
			t.Fatal(err)
		}
		msgs = append(msgs, msg)
	}

	// Bob creates session from first message's ratchet pub.
	bob, err := NewResponderSession([]byte("bob-multi"), rk, msgs[0].RatchetPub, store)
	if err != nil {
		t.Fatal(err)
	}

	// Bob decrypts all 3 in order.
	for i, msg := range msgs {
		pt, err := bob.Decrypt(msg.RatchetPub, msg.MessageNumber, msg.PrevChainLen, msg.Ciphertext, nil)
		if err != nil {
			t.Fatalf("decrypt msg %d: %v", i, err)
		}
		want := "msg-" + string(rune('A'+i))
		if string(pt) != want {
			t.Fatalf("msg %d: got %q, want %q", i, pt, want)
		}
	}
}

func TestSession_WrongSessionCannotDecrypt(t *testing.T) {
	rk1 := makeRootKey()
	rk2 := makeRootKey()
	store := NewInMemorySessionStorage()

	aliceKey, _ := ecdh.X25519().GenerateKey(rand.Reader)
	alice, _ := NewInitiatorSession([]byte("alice-wrong"), rk1, aliceKey, store)

	msg, err := alice.Encrypt([]byte("secret"), nil)
	if err != nil {
		t.Fatal(err)
	}

	// Eve tries to decrypt with a different root key.
	eve, _ := NewResponderSession([]byte("eve"), rk2, msg.RatchetPub, store)
	_, err = eve.Decrypt(msg.RatchetPub, msg.MessageNumber, msg.PrevChainLen, msg.Ciphertext, nil)
	if err == nil {
		t.Fatal("expected decryption to fail with wrong session")
	}
}

func TestSession_RatchetPubSize(t *testing.T) {
	rk := makeRootKey()
	store := NewInMemorySessionStorage()

	key, _ := ecdh.X25519().GenerateKey(rand.Reader)
	sess, _ := NewInitiatorSession([]byte("size-test"), rk, key, store)

	msg, err := sess.Encrypt([]byte("test"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(msg.RatchetPub) != 32 {
		t.Fatalf("ratchet pub key length = %d, want 32", len(msg.RatchetPub))
	}
}

func TestCryptoAdapter_Implements(t *testing.T) {
	// Compile-time check.
	var _ dr.Crypto = cryptoAdapter{}
}

func TestInMemorySessionStorage(t *testing.T) {
	store := NewInMemorySessionStorage()

	_, err := store.Load([]byte("nonexistent"))
	if err == nil {
		t.Fatal("expected error loading nonexistent session")
	}

	state := &dr.State{}
	if err := store.Save([]byte("test-id"), state); err != nil {
		t.Fatal(err)
	}

	loaded, err := store.Load([]byte("test-id"))
	if err != nil {
		t.Fatal(err)
	}
	if loaded != state {
		t.Fatal("loaded state does not match saved state")
	}
}
