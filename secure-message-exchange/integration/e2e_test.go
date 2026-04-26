// Package integration contains end-to-end tests that wire up the relay
// server and client library with real cryptography and in-memory store.
package integration

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kallja/ai-sandbox/secure-message-exchange/client"
	ecrypto "github.com/kallja/ai-sandbox/secure-message-exchange/crypto"
	"github.com/kallja/ai-sandbox/secure-message-exchange/envelope"
	"github.com/kallja/ai-sandbox/secure-message-exchange/relay"
	"github.com/kallja/ai-sandbox/secure-message-exchange/wire"
)

const testPoWDifficulty = 8 // Low for fast tests.

// testEnv holds all test infrastructure.
type testEnv struct {
	relayTS      *httptest.Server
	relayPriv    *ecdh.PrivateKey
	relayEdPub   ed25519.PublicKey
	relayEdPriv  ed25519.PrivateKey
	aliceID      *client.Identity
	alicePeer    *client.PeerConfig
	aliceConfig  *client.Config
	bobID        *client.Identity
	bobPeer      *client.PeerConfig
	bobConfig    *client.Config
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()

	// Generate relay keys.
	relayPriv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	relayEdPub, relayEdPriv, _ := ed25519.GenerateKey(rand.Reader)

	// Generate Alice keys.
	aliceEdPub, aliceEdPriv, _ := ed25519.GenerateKey(rand.Reader)
	aliceX25519, _ := ecdh.X25519().GenerateKey(rand.Reader)
	aliceMLKEM, _ := mlkem.GenerateKey768()

	// Generate Bob keys.
	bobEdPub, bobEdPriv, _ := ed25519.GenerateKey(rand.Reader)
	bobX25519, _ := ecdh.X25519().GenerateKey(rand.Reader)
	bobMLKEM, _ := mlkem.GenerateKey768()

	// Build client registry.
	registry := relay.NewStaticRegistry(map[[32]byte]ed25519.PublicKey{
		ecrypto.Fingerprint(aliceEdPub): aliceEdPub,
		ecrypto.Fingerprint(bobEdPub):   bobEdPub,
	})

	// Start relay server.
	srv := relay.NewServer(relay.ServerConfig{
		Store:          relay.NewMemStore(),
		ServerPriv:     relayPriv,
		ServerIdentity: relayEdPub,
		Registry:       registry,
		PoWDifficulty:  testPoWDifficulty,
	})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	// Build peer configs.
	alicePeer := &client.PeerConfig{
		Ed25519Pub:  aliceEdPub,
		X25519Pub:   aliceX25519.PublicKey(),
		MLKEM768Pub: aliceMLKEM.EncapsulationKey(),
	}
	bobPeer := &client.PeerConfig{
		Ed25519Pub:  bobEdPub,
		X25519Pub:   bobX25519.PublicKey(),
		MLKEM768Pub: bobMLKEM.EncapsulationKey(),
	}

	relayCfg := &client.RelayConfig{
		URL:        ts.URL,
		X25519Pub:  relayPriv.PublicKey(),
		Ed25519Pub: relayEdPub,
	}

	aliceConfig := &client.Config{
		Peers: map[string]*client.PeerConfig{"bob": bobPeer},
		Relay: relayCfg,
	}
	bobConfig := &client.Config{
		Peers: map[string]*client.PeerConfig{"alice": alicePeer},
		Relay: relayCfg,
	}

	return &testEnv{
		relayTS:     ts,
		relayPriv:   relayPriv,
		relayEdPub:  relayEdPub,
		relayEdPriv: relayEdPriv,
		aliceID: &client.Identity{
			Ed25519Priv:  aliceEdPriv,
			X25519Priv:   aliceX25519,
			MLKEM768Priv: aliceMLKEM,
		},
		alicePeer:   alicePeer,
		aliceConfig: aliceConfig,
		bobID: &client.Identity{
			Ed25519Priv:  bobEdPriv,
			X25519Priv:   bobX25519,
			MLKEM768Priv: bobMLKEM,
		},
		bobPeer:   bobPeer,
		bobConfig: bobConfig,
	}
}

func TestE2E_HandshakeMessageDelivery(t *testing.T) {
	env := newTestEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Alice sends a message to Bob.
	err := client.Send(ctx, env.aliceID, env.bobPeer, env.aliceConfig.Relay, []byte("hello bob!"), http.DefaultClient, testPoWDifficulty)
	if err != nil {
		t.Fatalf("Alice send: %v", err)
	}

	// Bob polls and receives.
	results, err := client.Poll(ctx, env.bobID, env.bobConfig.Relay, env.bobConfig.Peers, http.DefaultClient, testPoWDifficulty)
	if err != nil {
		t.Fatalf("Bob poll: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 message, got %d", len(results))
	}
	if !bytes.Equal(results[0].Message, []byte("hello bob!")) {
		t.Fatalf("got %q, want %q", results[0].Message, "hello bob!")
	}
}

func TestE2E_MultiMessageFIFO(t *testing.T) {
	env := newTestEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	messages := []string{"first", "second", "third"}
	for _, msg := range messages {
		err := client.Send(ctx, env.aliceID, env.bobPeer, env.aliceConfig.Relay, []byte(msg), http.DefaultClient, testPoWDifficulty)
		if err != nil {
			t.Fatalf("send %q: %v", msg, err)
		}
	}

	results, err := client.Poll(ctx, env.bobID, env.bobConfig.Relay, env.bobConfig.Peers, http.DefaultClient, testPoWDifficulty)
	if err != nil {
		t.Fatalf("poll: %v", err)
	}

	if len(results) != 3 {
		t.Fatalf("expected 3 messages, got %d", len(results))
	}
	for i, msg := range messages {
		if !bytes.Equal(results[i].Message, []byte(msg)) {
			t.Fatalf("message %d: got %q, want %q", i, results[i].Message, msg)
		}
	}
}

func TestE2E_EmptyPoll(t *testing.T) {
	env := newTestEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	results, err := client.Poll(ctx, env.bobID, env.bobConfig.Relay, env.bobConfig.Peers, http.DefaultClient, testPoWDifficulty)
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("expected 0 messages, got %d", len(results))
	}
}

func TestE2E_QueueIsolation(t *testing.T) {
	env := newTestEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Alice sends to Bob, Bob sends to Alice.
	client.Send(ctx, env.aliceID, env.bobPeer, env.aliceConfig.Relay, []byte("for bob"), http.DefaultClient, testPoWDifficulty)
	client.Send(ctx, env.bobID, env.alicePeer, env.bobConfig.Relay, []byte("for alice"), http.DefaultClient, testPoWDifficulty)

	// Bob polls — should get "for bob".
	bobResults, err := client.Poll(ctx, env.bobID, env.bobConfig.Relay, env.bobConfig.Peers, http.DefaultClient, testPoWDifficulty)
	if err != nil {
		t.Fatalf("bob poll: %v", err)
	}
	if len(bobResults) != 1 || !bytes.Equal(bobResults[0].Message, []byte("for bob")) {
		t.Fatalf("bob got wrong message: %v", bobResults)
	}

	// Alice polls — should get "for alice".
	aliceResults, err := client.Poll(ctx, env.aliceID, env.aliceConfig.Relay, env.aliceConfig.Peers, http.DefaultClient, testPoWDifficulty)
	if err != nil {
		t.Fatalf("alice poll: %v", err)
	}
	if len(aliceResults) != 1 || !bytes.Equal(aliceResults[0].Message, []byte("for alice")) {
		t.Fatalf("alice got wrong message: %v", aliceResults)
	}
}

func TestE2E_AllResponsesExact4096(t *testing.T) {
	env := newTestEnv(t)

	// Build a valid request manually and check response size.
	var inner [wire.InnerEnvelopeSize]byte
	rand.Read(inner[:])

	bobFP := ecrypto.Fingerprint(env.bobID.Ed25519Priv.Public().(ed25519.PublicKey))
	rh, _ := envelope.NewRoutingHeader(env.aliceID.Ed25519Priv, bobFP, inner[:])
	rhBytes := rh.Marshal()

	outer, _ := envelope.SealOuterEnvelope(rhBytes, inner, env.relayPriv.PublicKey())
	nonce, _ := ecrypto.ComputePoW(outer[:], testPoWDifficulty)

	req, _ := http.NewRequest("POST", env.relayTS.URL+"/", bytes.NewReader(outer[:]))
	req.Header.Set("X-PoW-Nonce", nonce)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if len(body) != 4096 {
		t.Fatalf("response size = %d, want 4096", len(body))
	}
}

func TestE2E_InvalidPoW_ConnectionDropped(t *testing.T) {
	env := newTestEnv(t)

	var inner [wire.InnerEnvelopeSize]byte
	rand.Read(inner[:])

	bobFP := ecrypto.Fingerprint(env.bobID.Ed25519Priv.Public().(ed25519.PublicKey))
	rh, _ := envelope.NewRoutingHeader(env.aliceID.Ed25519Priv, bobFP, inner[:])
	rhBytes := rh.Marshal()

	outer, _ := envelope.SealOuterEnvelope(rhBytes, inner, env.relayPriv.PublicKey())

	req, _ := http.NewRequest("POST", env.relayTS.URL+"/", bytes.NewReader(outer[:]))
	req.Header.Set("X-PoW-Nonce", "bad-nonce")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return // Connection dropped — expected.
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if len(body) == 4096 {
		t.Fatal("should not get valid 4096-byte response for invalid PoW")
	}
}

func TestE2E_BadSignature_AuthFail(t *testing.T) {
	env := newTestEnv(t)

	var inner [wire.InnerEnvelopeSize]byte
	rand.Read(inner[:])

	// Use a key not in the registry.
	_, unknownPriv, _ := ed25519.GenerateKey(rand.Reader)
	bobFP := ecrypto.Fingerprint(env.bobID.Ed25519Priv.Public().(ed25519.PublicKey))
	rh, _ := envelope.NewRoutingHeader(unknownPriv, bobFP, inner[:])
	rhBytes := rh.Marshal()

	outer, _ := envelope.SealOuterEnvelope(rhBytes, inner, env.relayPriv.PublicKey())
	nonce, _ := ecrypto.ComputePoW(outer[:], testPoWDifficulty)

	req, _ := http.NewRequest("POST", env.relayTS.URL+"/", bytes.NewReader(outer[:]))
	req.Header.Set("X-PoW-Nonce", nonce)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	// Response should still be 4096 bytes (ERR_AUTH_FAIL, encrypted).
	if len(body) != 4096 {
		t.Fatalf("auth fail response size = %d, want 4096", len(body))
	}
}

func TestE2E_ConfigRoundTrip(t *testing.T) {
	// Verify that a config written to JSON and read back produces working keys.
	env := newTestEnv(t)
	dir := t.TempDir()

	// Write config JSON for Alice.
	bobEdPub := env.bobID.Ed25519Priv.Public().(ed25519.PublicKey)
	bobX25519Pub := env.bobID.X25519Priv.PublicKey()
	bobMLKEMPub := env.bobID.MLKEM768Priv.EncapsulationKey()

	cfgJSON := map[string]interface{}{
		"peers": map[string]interface{}{
			"bob": map[string]string{
				"ed25519":  base64.StdEncoding.EncodeToString(bobEdPub),
				"x25519":   base64.StdEncoding.EncodeToString(bobX25519Pub.Bytes()),
				"mlkem768": base64.StdEncoding.EncodeToString(bobMLKEMPub.Bytes()),
			},
		},
		"relay": map[string]string{
			"url":     env.relayTS.URL,
			"x25519":  base64.StdEncoding.EncodeToString(env.relayPriv.PublicKey().Bytes()),
			"ed25519": base64.StdEncoding.EncodeToString(env.relayEdPub),
		},
	}
	data, _ := json.Marshal(cfgJSON)
	cfgPath := filepath.Join(dir, "config.json")
	os.WriteFile(cfgPath, data, 0644)

	// Write Alice identity keys.
	keyDir := filepath.Join(dir, "keys")
	os.MkdirAll(keyDir, 0700)
	ecrypto.SaveEd25519Private(env.aliceID.Ed25519Priv, filepath.Join(keyDir, "ed25519.pem"))
	ecrypto.SaveX25519Private(env.aliceID.X25519Priv, filepath.Join(keyDir, "x25519.pem"))
	ecrypto.SaveMLKEM768Private(env.aliceID.MLKEM768Priv, filepath.Join(keyDir, "mlkem768.key"))

	// Load back.
	cfg, err := client.LoadConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	id, err := client.LoadIdentity(keyDir)
	if err != nil {
		t.Fatal(err)
	}

	// Send using loaded config.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = client.Send(ctx, id, cfg.Peers["bob"], cfg.Relay, []byte("config test"), http.DefaultClient, testPoWDifficulty)
	if err != nil {
		t.Fatalf("send with loaded config: %v", err)
	}
}
