package client

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net/http"

	ecrypto "github.com/kallja/ai-sandbox/secure-message-exchange/crypto"
	"github.com/kallja/ai-sandbox/secure-message-exchange/envelope"
	"github.com/kallja/ai-sandbox/secure-message-exchange/wire"

	"golang.org/x/crypto/chacha20poly1305"
)

// Send sends an encrypted message to a peer via the relay server.
// For V1, every send performs a fresh handshake (no session persistence).
func Send(ctx context.Context, identity *Identity, peer *PeerConfig, relay *RelayConfig, message []byte, httpClient *http.Client, powDifficulty int) error {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	if powDifficulty == 0 {
		powDifficulty = wire.DefaultPoWDifficulty
	}

	// Step 1: Hybrid KEM to derive root key.
	ephX25519Pub, mlkemCt, rootKey, err := ecrypto.HybridEncapsulate(peer.X25519Pub, peer.MLKEM768Pub)
	if err != nil {
		return fmt.Errorf("hybrid encapsulate: %w", err)
	}
	defer ecrypto.Zero(rootKey[:])

	// Step 2: Encrypt message with root key directly (handshake message).
	aead, err := chacha20poly1305.NewX(rootKey[:])
	if err != nil {
		return fmt.Errorf("create AEAD: %w", err)
	}

	// The nonce is prepended to the ciphertext within the AEAD field.
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return fmt.Errorf("generate nonce: %w", err)
	}
	aeadCt := aead.Seal(nonce[:], nonce[:], message, nil)

	// Step 3: Build handshake inner envelope.
	if len(aeadCt) > wire.HandshakeAEADCtSize {
		return fmt.Errorf("message too large: AEAD ciphertext %d bytes, max %d", len(aeadCt), wire.HandshakeAEADCtSize)
	}
	inner, err := envelope.BuildHandshakeInner(ephX25519Pub, mlkemCt, aeadCt)
	if err != nil {
		return fmt.Errorf("build inner: %w", err)
	}

	// Step 4: Build routing header.
	recipientFP := ecrypto.Fingerprint(peer.Ed25519Pub)
	rh, err := envelope.NewRoutingHeader(identity.Ed25519Priv, recipientFP, inner[:])
	if err != nil {
		return fmt.Errorf("build routing header: %w", err)
	}
	rhBytes := rh.Marshal()

	// Step 5: Seal outer envelope.
	outer, err := envelope.SealOuterEnvelope(rhBytes, inner, relay.X25519Pub)
	if err != nil {
		return fmt.Errorf("seal outer: %w", err)
	}

	// Step 6: Compute PoW.
	powNonce, err := ecrypto.ComputePoW(outer[:], powDifficulty)
	if err != nil {
		return fmt.Errorf("compute PoW: %w", err)
	}

	// Step 7: Send.
	req, err := http.NewRequestWithContext(ctx, "POST", relay.URL, bytes.NewReader(outer[:]))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("X-PoW-Nonce", powNonce)

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()
	io.ReadAll(resp.Body) // Drain.

	return nil
}
