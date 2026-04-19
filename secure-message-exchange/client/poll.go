package client

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"io"
	"net/http"

	ecrypto "github.com/kallja/ai-sandbox/secure-message-exchange/crypto"
	"github.com/kallja/ai-sandbox/secure-message-exchange/envelope"
	"github.com/kallja/ai-sandbox/secure-message-exchange/wire"

	"golang.org/x/crypto/chacha20poly1305"
)

// PollResult holds the result of a poll operation.
type PollResult struct {
	Message []byte // Decrypted plaintext message.
}

// Poll polls the relay for pending messages and decrypts any received.
// Performs rapid drain — polling repeatedly until QUEUE_EMPTY.
func Poll(ctx context.Context, identity *Identity, relay *RelayConfig, peers map[string]*PeerConfig, httpClient *http.Client, powDifficulty int) ([]*PollResult, error) {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	if powDifficulty == 0 {
		powDifficulty = wire.DefaultPoWDifficulty
	}

	var results []*PollResult
	for {
		result, err := pollOnce(ctx, identity, relay, peers, httpClient, powDifficulty)
		if err != nil {
			return results, err
		}
		if result == nil {
			break
		}
		results = append(results, result)
	}
	return results, nil
}

// pollOnce sends a single poll request and decrypts the response.
func pollOnce(ctx context.Context, identity *Identity, relay *RelayConfig, peers map[string]*PeerConfig, httpClient *http.Client, powDifficulty int) (*PollResult, error) {
	// Generate ephemeral X25519 key — we keep the private key for response decryption.
	ephPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ephemeral key: %w", err)
	}

	// Build noise inner envelope.
	var inner [wire.InnerEnvelopeSize]byte
	rand.Read(inner[:])

	// Routing header: recipient = server fingerprint (poll).
	serverFP := ecrypto.Fingerprint(relay.Ed25519Pub)
	rh, err := envelope.NewRoutingHeader(identity.Ed25519Priv, serverFP, inner[:])
	if err != nil {
		return nil, fmt.Errorf("build routing header: %w", err)
	}
	rhBytes := rh.Marshal()

	// Build outer envelope plaintext.
	outerPlaintext := make([]byte, wire.OuterPlaintextSize)
	copy(outerPlaintext[:wire.RoutingHeaderSize], rhBytes[:])
	copy(outerPlaintext[wire.RoutingHeaderSize:], inner[:])

	// Manual sealed box with our own ephemeral key.
	outerEnv, err := sealOuterManual(outerPlaintext, ephPriv, relay.X25519Pub)
	if err != nil {
		return nil, fmt.Errorf("seal outer: %w", err)
	}

	// Compute PoW.
	powNonce, err := ecrypto.ComputePoW(outerEnv[:], powDifficulty)
	if err != nil {
		return nil, fmt.Errorf("compute PoW: %w", err)
	}

	// Send.
	req, err := http.NewRequestWithContext(ctx, "POST", relay.URL, bytes.NewReader(outerEnv[:]))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("X-PoW-Nonce", powNonce)

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("poll request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if len(body) != wire.ResponseSize {
		return nil, fmt.Errorf("response size %d, want %d", len(body), wire.ResponseSize)
	}

	// Decrypt response.
	var respBuf [wire.ResponseSize]byte
	copy(respBuf[:], body)

	status, payload, err := envelope.OpenResponse(respBuf, ephPriv, relay.X25519Pub)
	if err != nil {
		return nil, fmt.Errorf("decrypt response: %w", err)
	}

	switch status {
	case wire.StatusQueueEmpty:
		return nil, nil
	case wire.StatusErrAuthFail:
		return nil, fmt.Errorf("server returned ERR_AUTH_FAIL")
	case wire.StatusDataFollows:
		msg, err := decryptInnerEnvelope(payload, identity, peers)
		if err != nil {
			return nil, fmt.Errorf("decrypt inner: %w", err)
		}
		return &PollResult{Message: msg}, nil
	default:
		return nil, fmt.Errorf("unknown status: 0x%02x", status)
	}
}

// sealOuterManual encrypts an outer envelope with a specific ephemeral key.
func sealOuterManual(plaintext []byte, ephPriv *ecdh.PrivateKey, serverPub *ecdh.PublicKey) ([wire.OuterEnvelopeSize]byte, error) {
	var out [wire.OuterEnvelopeSize]byte

	symKey, err := ecrypto.DeriveRequestKey(ephPriv, serverPub)
	if err != nil {
		return out, err
	}
	defer ecrypto.Zero(symKey[:])

	aead, err := chacha20poly1305.NewX(symKey[:])
	if err != nil {
		return out, fmt.Errorf("create AEAD: %w", err)
	}

	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return out, fmt.Errorf("generate nonce: %w", err)
	}

	ct := aead.Seal(nil, nonce[:], plaintext, nil)

	copy(out[wire.OuterEphKeyOffset:], ephPriv.PublicKey().Bytes())
	copy(out[wire.OuterNonceOffset:], nonce[:])
	copy(out[wire.OuterCiphertextOffset:], ct)

	return out, nil
}

// decryptInnerEnvelope decrypts a received inner envelope payload.
func decryptInnerEnvelope(payload []byte, identity *Identity, peers map[string]*PeerConfig) ([]byte, error) {
	var innerBuf [wire.InnerEnvelopeSize]byte
	copy(innerBuf[:], payload)

	parsed, err := envelope.ParseInner(innerBuf)
	if err != nil {
		return nil, fmt.Errorf("parse inner: %w", err)
	}

	switch inner := parsed.(type) {
	case *envelope.HandshakeInner:
		return decryptHandshake(inner, identity)
	case *envelope.RatchetInner:
		return nil, fmt.Errorf("ratcheted messages not yet supported in V1 poll")
	default:
		return nil, fmt.Errorf("unknown inner type: %T", parsed)
	}
}

// decryptHandshake decrypts a handshake inner envelope.
func decryptHandshake(inner *envelope.HandshakeInner, identity *Identity) ([]byte, error) {
	rootKey, err := ecrypto.HybridDecapsulate(
		inner.EphX25519Pub[:],
		inner.MLKEMCiphertext[:],
		identity.X25519Priv,
		identity.MLKEM768Priv,
	)
	if err != nil {
		return nil, fmt.Errorf("hybrid decapsulate: %w", err)
	}
	defer ecrypto.Zero(rootKey[:])

	aead, err := chacha20poly1305.NewX(rootKey[:])
	if err != nil {
		return nil, fmt.Errorf("create AEAD: %w", err)
	}

	// The AEAD field format: [2-byte big-endian length] [nonce (24)] [ciphertext+tag] [padding]
	aeadCt := inner.AEADCiphertext
	if len(aeadCt) < 2 {
		return nil, fmt.Errorf("AEAD field too short: %d bytes", len(aeadCt))
	}

	payloadLen := int(aeadCt[0])<<8 | int(aeadCt[1])
	if payloadLen < 24+16 || 2+payloadLen > len(aeadCt) {
		return nil, fmt.Errorf("invalid AEAD payload length: %d", payloadLen)
	}

	nonce := aeadCt[2 : 2+24]
	ciphertext := aeadCt[26 : 2+payloadLen]

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt handshake: %w", err)
	}

	return plaintext, nil
}
