package clienta

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/kallja/ai-sandbox/oob-auth/crypto"
	"github.com/kallja/ai-sandbox/oob-auth/protocol"
)

// Config holds the settings for a Requester session.
type Config struct {
	RelayURL   string // Base URL of the relay backend.
	AuthURL    string // OAuth authorization endpoint.
	TokenURL   string // OAuth token endpoint.
	ClientID   string // OAuth client ID.
	Scopes     []string
	RedirectURI string

	PrivateKey ed25519.PrivateKey // Requester's Ed25519 private key.
	PeerPub    ed25519.PublicKey  // Broker's Ed25519 public key.
}

// Result holds the decrypted response from the Broker.
type Result struct {
	AuthCode    string
	AccessToken string
	TokenType   string
	ExpiresIn   int
	Error       string
}

// Run executes the full Requester flow:
// 1. Generate PKCE pair
// 2. Encrypt intent with Broker's public key
// 3. Publish to relay
// 4. Long-poll relay for response
// 5. Decrypt and return the result
func Run(ctx context.Context, cfg *Config, client *http.Client) (*Result, error) {
	verifier, challenge, err := GeneratePKCE()
	if err != nil {
		return nil, fmt.Errorf("generate PKCE: %w", err)
	}
	defer crypto.Zero([]byte(verifier))

	intent := &protocol.Intent{
		AuthURL:         cfg.AuthURL,
		TokenURL:        cfg.TokenURL,
		ClientID:        cfg.ClientID,
		Scopes:          cfg.Scopes,
		RedirectURI:     cfg.RedirectURI,
		CodeChallenge:   challenge,
		ChallengeMethod: "S256",
		State:           generateState(),
	}

	plaintext, err := protocol.MarshalIntent(intent)
	if err != nil {
		return nil, err
	}

	padded, err := crypto.Pad(plaintext, protocol.PaddedPlaintextSize)
	if err != nil {
		return nil, fmt.Errorf("pad intent: %w", err)
	}
	crypto.Zero(plaintext)

	nonce, ciphertext, err := crypto.Seal(padded, cfg.PrivateKey, cfg.PeerPub)
	if err != nil {
		return nil, fmt.Errorf("encrypt intent: %w", err)
	}
	crypto.Zero(padded)

	envelope := &protocol.Envelope{
		SenderID:   crypto.Fingerprint(cfg.PrivateKey.Public().(ed25519.PublicKey)),
		Nonce:      nonce[:],
		Ciphertext: ciphertext,
	}

	// Publish the encrypted intent.
	brokerQueueID := crypto.QueueID(cfg.PeerPub)
	if err := publish(ctx, client, cfg.RelayURL, brokerQueueID, envelope); err != nil {
		return nil, fmt.Errorf("publish intent: %w", err)
	}

	// Long-poll for the encrypted response on our own queue.
	myPub := cfg.PrivateKey.Public().(ed25519.PublicKey)
	myQueueID := crypto.QueueID(myPub)
	respEnvelope, err := subscribe(ctx, client, cfg.RelayURL, myQueueID)
	if err != nil {
		return nil, fmt.Errorf("subscribe for response: %w", err)
	}

	// Decrypt the response.
	var respNonce [24]byte
	copy(respNonce[:], respEnvelope.Nonce)
	respPadded, err := crypto.Open(respEnvelope.Ciphertext, respNonce, cfg.PeerPub, cfg.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt response: %w", err)
	}
	defer crypto.Zero(respPadded)

	respPlain, err := crypto.Unpad(respPadded)
	if err != nil {
		return nil, fmt.Errorf("unpad response: %w", err)
	}

	resp, err := protocol.UnmarshalResponse(respPlain)
	if err != nil {
		return nil, err
	}

	return &Result{
		AuthCode:    resp.AuthCode,
		AccessToken: resp.AccessToken,
		TokenType:   resp.TokenType,
		ExpiresIn:   resp.ExpiresIn,
		Error:       resp.Error,
	}, nil
}

// generateState produces a cryptographically random state parameter:
// 32 random bytes → standard base64 → URL-safe (+ → -, / → _) → strip padding.
// This matches the Node.js reference: crypto.randomBytes(32).toString('base64')
// with +→-, /→_, =→removed.
func generateState() string {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	s := base64.StdEncoding.EncodeToString(buf)
	s = strings.ReplaceAll(s, "+", "-")
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, "=", "")
	return s
}

// publish sends an encrypted envelope to the relay.
func publish(ctx context.Context, client *http.Client, relayURL, queueID string, env *protocol.Envelope) error {
	data, err := protocol.MarshalEnvelope(env)
	if err != nil {
		return err
	}

	url := relayURL + "/api/v1/queue/" + queueID
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("relay returned %d: %s", resp.StatusCode, body)
	}
	return nil
}

// subscribe long-polls the relay until a response appears.
// Reconnects immediately on 204 (timeout) per the spec.
func subscribe(ctx context.Context, client *http.Client, relayURL, queueID string) (*protocol.Envelope, error) {
	url := relayURL + "/api/v1/queue/" + queueID

	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}

		resp, err := client.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, err
		}

		switch resp.StatusCode {
		case http.StatusOK:
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				return nil, fmt.Errorf("read response body: %w", err)
			}
			env, err := protocol.UnmarshalEnvelope(body)
			if err != nil {
				return nil, fmt.Errorf("unmarshal response envelope: %w", err)
			}
			return env, nil

		case http.StatusNoContent:
			resp.Body.Close()
			// Reconnect immediately — no backoff per spec.
			continue

		default:
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return nil, fmt.Errorf("relay returned %d: %s", resp.StatusCode, body)
		}
	}
}
