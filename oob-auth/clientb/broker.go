package clientb

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"io"
	"net/http"

	"github.com/kallja/ai-sandbox/oob-auth/crypto"
	"github.com/kallja/ai-sandbox/oob-auth/protocol"
	"github.com/kallja/ai-sandbox/oob-auth/reqconfig"
)

// Config holds the settings for a Broker session.
type Config struct {
	RelayURL   string
	PrivateKey ed25519.PrivateKey // Broker's Ed25519 private key.
	PeerPub    ed25519.PublicKey  // Requester's Ed25519 public key.

	// Mode controls what the Broker returns.
	// "code"  — return the authorization code (Requester redeems it).
	// "token" — redeem the code and return tokens directly.
	Mode string
}

// Run executes the Broker flow:
// 1. Long-poll the relay for an encrypted intent
// 2. Decrypt and parse the intent
// 3. Execute the OAuth flow
// 4. Optionally redeem the auth code for tokens
// 5. Encrypt and publish the response
func Run(ctx context.Context, cfg *Config, client *http.Client, auth OAuthExecutor, redeemer TokenRedeemer) error {
	myPub := cfg.PrivateKey.Public().(ed25519.PublicKey)
	myQueueID := crypto.QueueID(myPub)

	fmt.Println("Waiting for intent from Requester...")
	envelope, err := subscribe(ctx, client, cfg.RelayURL, myQueueID)
	if err != nil {
		return fmt.Errorf("subscribe for intent: %w", err)
	}

	// Decrypt the intent.
	var nonce [24]byte
	copy(nonce[:], envelope.Nonce)
	padded, err := crypto.Open(envelope.Ciphertext, nonce, cfg.PeerPub, cfg.PrivateKey)
	if err != nil {
		return fmt.Errorf("decrypt intent: %w", err)
	}
	defer crypto.Zero(padded)

	plaintext, err := crypto.Unpad(padded)
	if err != nil {
		return fmt.Errorf("unpad intent: %w", err)
	}

	intent, err := protocol.UnmarshalIntent(plaintext)
	if err != nil {
		return fmt.Errorf("parse intent: %w", err)
	}

	// Execute the OAuth flow.
	fmt.Println("Executing OAuth flow...")
	authCode, err := auth.Authorize(ctx, intent)
	if err != nil {
		return sendError(ctx, client, cfg, fmt.Sprintf("authorization failed: %v", err))
	}
	defer zeroString(&authCode)

	// Build the response.
	var resp *protocol.Response
	if cfg.Mode == "token" && redeemer != nil && intent.TokenURL != "" {
		reqCfg := &reqconfig.Config{
			RequestHeaders:      intent.RequestHeaders,
			OrderRequestHeaders: intent.OrderRequestHeaders,
			OrderBodyFields:     intent.OrderBodyFields,
		}
		resp, err = redeemer.RedeemWithConfig(ctx, intent.TokenURL, intent.ClientID, authCode, intent.RedirectURI, reqCfg)
		if err != nil {
			return sendError(ctx, client, cfg, fmt.Sprintf("token redemption failed: %v", err))
		}
	} else {
		resp = &protocol.Response{AuthCode: authCode}
	}

	return sendResponse(ctx, client, cfg, resp)
}

func sendResponse(ctx context.Context, client *http.Client, cfg *Config, resp *protocol.Response) error {
	plaintext, err := protocol.MarshalResponse(resp)
	if err != nil {
		return err
	}

	padded, err := crypto.Pad(plaintext, protocol.PaddedPlaintextSize)
	if err != nil {
		return fmt.Errorf("pad response: %w", err)
	}
	crypto.Zero(plaintext)
	defer crypto.Zero(padded)

	nonce, ciphertext, err := crypto.Seal(padded, cfg.PrivateKey, cfg.PeerPub)
	if err != nil {
		return fmt.Errorf("encrypt response: %w", err)
	}

	myPub := cfg.PrivateKey.Public().(ed25519.PublicKey)
	envelope := &protocol.Envelope{
		SenderID:   crypto.Fingerprint(myPub),
		Nonce:      nonce[:],
		Ciphertext: ciphertext,
	}

	peerQueueID := crypto.QueueID(cfg.PeerPub)
	return publish(ctx, client, cfg.RelayURL, peerQueueID, envelope)
}

func sendError(ctx context.Context, client *http.Client, cfg *Config, errMsg string) error {
	resp := &protocol.Response{Error: errMsg}
	if err := sendResponse(ctx, client, cfg, resp); err != nil {
		return fmt.Errorf("send error response: %w (original: %s)", err, errMsg)
	}
	return fmt.Errorf("broker: %s", errMsg)
}

// publish and subscribe mirror the Client A implementations — they share
// the same relay HTTP contract.

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
				return nil, fmt.Errorf("unmarshal envelope: %w", err)
			}
			return env, nil

		case http.StatusNoContent:
			resp.Body.Close()
			continue

		default:
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return nil, fmt.Errorf("relay returned %d: %s", resp.StatusCode, body)
		}
	}
}
