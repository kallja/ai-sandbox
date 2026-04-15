// Package protocol defines the wire-format types for the OOB-Auth system:
// the E2EE envelope exchanged via the relay, and the cleartext payloads
// that live inside it after decryption.
package protocol

import (
	"encoding/json"
	"fmt"
)

// MaxPayloadSize is the maximum ciphertext size the relay will accept (4 KB).
const MaxPayloadSize = 4096

// Envelope is the E2EE container transmitted through the relay.
// The relay sees only opaque bytes — it never decrypts.
type Envelope struct {
	SenderID   string   `json:"sender_id"`   // SHA-256 fingerprint of sender's public key.
	Nonce      [24]byte `json:"nonce"`        // Random nonce for NaCl box.
	Ciphertext []byte   `json:"ciphertext"`   // Sealed JSON payload.
}

// Intent is the cleartext payload sent by Client A (the Requester).
// It describes the OAuth authorization the Requester wants the Broker
// to perform on its behalf.
type Intent struct {
	AuthURL      string   `json:"auth_url"`
	TokenURL     string   `json:"token_url"`
	ClientID     string   `json:"client_id"`
	Scopes       []string `json:"scopes"`
	RedirectURI  string   `json:"redirect_uri"`
	CodeChallenge string  `json:"code_challenge"`
	ChallengeMethod string `json:"challenge_method"` // Always "S256".
	State        string   `json:"state"`
}

// Response is the cleartext payload sent by Client B (the Broker) back
// through the relay after completing the OAuth flow.
type Response struct {
	// Exactly one of these groups is populated.
	AuthCode    string `json:"auth_code,omitempty"`
	AccessToken string `json:"access_token,omitempty"`
	TokenType   string `json:"token_type,omitempty"`
	ExpiresIn   int    `json:"expires_in,omitempty"`

	// Error is set when the Broker could not complete the flow.
	Error string `json:"error,omitempty"`
}

// MarshalIntent serializes an Intent to JSON bytes.
func MarshalIntent(intent *Intent) ([]byte, error) {
	data, err := json.Marshal(intent)
	if err != nil {
		return nil, fmt.Errorf("marshal intent: %w", err)
	}
	return data, nil
}

// UnmarshalIntent deserializes an Intent from JSON bytes.
func UnmarshalIntent(data []byte) (*Intent, error) {
	var intent Intent
	if err := json.Unmarshal(data, &intent); err != nil {
		return nil, fmt.Errorf("unmarshal intent: %w", err)
	}
	return &intent, nil
}

// MarshalResponse serializes a Response to JSON bytes.
func MarshalResponse(resp *Response) ([]byte, error) {
	data, err := json.Marshal(resp)
	if err != nil {
		return nil, fmt.Errorf("marshal response: %w", err)
	}
	return data, nil
}

// UnmarshalResponse deserializes a Response from JSON bytes.
func UnmarshalResponse(data []byte) (*Response, error) {
	var resp Response
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}
	return &resp, nil
}

// MarshalEnvelope serializes an Envelope to JSON bytes.
func MarshalEnvelope(env *Envelope) ([]byte, error) {
	data, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("marshal envelope: %w", err)
	}
	return data, nil
}

// UnmarshalEnvelope deserializes an Envelope from JSON bytes.
func UnmarshalEnvelope(data []byte) (*Envelope, error) {
	var env Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("unmarshal envelope: %w", err)
	}
	return &env, nil
}
