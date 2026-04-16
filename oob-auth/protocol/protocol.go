// Package protocol defines the wire-format types for the OOB-Auth system:
// the E2EE envelope exchanged via the relay, and the cleartext payloads
// that live inside it after decryption.
package protocol

import (
	"bytes"
	"encoding/json"
	"fmt"
)

const (
	// EnvelopeSize is the exact size (in bytes) of every serialized envelope
	// on the wire. The relay rejects anything that isn't exactly this size.
	EnvelopeSize = 4096

	// NaClBoxOverhead is the Poly1305 authentication tag added by NaCl box.
	NaClBoxOverhead = 16

	// envelopeJSONOverhead is the fixed number of bytes consumed by the JSON
	// structure, sender_id (64 hex chars), and nonce (32 base64 chars),
	// excluding the ciphertext base64 content.
	envelopeJSONOverhead = 139

	// CiphertextSize is the fixed raw ciphertext length that, when base64-
	// encoded, produces a JSON envelope of EnvelopeSize - 1 bytes (the last
	// byte is a padding space).
	// 4096 - 139 = 3957 remaining → floor(3957/4)*3 = 2967 → 3956 base64 chars
	// 139 + 3956 = 4095 → +1 trailing space = 4096
	CiphertextSize = 2967

	// PaddedPlaintextSize is the fixed plaintext size after ISO 7816-4
	// padding and before NaCl box encryption.
	PaddedPlaintextSize = CiphertextSize - NaClBoxOverhead // 2951

	// MaxMessageSize is the largest cleartext message that fits after
	// reserving one byte for the ISO 7816-4 padding marker.
	MaxMessageSize = PaddedPlaintextSize - 1 // 2950
)

// Envelope is the E2EE container transmitted through the relay.
// The relay sees only opaque bytes — it never decrypts.
type Envelope struct {
	SenderID   string `json:"sender_id"`   // SHA-256 fingerprint of sender's public key.
	Nonce      []byte `json:"nonce"`        // Random nonce for NaCl box (24 bytes, base64 in JSON).
	Ciphertext []byte `json:"ciphertext"`   // Sealed padded payload (fixed size).
}

// Intent is the cleartext payload sent by Client A (the Requester).
// It describes the OAuth authorization the Requester wants the Broker
// to perform on its behalf.
type Intent struct {
	AuthURL         string   `json:"auth_url"`
	TokenURL        string   `json:"token_url"`
	ClientID        string   `json:"client_id"`
	Scopes          []string `json:"scopes"`
	RedirectURI     string   `json:"redirect_uri"`
	CodeChallenge   string   `json:"code_challenge"`
	ChallengeMethod string   `json:"challenge_method"` // Always "S256".
	State           string   `json:"state"`

	// Request customization — controls how the Broker formats requests
	// to the OAuth provider. Optional; nil means use defaults.
	ExtraParams         map[string]string `json:"extra_params,omitempty"`
	OrderQueryParams    []string          `json:"order_query_params,omitempty"`
	RequestHeaders      map[string]string `json:"request_headers,omitempty"`
	OrderRequestHeaders []string          `json:"order_request_headers,omitempty"`
	OrderBodyFields     []string          `json:"order_body_fields,omitempty"`
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

// MarshalEnvelope serializes an Envelope to exactly EnvelopeSize bytes.
// The JSON payload is right-padded with a single space to reach the target.
func MarshalEnvelope(env *Envelope) ([]byte, error) {
	data, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("marshal envelope: %w", err)
	}
	if len(data) > EnvelopeSize {
		return nil, fmt.Errorf("envelope JSON too large: %d bytes (max %d)", len(data), EnvelopeSize)
	}
	if len(data) < EnvelopeSize {
		buf := make([]byte, EnvelopeSize)
		copy(buf, data)
		for i := len(data); i < EnvelopeSize; i++ {
			buf[i] = ' '
		}
		data = buf
	}
	return data, nil
}

// UnmarshalEnvelope deserializes an Envelope from JSON bytes,
// trimming any trailing whitespace padding first.
func UnmarshalEnvelope(data []byte) (*Envelope, error) {
	data = bytes.TrimRight(data, " ")
	var env Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("unmarshal envelope: %w", err)
	}
	return &env, nil
}
