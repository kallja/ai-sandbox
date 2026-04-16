package protocol

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestMarshalUnmarshalIntent(t *testing.T) {
	original := &Intent{
		AuthURL:         "https://auth.example.com/authorize",
		TokenURL:        "https://auth.example.com/token",
		ClientID:        "my-client-id",
		Scopes:          []string{"openid", "profile"},
		RedirectURI:     "http://localhost:8080/callback",
		CodeChallenge:   "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
		ChallengeMethod: "S256",
		State:           "random-state-value",
	}

	data, err := MarshalIntent(original)
	if err != nil {
		t.Fatalf("MarshalIntent: %v", err)
	}

	got, err := UnmarshalIntent(data)
	if err != nil {
		t.Fatalf("UnmarshalIntent: %v", err)
	}

	if got.AuthURL != original.AuthURL {
		t.Errorf("AuthURL = %q, want %q", got.AuthURL, original.AuthURL)
	}
	if got.TokenURL != original.TokenURL {
		t.Errorf("TokenURL = %q, want %q", got.TokenURL, original.TokenURL)
	}
	if got.ClientID != original.ClientID {
		t.Errorf("ClientID = %q, want %q", got.ClientID, original.ClientID)
	}
	if len(got.Scopes) != len(original.Scopes) {
		t.Fatalf("Scopes length = %d, want %d", len(got.Scopes), len(original.Scopes))
	}
	for i, s := range got.Scopes {
		if s != original.Scopes[i] {
			t.Errorf("Scopes[%d] = %q, want %q", i, s, original.Scopes[i])
		}
	}
	if got.CodeChallenge != original.CodeChallenge {
		t.Errorf("CodeChallenge = %q, want %q", got.CodeChallenge, original.CodeChallenge)
	}
	if got.ChallengeMethod != original.ChallengeMethod {
		t.Errorf("ChallengeMethod = %q, want %q", got.ChallengeMethod, original.ChallengeMethod)
	}
	if got.State != original.State {
		t.Errorf("State = %q, want %q", got.State, original.State)
	}
}

func TestMarshalUnmarshalResponse_WithToken(t *testing.T) {
	original := &Response{
		AccessToken: "eyJhbGciOi...",
		TokenType:   "Bearer",
		ExpiresIn:   3600,
	}

	data, err := MarshalResponse(original)
	if err != nil {
		t.Fatalf("MarshalResponse: %v", err)
	}

	got, err := UnmarshalResponse(data)
	if err != nil {
		t.Fatalf("UnmarshalResponse: %v", err)
	}

	if got.AccessToken != original.AccessToken {
		t.Errorf("AccessToken = %q, want %q", got.AccessToken, original.AccessToken)
	}
	if got.TokenType != original.TokenType {
		t.Errorf("TokenType = %q, want %q", got.TokenType, original.TokenType)
	}
	if got.ExpiresIn != original.ExpiresIn {
		t.Errorf("ExpiresIn = %d, want %d", got.ExpiresIn, original.ExpiresIn)
	}
	if got.Error != "" {
		t.Errorf("Error = %q, want empty", got.Error)
	}
}

func TestMarshalUnmarshalResponse_WithAuthCode(t *testing.T) {
	original := &Response{AuthCode: "abc123"}

	data, _ := MarshalResponse(original)
	got, _ := UnmarshalResponse(data)

	if got.AuthCode != "abc123" {
		t.Errorf("AuthCode = %q, want %q", got.AuthCode, "abc123")
	}
	if got.AccessToken != "" {
		t.Errorf("AccessToken = %q, want empty", got.AccessToken)
	}
}

func TestMarshalUnmarshalResponse_WithError(t *testing.T) {
	original := &Response{Error: "access_denied"}

	data, _ := MarshalResponse(original)
	got, _ := UnmarshalResponse(data)

	if got.Error != "access_denied" {
		t.Errorf("Error = %q, want %q", got.Error, "access_denied")
	}
	if got.AccessToken != "" {
		t.Errorf("AccessToken should be empty on error response")
	}
}

func TestMarshalUnmarshalEnvelope(t *testing.T) {
	nonce := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24}
	original := &Envelope{
		SenderID:   "abc123fingerprint",
		Nonce:      nonce,
		Ciphertext: []byte{0xDE, 0xAD, 0xBE, 0xEF},
	}

	data, err := MarshalEnvelope(original)
	if err != nil {
		t.Fatalf("MarshalEnvelope: %v", err)
	}

	if len(data) != EnvelopeSize {
		t.Errorf("serialized envelope = %d bytes, want %d", len(data), EnvelopeSize)
	}

	got, err := UnmarshalEnvelope(data)
	if err != nil {
		t.Fatalf("UnmarshalEnvelope: %v", err)
	}

	if got.SenderID != original.SenderID {
		t.Errorf("SenderID = %q, want %q", got.SenderID, original.SenderID)
	}
	if !bytes.Equal(got.Nonce, original.Nonce) {
		t.Errorf("Nonce mismatch")
	}
	if !bytes.Equal(got.Ciphertext, original.Ciphertext) {
		t.Errorf("Ciphertext mismatch")
	}
}

func TestUnmarshalIntent_InvalidJSON(t *testing.T) {
	_, err := UnmarshalIntent([]byte("not json"))
	if err == nil {
		t.Error("UnmarshalIntent should fail on invalid JSON")
	}
}

func TestUnmarshalResponse_InvalidJSON(t *testing.T) {
	_, err := UnmarshalResponse([]byte("{bad"))
	if err == nil {
		t.Error("UnmarshalResponse should fail on invalid JSON")
	}
}

func TestUnmarshalEnvelope_InvalidJSON(t *testing.T) {
	_, err := UnmarshalEnvelope([]byte(""))
	if err == nil {
		t.Error("UnmarshalEnvelope should fail on empty input")
	}
}

func TestEnvelope_JSONFieldNames(t *testing.T) {
	env := &Envelope{
		SenderID:   "test",
		Nonce:      make([]byte, 24),
		Ciphertext: []byte("ct"),
	}
	data, _ := MarshalEnvelope(env)

	// Trim trailing whitespace padding before checking JSON fields.
	trimmed := bytes.TrimRight(data, " ")
	var raw map[string]json.RawMessage
	json.Unmarshal(trimmed, &raw)

	for _, key := range []string{"sender_id", "nonce", "ciphertext"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("JSON missing expected field %q", key)
		}
	}
}

func TestIntent_JSONOmitEmpty(t *testing.T) {
	// Verify that zero-value intent still serializes all fields
	// (no omitempty on required fields).
	intent := &Intent{}
	data, _ := MarshalIntent(intent)

	var raw map[string]json.RawMessage
	json.Unmarshal(data, &raw)

	for _, key := range []string{"auth_url", "token_url", "client_id", "code_challenge"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("JSON missing expected field %q even for zero value", key)
		}
	}
}

func TestResponse_OmitEmptyFields(t *testing.T) {
	// A response with only an auth code should omit token fields.
	resp := &Response{AuthCode: "code123"}
	data, _ := MarshalResponse(resp)

	var raw map[string]json.RawMessage
	json.Unmarshal(data, &raw)

	if _, ok := raw["auth_code"]; !ok {
		t.Error("auth_code should be present")
	}
	if _, ok := raw["access_token"]; ok {
		t.Error("access_token should be omitted when empty")
	}
}

func TestEnvelopeSize(t *testing.T) {
	if EnvelopeSize != 4096 {
		t.Errorf("EnvelopeSize = %d, want 4096", EnvelopeSize)
	}
}

func TestMarshalEnvelope_FixedSize(t *testing.T) {
	// With a correctly sized ciphertext, output must be exactly EnvelopeSize.
	env := &Envelope{
		SenderID:   "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		Nonce:      make([]byte, 24),
		Ciphertext: make([]byte, CiphertextSize),
	}
	data, err := MarshalEnvelope(env)
	if err != nil {
		t.Fatalf("MarshalEnvelope: %v", err)
	}
	if len(data) != EnvelopeSize {
		t.Errorf("len = %d, want %d", len(data), EnvelopeSize)
	}
}
