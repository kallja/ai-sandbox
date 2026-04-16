package clientb

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/kallja/ai-sandbox/oob-auth/protocol"
	"github.com/kallja/ai-sandbox/oob-auth/reqconfig"
)

func TestBuildAuthURL(t *testing.T) {
	intent := &protocol.Intent{
		AuthURL:         "https://auth.example.com/authorize",
		ClientID:        "my-client",
		Scopes:          []string{"read", "write"},
		RedirectURI:     "http://localhost/callback",
		CodeChallenge:   "test-challenge",
		ChallengeMethod: "S256",
		State:           "test-state",
	}

	raw, err := buildAuthURL(intent)
	if err != nil {
		t.Fatalf("buildAuthURL: %v", err)
	}

	u, _ := url.Parse(raw)
	q := u.Query()

	tests := map[string]string{
		"response_type":        "code",
		"client_id":            "my-client",
		"redirect_uri":         "http://localhost/callback",
		"code_challenge":       "test-challenge",
		"code_challenge_method": "S256",
		"state":                "test-state",
		"scope":                "read write",
	}

	for key, want := range tests {
		if got := q.Get(key); got != want {
			t.Errorf("query param %q = %q, want %q", key, got, want)
		}
	}
}

func TestBuildAuthURL_NoScopes(t *testing.T) {
	intent := &protocol.Intent{
		AuthURL:         "https://auth.example.com/authorize",
		ClientID:        "my-client",
		RedirectURI:     "http://localhost/callback",
		CodeChallenge:   "challenge",
		ChallengeMethod: "S256",
	}

	raw, _ := buildAuthURL(intent)
	u, _ := url.Parse(raw)

	if u.Query().Has("scope") {
		t.Error("scope should not be present when no scopes are set")
	}
}

func TestBuildAuthURL_PreservesExistingQueryParams(t *testing.T) {
	intent := &protocol.Intent{
		AuthURL:         "https://auth.example.com/authorize?foo=bar",
		ClientID:        "client",
		CodeChallenge:   "ch",
		ChallengeMethod: "S256",
	}

	raw, _ := buildAuthURL(intent)
	u, _ := url.Parse(raw)

	if u.Query().Get("foo") != "bar" {
		t.Error("existing query params should be preserved")
	}
	if u.Query().Get("client_id") != "client" {
		t.Error("new params should be added")
	}
}

func TestURLPresenter_Authorize(t *testing.T) {
	var capturedURL string
	presenter := &URLPresenter{
		PromptFunc: func(ctx context.Context, authURL string) (string, error) {
			capturedURL = authURL
			return "injected-code", nil
		},
	}

	intent := &protocol.Intent{
		AuthURL:         "https://auth.example.com/authorize",
		ClientID:        "client",
		CodeChallenge:   "ch",
		ChallengeMethod: "S256",
		State:           "s",
	}

	code, err := presenter.Authorize(context.Background(), intent)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if code != "injected-code" {
		t.Errorf("code = %q, want %q", code, "injected-code")
	}
	if capturedURL == "" {
		t.Error("PromptFunc was not called")
	}
}

func TestHTTPTokenRedeemer_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.FormValue("grant_type") != "authorization_code" {
			t.Errorf("grant_type = %q", r.FormValue("grant_type"))
		}
		if r.FormValue("code") != "test-code" {
			t.Errorf("code = %q", r.FormValue("code"))
		}
		if r.FormValue("client_id") != "my-client" {
			t.Errorf("client_id = %q", r.FormValue("client_id"))
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token":"tok","token_type":"Bearer","expires_in":3600}`))
	}))
	defer ts.Close()

	redeemer := &HTTPTokenRedeemer{Client: http.DefaultClient}
	resp, err := redeemer.Redeem(context.Background(), ts.URL, "my-client", "test-code", "http://localhost/cb")
	if err != nil {
		t.Fatalf("Redeem: %v", err)
	}
	if resp.AccessToken != "tok" {
		t.Errorf("AccessToken = %q, want %q", resp.AccessToken, "tok")
	}
	if resp.TokenType != "Bearer" {
		t.Errorf("TokenType = %q, want %q", resp.TokenType, "Bearer")
	}
}

func TestHTTPTokenRedeemer_ServerError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	defer ts.Close()

	redeemer := &HTTPTokenRedeemer{Client: http.DefaultClient}
	resp, err := redeemer.Redeem(context.Background(), ts.URL, "client", "bad-code", "http://localhost/cb")
	if err != nil {
		t.Fatalf("Redeem: %v", err)
	}
	if resp.Error == "" {
		t.Error("expected error in response for 400 status")
	}
}

func TestBuildAuthURL_ExtraParams(t *testing.T) {
	intent := &protocol.Intent{
		AuthURL:         "https://auth.example.com/authorize",
		ClientID:        "client",
		RedirectURI:     "http://localhost/callback",
		CodeChallenge:   "ch",
		ChallengeMethod: "S256",
		State:           "s",
		ExtraParams:     map[string]string{"prompt": "consent", "access_type": "offline"},
	}

	raw, err := buildAuthURL(intent)
	if err != nil {
		t.Fatalf("buildAuthURL: %v", err)
	}

	u, _ := url.Parse(raw)
	q := u.Query()

	if q.Get("prompt") != "consent" {
		t.Errorf("prompt = %q, want %q", q.Get("prompt"), "consent")
	}
	if q.Get("access_type") != "offline" {
		t.Errorf("access_type = %q, want %q", q.Get("access_type"), "offline")
	}
	// Standard params should still be present.
	if q.Get("client_id") != "client" {
		t.Errorf("client_id = %q, want %q", q.Get("client_id"), "client")
	}
}

func TestBuildAuthURL_OrderedParams(t *testing.T) {
	intent := &protocol.Intent{
		AuthURL:         "https://auth.example.com/authorize",
		ClientID:        "client",
		RedirectURI:     "http://localhost/callback",
		CodeChallenge:   "ch",
		ChallengeMethod: "S256",
		State:           "s",
		Scopes:          []string{"read"},
		OrderQueryParams: []string{
			"response_type", "client_id", "redirect_uri",
			"scope", "state", "code_challenge", "code_challenge_method",
		},
	}

	raw, err := buildAuthURL(intent)
	if err != nil {
		t.Fatalf("buildAuthURL: %v", err)
	}

	// Extract the query string and verify ordering.
	u, _ := url.Parse(raw)
	qs := u.RawQuery

	// response_type should come before client_id
	rtIdx := indexOf(qs, "response_type=")
	cidIdx := indexOf(qs, "client_id=")
	if rtIdx >= cidIdx {
		t.Errorf("response_type should come before client_id in: %s", qs)
	}

	// client_id should come before redirect_uri
	ruIdx := indexOf(qs, "redirect_uri=")
	if cidIdx >= ruIdx {
		t.Errorf("client_id should come before redirect_uri in: %s", qs)
	}
}

func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

func TestHTTPTokenRedeemer_RedeemWithConfig_CustomHeaders(t *testing.T) {
	var gotHeaders http.Header
	var gotBody string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeaders = r.Header.Clone()
		bodyBytes, _ := io.ReadAll(r.Body)
		gotBody = string(bodyBytes)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token":"tok","token_type":"Bearer","expires_in":3600}`))
	}))
	defer ts.Close()

	redeemer := &HTTPTokenRedeemer{Client: http.DefaultClient}
	cfg := &reqconfig.Config{
		RequestHeaders: map[string]string{
			"User-Agent": "TestApp/1.0",
			"X-Custom":   "value",
		},
		OrderBodyFields: []string{"grant_type", "code", "client_id", "redirect_uri"},
	}

	resp, err := redeemer.RedeemWithConfig(context.Background(), ts.URL, "my-client", "test-code", "http://localhost/cb", cfg)
	if err != nil {
		t.Fatalf("RedeemWithConfig: %v", err)
	}
	if resp.AccessToken != "tok" {
		t.Errorf("AccessToken = %q", resp.AccessToken)
	}

	if gotHeaders.Get("User-Agent") != "TestApp/1.0" {
		t.Errorf("User-Agent = %q, want %q", gotHeaders.Get("User-Agent"), "TestApp/1.0")
	}
	if gotHeaders.Get("X-Custom") != "value" {
		t.Errorf("X-Custom = %q, want %q", gotHeaders.Get("X-Custom"), "value")
	}

	// Verify body field ordering: grant_type should come first.
	if !hasPrefix(gotBody, "grant_type=") {
		t.Errorf("body should start with grant_type=, got: %s", gotBody)
	}
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func TestZeroString(t *testing.T) {
	s := "secret-value"
	zeroString(&s)
	if s != "" {
		t.Errorf("string should be empty after zeroString, got %q", s)
	}
}
