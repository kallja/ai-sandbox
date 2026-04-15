// Package integration contains end-to-end tests that wire up all three
// OOB-Auth components: relay (with in-memory store), Client A (Requester),
// and Client B (Broker). All communication goes through real HTTP using
// httptest, with mock OAuth for the authorization step.
package integration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kallja/ai-sandbox/oob-auth/clienta"
	"github.com/kallja/ai-sandbox/oob-auth/clientb"
	"github.com/kallja/ai-sandbox/oob-auth/crypto"
	"github.com/kallja/ai-sandbox/oob-auth/protocol"
	"github.com/kallja/ai-sandbox/oob-auth/relay"
)

// mockOAuth is a test OAuthExecutor that returns a fixed auth code
// and records the intent it received.
type mockOAuth struct {
	code       string
	gotIntent  *protocol.Intent
}

func (m *mockOAuth) Authorize(ctx context.Context, intent *protocol.Intent) (string, error) {
	m.gotIntent = intent
	return m.code, nil
}

// mockTokenEndpoint returns a fake token response.
func mockTokenEndpoint() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token":"e2e-access-token","token_type":"Bearer","expires_in":3600}`))
	}))
}

func TestE2E_CodeMode(t *testing.T) {
	// Setup: generate key pairs for both parties.
	requesterKP, _ := crypto.GenerateKeyPair()
	brokerKP, _ := crypto.GenerateKeyPair()

	// Start the relay with in-memory store.
	store := relay.NewMemStore()
	relaySrv := relay.NewServer(store)
	relayTS := httptest.NewServer(relaySrv.Handler())
	defer relayTS.Close()

	// Configure Client A.
	cfgA := &clienta.Config{
		RelayURL:    relayTS.URL,
		AuthURL:     "https://auth.example.com/authorize",
		TokenURL:    "https://auth.example.com/token",
		ClientID:    "e2e-client",
		Scopes:      []string{"read", "write"},
		RedirectURI: "http://localhost/callback",
		PrivateKey:  requesterKP.Private,
		PeerPub:     brokerKP.Public,
	}

	// Configure Client B.
	cfgB := &clientb.Config{
		RelayURL:   relayTS.URL,
		PrivateKey: brokerKP.Private,
		PeerPub:    requesterKP.Public,
		Mode:       "code",
	}

	auth := &mockOAuth{code: "e2e-auth-code"}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Run both clients concurrently.
	brokerErr := make(chan error, 1)
	go func() {
		brokerErr <- clientb.Run(ctx, cfgB, http.DefaultClient, auth, nil)
	}()

	result, err := clienta.Run(ctx, cfgA, http.DefaultClient)
	if err != nil {
		t.Fatalf("Client A: %v", err)
	}

	// Verify the result.
	if result.AuthCode != "e2e-auth-code" {
		t.Errorf("AuthCode = %q, want %q", result.AuthCode, "e2e-auth-code")
	}
	if result.AccessToken != "" {
		t.Errorf("AccessToken should be empty in code mode, got %q", result.AccessToken)
	}

	// Verify the broker saw the correct intent.
	if err := <-brokerErr; err != nil {
		t.Errorf("Client B: %v", err)
	}
	if auth.gotIntent == nil {
		t.Fatal("broker never received an intent")
	}
	if auth.gotIntent.ClientID != "e2e-client" {
		t.Errorf("intent ClientID = %q, want %q", auth.gotIntent.ClientID, "e2e-client")
	}
	if auth.gotIntent.ChallengeMethod != "S256" {
		t.Errorf("intent ChallengeMethod = %q, want %q", auth.gotIntent.ChallengeMethod, "S256")
	}
	if len(auth.gotIntent.Scopes) != 2 {
		t.Errorf("intent Scopes = %v, want [read write]", auth.gotIntent.Scopes)
	}
}

func TestE2E_TokenMode(t *testing.T) {
	requesterKP, _ := crypto.GenerateKeyPair()
	brokerKP, _ := crypto.GenerateKeyPair()

	store := relay.NewMemStore()
	relaySrv := relay.NewServer(store)
	relayTS := httptest.NewServer(relaySrv.Handler())
	defer relayTS.Close()

	// Mock token endpoint.
	tokenTS := mockTokenEndpoint()
	defer tokenTS.Close()

	cfgA := &clienta.Config{
		RelayURL:    relayTS.URL,
		AuthURL:     "https://auth.example.com/authorize",
		TokenURL:    tokenTS.URL,
		ClientID:    "e2e-client",
		Scopes:      []string{"admin"},
		RedirectURI: "http://localhost/callback",
		PrivateKey:  requesterKP.Private,
		PeerPub:     brokerKP.Public,
	}

	cfgB := &clientb.Config{
		RelayURL:   relayTS.URL,
		PrivateKey: brokerKP.Private,
		PeerPub:    requesterKP.Public,
		Mode:       "token",
	}

	auth := &mockOAuth{code: "code-to-redeem"}
	redeemer := &clientb.HTTPTokenRedeemer{Client: http.DefaultClient}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	brokerErr := make(chan error, 1)
	go func() {
		brokerErr <- clientb.Run(ctx, cfgB, http.DefaultClient, auth, redeemer)
	}()

	result, err := clienta.Run(ctx, cfgA, http.DefaultClient)
	if err != nil {
		t.Fatalf("Client A: %v", err)
	}

	if result.AccessToken != "e2e-access-token" {
		t.Errorf("AccessToken = %q, want %q", result.AccessToken, "e2e-access-token")
	}
	if result.TokenType != "Bearer" {
		t.Errorf("TokenType = %q, want %q", result.TokenType, "Bearer")
	}
	if result.ExpiresIn != 3600 {
		t.Errorf("ExpiresIn = %d, want 3600", result.ExpiresIn)
	}

	if err := <-brokerErr; err != nil {
		t.Errorf("Client B: %v", err)
	}
}

func TestE2E_WithCloudflareMiddleware(t *testing.T) {
	requesterKP, _ := crypto.GenerateKeyPair()
	brokerKP, _ := crypto.GenerateKeyPair()

	store := relay.NewMemStore()
	relaySrv := relay.NewServer(store)

	// Wrap with Cloudflare middleware.
	handler := relay.CloudflareMiddleware("cf-id", "cf-secret", relaySrv.Handler())
	relayTS := httptest.NewServer(handler)
	defer relayTS.Close()

	// Client that injects CF headers on every request.
	cfTransport := &cfHeaderTransport{
		base:     http.DefaultTransport,
		clientID: "cf-id",
		secret:   "cf-secret",
	}
	cfClient := &http.Client{Transport: cfTransport}

	cfgA := &clienta.Config{
		RelayURL:    relayTS.URL,
		AuthURL:     "https://auth.example.com/authorize",
		ClientID:    "cf-test",
		RedirectURI: "http://localhost/callback",
		PrivateKey:  requesterKP.Private,
		PeerPub:     brokerKP.Public,
	}

	cfgB := &clientb.Config{
		RelayURL:   relayTS.URL,
		PrivateKey: brokerKP.Private,
		PeerPub:    requesterKP.Public,
		Mode:       "code",
	}

	auth := &mockOAuth{code: "cf-code"}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	brokerErr := make(chan error, 1)
	go func() {
		brokerErr <- clientb.Run(ctx, cfgB, cfClient, auth, nil)
	}()

	result, err := clienta.Run(ctx, cfgA, cfClient)
	if err != nil {
		t.Fatalf("Client A: %v", err)
	}

	if result.AuthCode != "cf-code" {
		t.Errorf("AuthCode = %q, want %q", result.AuthCode, "cf-code")
	}

	if err := <-brokerErr; err != nil {
		t.Errorf("Client B: %v", err)
	}
}

func TestE2E_CloudflareMiddleware_Rejects(t *testing.T) {
	store := relay.NewMemStore()
	relaySrv := relay.NewServer(store)
	handler := relay.CloudflareMiddleware("cf-id", "cf-secret", relaySrv.Handler())
	relayTS := httptest.NewServer(handler)
	defer relayTS.Close()

	// Request without CF headers should be rejected.
	resp, err := http.Post(relayTS.URL+"/api/v1/queue/test", "application/json", nil)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
}

func TestE2E_QueueIsolation(t *testing.T) {
	// Verify that two separate requester-broker pairs don't interfere.
	kpA1, _ := crypto.GenerateKeyPair()
	kpB1, _ := crypto.GenerateKeyPair()
	kpA2, _ := crypto.GenerateKeyPair()
	kpB2, _ := crypto.GenerateKeyPair()

	store := relay.NewMemStore()
	relaySrv := relay.NewServer(store)
	relayTS := httptest.NewServer(relaySrv.Handler())
	defer relayTS.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Pair 1.
	cfgA1 := &clienta.Config{
		RelayURL: relayTS.URL, AuthURL: "https://a.com/auth", ClientID: "pair1",
		RedirectURI: "http://localhost/cb", PrivateKey: kpA1.Private, PeerPub: kpB1.Public,
	}
	cfgB1 := &clientb.Config{
		RelayURL: relayTS.URL, PrivateKey: kpB1.Private, PeerPub: kpA1.Public, Mode: "code",
	}
	auth1 := &mockOAuth{code: "code-pair-1"}

	// Pair 2.
	cfgA2 := &clienta.Config{
		RelayURL: relayTS.URL, AuthURL: "https://b.com/auth", ClientID: "pair2",
		RedirectURI: "http://localhost/cb", PrivateKey: kpA2.Private, PeerPub: kpB2.Public,
	}
	cfgB2 := &clientb.Config{
		RelayURL: relayTS.URL, PrivateKey: kpB2.Private, PeerPub: kpA2.Public, Mode: "code",
	}
	auth2 := &mockOAuth{code: "code-pair-2"}

	// Run all four clients concurrently.
	go clientb.Run(ctx, cfgB1, http.DefaultClient, auth1, nil)
	go clientb.Run(ctx, cfgB2, http.DefaultClient, auth2, nil)

	r1 := make(chan *clienta.Result, 1)
	r2 := make(chan *clienta.Result, 1)

	go func() {
		res, _ := clienta.Run(ctx, cfgA1, http.DefaultClient)
		r1 <- res
	}()
	go func() {
		res, _ := clienta.Run(ctx, cfgA2, http.DefaultClient)
		r2 <- res
	}()

	res1 := <-r1
	res2 := <-r2

	if res1 == nil || res1.AuthCode != "code-pair-1" {
		t.Errorf("pair 1 AuthCode = %v, want code-pair-1", res1)
	}
	if res2 == nil || res2.AuthCode != "code-pair-2" {
		t.Errorf("pair 2 AuthCode = %v, want code-pair-2", res2)
	}
}

// cfHeaderTransport injects Cloudflare Access headers into every request.
type cfHeaderTransport struct {
	base     http.RoundTripper
	clientID string
	secret   string
}

func (t *cfHeaderTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("CF-Access-Client-Id", t.clientID)
	req.Header.Set("CF-Access-Client-Secret", t.secret)
	return t.base.RoundTrip(req)
}
