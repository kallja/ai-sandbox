package clientb

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/kallja/ai-sandbox/oob-auth/crypto"
	"github.com/kallja/ai-sandbox/oob-auth/protocol"
	"github.com/kallja/ai-sandbox/oob-auth/reqconfig"
)

// mockRelay is a minimal relay simulation for broker tests.
type mockRelay struct {
	mu      sync.Mutex
	queues  map[string][]byte
	waiters map[string][]chan struct{}
}

func newMockRelay() *mockRelay {
	return &mockRelay{
		queues:  make(map[string][]byte),
		waiters: make(map[string][]chan struct{}),
	}
}

func (m *mockRelay) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	queueID := r.URL.Path[len("/api/v1/queue/"):]
	switch r.Method {
	case http.MethodPost:
		body, _ := io.ReadAll(r.Body)
		m.mu.Lock()
		m.queues[queueID] = body
		for _, ch := range m.waiters[queueID] {
			select {
			case ch <- struct{}{}:
			default:
			}
		}
		m.waiters[queueID] = nil
		m.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
	case http.MethodGet:
		m.mu.Lock()
		data, ok := m.queues[queueID]
		if ok {
			delete(m.queues, queueID)
			m.mu.Unlock()
			w.WriteHeader(http.StatusOK)
			w.Write(data)
			return
		}
		ch := make(chan struct{}, 1)
		m.waiters[queueID] = append(m.waiters[queueID], ch)
		m.mu.Unlock()

		select {
		case <-ch:
			m.mu.Lock()
			data, ok = m.queues[queueID]
			if ok {
				delete(m.queues, queueID)
			}
			m.mu.Unlock()
			if ok {
				w.WriteHeader(http.StatusOK)
				w.Write(data)
			} else {
				w.WriteHeader(http.StatusNoContent)
			}
		case <-r.Context().Done():
			w.WriteHeader(http.StatusNoContent)
		}
	}
}

// mockAuth is a test OAuthExecutor that returns a fixed auth code.
type mockAuth struct {
	code string
	err  error
}

func (m *mockAuth) Authorize(ctx context.Context, intent *protocol.Intent) (string, error) {
	return m.code, m.err
}

// mockRedeemer is a test TokenRedeemer that returns a fixed response.
type mockRedeemer struct {
	resp *protocol.Response
	err  error
}

func (m *mockRedeemer) Redeem(ctx context.Context, tokenURL, clientID, authCode, redirectURI string) (*protocol.Response, error) {
	return m.resp, m.err
}

func (m *mockRedeemer) RedeemWithConfig(ctx context.Context, tokenURL, clientID, authCode, redirectURI string, _ *reqconfig.Config) (*protocol.Response, error) {
	return m.resp, m.err
}

// publishIntent encrypts and publishes an intent to the broker's queue,
// simulating what Client A does.
func publishIntent(t *testing.T, relayURL string, requesterKP, brokerKP *crypto.KeyPair, intent *protocol.Intent) {
	t.Helper()
	plaintext, _ := protocol.MarshalIntent(intent)
	padded, _ := crypto.Pad(plaintext, protocol.PaddedPlaintextSize)
	nonce, ct, _ := crypto.Seal(padded, requesterKP.Private, brokerKP.Public)
	env := &protocol.Envelope{
		SenderID:   crypto.Fingerprint(requesterKP.Public),
		Nonce:      nonce[:],
		Ciphertext: ct,
	}
	envData, _ := protocol.MarshalEnvelope(env)
	brokerQueueID := crypto.QueueID(brokerKP.Public)
	http.Post(relayURL+"/api/v1/queue/"+brokerQueueID, "application/json", bytes.NewReader(envData))
}

// collectResponse subscribes on the requester's queue and decrypts the
// broker's response.
func collectResponse(t *testing.T, relayURL string, requesterKP, brokerKP *crypto.KeyPair) *protocol.Response {
	t.Helper()
	reqQueueID := crypto.QueueID(requesterKP.Public)

	var envData []byte
	for i := 0; i < 50; i++ {
		r, err := http.Get(relayURL + "/api/v1/queue/" + reqQueueID)
		if err != nil {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		if r.StatusCode == http.StatusOK {
			envData, _ = io.ReadAll(r.Body)
			r.Body.Close()
			break
		}
		r.Body.Close()
		time.Sleep(50 * time.Millisecond)
	}
	if envData == nil {
		t.Fatal("never received broker response")
	}

	env, _ := protocol.UnmarshalEnvelope(envData)
	var nonce [24]byte
	copy(nonce[:], env.Nonce)
	padded, err := crypto.Open(env.Ciphertext, nonce, brokerKP.Public, requesterKP.Private)
	if err != nil {
		t.Fatalf("decrypt broker response: %v", err)
	}
	plaintext, err := crypto.Unpad(padded)
	if err != nil {
		t.Fatalf("unpad broker response: %v", err)
	}
	resp, _ := protocol.UnmarshalResponse(plaintext)
	return resp
}

func TestRun_CodeMode(t *testing.T) {
	requester, _ := crypto.GenerateKeyPair()
	broker, _ := crypto.GenerateKeyPair()

	relay := newMockRelay()
	ts := httptest.NewServer(relay)
	defer ts.Close()

	cfg := &Config{
		RelayURL:   ts.URL,
		PrivateKey: broker.Private,
		PeerPub:    requester.Public,
		Mode:       "code",
	}

	intent := &protocol.Intent{
		AuthURL:         "https://auth.example.com/authorize",
		ClientID:        "test-client",
		Scopes:          []string{"read"},
		RedirectURI:     "http://localhost/callback",
		CodeChallenge:   "test-challenge",
		ChallengeMethod: "S256",
		State:           "test-state",
	}

	// Publish the intent, then run the broker.
	go func() {
		time.Sleep(50 * time.Millisecond)
		publishIntent(t, ts.URL, requester, broker, intent)
	}()

	auth := &mockAuth{code: "auth-code-xyz"}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Run broker in background so we can collect the response.
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, cfg, http.DefaultClient, auth, nil)
	}()

	resp := collectResponse(t, ts.URL, requester, broker)
	if resp.AuthCode != "auth-code-xyz" {
		t.Errorf("AuthCode = %q, want %q", resp.AuthCode, "auth-code-xyz")
	}

	if err := <-done; err != nil {
		t.Errorf("Run error: %v", err)
	}
}

func TestRun_TokenMode(t *testing.T) {
	requester, _ := crypto.GenerateKeyPair()
	broker, _ := crypto.GenerateKeyPair()

	relay := newMockRelay()
	ts := httptest.NewServer(relay)
	defer ts.Close()

	cfg := &Config{
		RelayURL:   ts.URL,
		PrivateKey: broker.Private,
		PeerPub:    requester.Public,
		Mode:       "token",
	}

	intent := &protocol.Intent{
		AuthURL:         "https://auth.example.com/authorize",
		TokenURL:        "https://auth.example.com/token",
		ClientID:        "test-client",
		RedirectURI:     "http://localhost/callback",
		CodeChallenge:   "challenge",
		ChallengeMethod: "S256",
		State:           "state",
	}

	go func() {
		time.Sleep(50 * time.Millisecond)
		publishIntent(t, ts.URL, requester, broker, intent)
	}()

	tokenResp := &protocol.Response{
		AccessToken: "token-from-redeemer",
		TokenType:   "Bearer",
		ExpiresIn:   7200,
	}
	auth := &mockAuth{code: "code-for-redemption"}
	redeemer := &mockRedeemer{resp: tokenResp}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, cfg, http.DefaultClient, auth, redeemer)
	}()

	resp := collectResponse(t, ts.URL, requester, broker)
	if resp.AccessToken != "token-from-redeemer" {
		t.Errorf("AccessToken = %q, want %q", resp.AccessToken, "token-from-redeemer")
	}
	if resp.ExpiresIn != 7200 {
		t.Errorf("ExpiresIn = %d, want 7200", resp.ExpiresIn)
	}

	if err := <-done; err != nil {
		t.Errorf("Run error: %v", err)
	}
}

func TestRun_AuthFailure_SendsError(t *testing.T) {
	requester, _ := crypto.GenerateKeyPair()
	broker, _ := crypto.GenerateKeyPair()

	relay := newMockRelay()
	ts := httptest.NewServer(relay)
	defer ts.Close()

	cfg := &Config{
		RelayURL:   ts.URL,
		PrivateKey: broker.Private,
		PeerPub:    requester.Public,
		Mode:       "code",
	}

	intent := &protocol.Intent{
		AuthURL:         "https://auth.example.com/authorize",
		ClientID:        "test-client",
		RedirectURI:     "http://localhost/callback",
		CodeChallenge:   "challenge",
		ChallengeMethod: "S256",
	}

	go func() {
		time.Sleep(50 * time.Millisecond)
		publishIntent(t, ts.URL, requester, broker, intent)
	}()

	auth := &mockAuth{err: context.DeadlineExceeded}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, cfg, http.DefaultClient, auth, nil)
	}()

	resp := collectResponse(t, ts.URL, requester, broker)
	if resp.Error == "" {
		t.Error("expected error response from broker")
	}
}

func TestRun_Timeout(t *testing.T) {
	requester, _ := crypto.GenerateKeyPair()
	broker, _ := crypto.GenerateKeyPair()

	relay := newMockRelay()
	ts := httptest.NewServer(relay)
	defer ts.Close()

	cfg := &Config{
		RelayURL:   ts.URL,
		PrivateKey: broker.Private,
		PeerPub:    requester.Public,
		Mode:       "code",
	}

	// No intent published — broker should time out.
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	auth := &mockAuth{code: "unused"}
	err := Run(ctx, cfg, http.DefaultClient, auth, nil)
	if err == nil {
		t.Error("Run should fail when no intent arrives")
	}
}
