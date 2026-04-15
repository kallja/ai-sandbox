package clienta

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
)

// mockRelay simulates the relay backend for testing.
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

// simulateBroker acts as Client B in the background: subscribes for the
// intent, builds a canned token response, encrypts it, and publishes back.
func simulateBroker(t *testing.T, relayURL string, brokerKP, requesterKP *crypto.KeyPair, resp *protocol.Response) {
	t.Helper()
	brokerQueueID := crypto.QueueID(brokerKP.Public)

	// Poll for the intent.
	var envData []byte
	for i := 0; i < 50; i++ {
		r, err := http.Get(relayURL + "/api/v1/queue/" + brokerQueueID)
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
		t.Error("broker: never received intent")
		return
	}

	// Decrypt intent (verify it's valid).
	env, _ := protocol.UnmarshalEnvelope(envData)
	_, err := crypto.Open(env.Ciphertext, env.Nonce, requesterKP.Public, brokerKP.Private)
	if err != nil {
		t.Errorf("broker: decrypt intent: %v", err)
		return
	}

	// Encrypt and publish the response.
	respData, _ := protocol.MarshalResponse(resp)
	nonce, ct, _ := crypto.Seal(respData, brokerKP.Private, requesterKP.Public)

	respEnv := &protocol.Envelope{
		SenderID:   crypto.Fingerprint(brokerKP.Public),
		Nonce:      nonce,
		Ciphertext: ct,
	}
	respEnvData, _ := protocol.MarshalEnvelope(respEnv)

	reqQueueID := crypto.QueueID(requesterKP.Public)
	http.Post(relayURL+"/api/v1/queue/"+reqQueueID, "application/json", bytes.NewReader(respEnvData))
}

func TestRun_ReceivesAccessToken(t *testing.T) {
	requester, _ := crypto.GenerateKeyPair()
	broker, _ := crypto.GenerateKeyPair()

	relay := newMockRelay()
	ts := httptest.NewServer(relay)
	defer ts.Close()

	cfg := &Config{
		RelayURL:    ts.URL,
		AuthURL:     "https://auth.example.com/authorize",
		TokenURL:    "https://auth.example.com/token",
		ClientID:    "test-client",
		Scopes:      []string{"read", "write"},
		RedirectURI: "http://localhost/callback",
		PrivateKey:  requester.Private,
		PeerPub:     broker.Public,
	}

	expectedResp := &protocol.Response{
		AccessToken: "test-token-123",
		TokenType:   "Bearer",
		ExpiresIn:   3600,
	}

	go simulateBroker(t, ts.URL, broker, requester, expectedResp)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := Run(ctx, cfg, http.DefaultClient)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if result.AccessToken != "test-token-123" {
		t.Errorf("AccessToken = %q, want %q", result.AccessToken, "test-token-123")
	}
	if result.TokenType != "Bearer" {
		t.Errorf("TokenType = %q, want %q", result.TokenType, "Bearer")
	}
	if result.ExpiresIn != 3600 {
		t.Errorf("ExpiresIn = %d, want 3600", result.ExpiresIn)
	}
}

func TestRun_ReceivesAuthCode(t *testing.T) {
	requester, _ := crypto.GenerateKeyPair()
	broker, _ := crypto.GenerateKeyPair()

	relay := newMockRelay()
	ts := httptest.NewServer(relay)
	defer ts.Close()

	cfg := &Config{
		RelayURL:    ts.URL,
		AuthURL:     "https://auth.example.com/authorize",
		ClientID:    "test-client",
		RedirectURI: "http://localhost/callback",
		PrivateKey:  requester.Private,
		PeerPub:     broker.Public,
	}

	go simulateBroker(t, ts.URL, broker, requester, &protocol.Response{AuthCode: "code-abc"})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := Run(ctx, cfg, http.DefaultClient)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if result.AuthCode != "code-abc" {
		t.Errorf("AuthCode = %q, want %q", result.AuthCode, "code-abc")
	}
}

func TestRun_ReceivesError(t *testing.T) {
	requester, _ := crypto.GenerateKeyPair()
	broker, _ := crypto.GenerateKeyPair()

	relay := newMockRelay()
	ts := httptest.NewServer(relay)
	defer ts.Close()

	cfg := &Config{
		RelayURL:    ts.URL,
		AuthURL:     "https://auth.example.com/authorize",
		ClientID:    "test-client",
		RedirectURI: "http://localhost/callback",
		PrivateKey:  requester.Private,
		PeerPub:     broker.Public,
	}

	go simulateBroker(t, ts.URL, broker, requester, &protocol.Response{Error: "access_denied"})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := Run(ctx, cfg, http.DefaultClient)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if result.Error != "access_denied" {
		t.Errorf("Error = %q, want %q", result.Error, "access_denied")
	}
}

func TestRun_ContextCancellation(t *testing.T) {
	requester, _ := crypto.GenerateKeyPair()
	broker, _ := crypto.GenerateKeyPair()

	relay := newMockRelay()
	ts := httptest.NewServer(relay)
	defer ts.Close()

	cfg := &Config{
		RelayURL:    ts.URL,
		AuthURL:     "https://auth.example.com/authorize",
		ClientID:    "test-client",
		RedirectURI: "http://localhost/callback",
		PrivateKey:  requester.Private,
		PeerPub:     broker.Public,
	}

	// No broker running — requester should time out.
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	_, err := Run(ctx, cfg, http.DefaultClient)
	if err == nil {
		t.Fatal("Run should fail when context is cancelled")
	}
}

func TestPublish_Success(t *testing.T) {
	var gotBody []byte
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusCreated)
	}))
	defer ts.Close()

	env := &protocol.Envelope{
		SenderID:   "test-sender",
		Nonce:      [24]byte{1, 2, 3},
		Ciphertext: []byte("encrypted"),
	}

	err := publish(context.Background(), http.DefaultClient, ts.URL, "q1", env)
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	if len(gotBody) == 0 {
		t.Error("server received empty body")
	}
}

func TestPublish_ServerError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	env := &protocol.Envelope{SenderID: "test", Ciphertext: []byte("x")}
	err := publish(context.Background(), http.DefaultClient, ts.URL, "q1", env)
	if err == nil {
		t.Error("publish should fail on 500")
	}
}

func TestSubscribe_ImmediateData(t *testing.T) {
	env := &protocol.Envelope{SenderID: "test", Nonce: [24]byte{1}, Ciphertext: []byte("ct")}
	envData, _ := protocol.MarshalEnvelope(env)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(envData)
	}))
	defer ts.Close()

	got, err := subscribe(context.Background(), http.DefaultClient, ts.URL, "q1")
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	if got.SenderID != "test" {
		t.Errorf("SenderID = %q, want %q", got.SenderID, "test")
	}
}

func TestSubscribe_ReconnectsOn204(t *testing.T) {
	attempts := 0
	env := &protocol.Envelope{SenderID: "test", Nonce: [24]byte{1}, Ciphertext: []byte("ct")}
	envData, _ := protocol.MarshalEnvelope(env)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 3 {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write(envData)
	}))
	defer ts.Close()

	got, err := subscribe(context.Background(), http.DefaultClient, ts.URL, "q1")
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	if attempts != 3 {
		t.Errorf("attempts = %d, want 3", attempts)
	}
	if got.SenderID != "test" {
		t.Errorf("SenderID = %q, want %q", got.SenderID, "test")
	}
}

func TestSubscribe_ServerError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("boom"))
	}))
	defer ts.Close()

	_, err := subscribe(context.Background(), http.DefaultClient, ts.URL, "q1")
	if err == nil {
		t.Error("subscribe should fail on 500")
	}
}
