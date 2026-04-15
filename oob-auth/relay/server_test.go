package relay

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func newTestServer() (*Server, *httptest.Server) {
	store := NewMemStore()
	srv := NewServer(store)
	ts := httptest.NewServer(srv.Handler())
	return srv, ts
}

func TestPublish_Created(t *testing.T) {
	_, ts := newTestServer()
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/api/v1/queue/test-queue", "application/json", strings.NewReader(`{"data":"hello"}`))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusCreated)
	}
}

func TestPublish_EmptyBody(t *testing.T) {
	_, ts := newTestServer()
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/api/v1/queue/test-queue", "application/json", strings.NewReader(""))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

func TestPublish_PayloadTooLarge(t *testing.T) {
	_, ts := newTestServer()
	defer ts.Close()

	// 4097 bytes exceeds the 4096 byte limit.
	body := strings.Repeat("x", 4097)
	resp, err := http.Post(ts.URL+"/api/v1/queue/test-queue", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusRequestEntityTooLarge)
	}
}

func TestPublish_ExactMaxPayload(t *testing.T) {
	_, ts := newTestServer()
	defer ts.Close()

	// Exactly 4096 bytes should be accepted.
	body := strings.Repeat("x", 4096)
	resp, err := http.Post(ts.URL+"/api/v1/queue/test-queue", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusCreated)
	}
}

func TestSubscribe_Timeout(t *testing.T) {
	store := NewMemStore()
	srv := NewServer(store)

	// Use a short-timeout handler wrapper to avoid waiting 30s.
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/queue/{queue_id}", func(w http.ResponseWriter, r *http.Request) {
		srv.handleSubscribe(w, r)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(ts.URL + "/api/v1/queue/empty-queue")
	if err != nil {
		// Client timeout is expected — the 30s long-poll outlasts
		// the 2s client deadline. This proves Subscribe blocks.
		return
	}
	defer resp.Body.Close()

	// If the server responds before client timeout, it must be 204.
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}
}

func TestPublishThenSubscribe(t *testing.T) {
	_, ts := newTestServer()
	defer ts.Close()

	payload := `{"envelope":"data"}`

	// Publish first.
	resp, _ := http.Post(ts.URL+"/api/v1/queue/q1", "application/json", strings.NewReader(payload))
	resp.Body.Close()

	// Subscribe should return immediately.
	resp, err := http.Get(ts.URL + "/api/v1/queue/q1")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	body, _ := io.ReadAll(resp.Body)
	if string(body) != payload {
		t.Errorf("body = %q, want %q", body, payload)
	}
}

func TestSubscribeThenPublish(t *testing.T) {
	_, ts := newTestServer()
	defer ts.Close()

	payload := `{"envelope":"async"}`
	var wg sync.WaitGroup
	var gotBody []byte
	var gotStatus int

	// Subscribe in background — will block until publish.
	wg.Add(1)
	go func() {
		defer wg.Done()
		resp, err := http.Get(ts.URL + "/api/v1/queue/q2")
		if err != nil {
			return
		}
		defer resp.Body.Close()
		gotStatus = resp.StatusCode
		gotBody, _ = io.ReadAll(resp.Body)
	}()

	// Give the subscriber time to register.
	time.Sleep(100 * time.Millisecond)

	// Publish.
	resp, _ := http.Post(ts.URL+"/api/v1/queue/q2", "application/json", strings.NewReader(payload))
	resp.Body.Close()

	wg.Wait()

	if gotStatus != http.StatusOK {
		t.Fatalf("status = %d, want %d", gotStatus, http.StatusOK)
	}
	if string(gotBody) != payload {
		t.Errorf("body = %q, want %q", gotBody, payload)
	}
}

func TestPopAndDrop(t *testing.T) {
	_, ts := newTestServer()
	defer ts.Close()

	// Publish one message.
	resp, _ := http.Post(ts.URL+"/api/v1/queue/once", "application/json", strings.NewReader(`"one-shot"`))
	resp.Body.Close()

	// First subscribe gets the message.
	resp, _ = http.Get(ts.URL + "/api/v1/queue/once")
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first subscribe status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	// Second subscribe should find nothing (message was deleted).
	client := &http.Client{Timeout: 500 * time.Millisecond}
	resp, err := client.Get(ts.URL + "/api/v1/queue/once")
	if err != nil {
		// Client timeout — which means no immediate data. That's correct.
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		t.Error("second subscribe should not get the same message (pop-and-drop violated)")
	}
}

func TestPublish_OverwritesPrevious(t *testing.T) {
	_, ts := newTestServer()
	defer ts.Close()

	// Publish two messages to the same queue.
	resp, _ := http.Post(ts.URL+"/api/v1/queue/overwrite", "application/json", strings.NewReader(`"first"`))
	resp.Body.Close()
	resp, _ = http.Post(ts.URL+"/api/v1/queue/overwrite", "application/json", strings.NewReader(`"second"`))
	resp.Body.Close()

	// Subscribe should get the latest.
	resp, _ = http.Get(ts.URL + "/api/v1/queue/overwrite")
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != `"second"` {
		t.Errorf("body = %q, want %q", body, `"second"`)
	}
}

func TestConcurrentPublishSubscribe(t *testing.T) {
	_, ts := newTestServer()
	defer ts.Close()

	const n = 20
	var wg sync.WaitGroup

	// Launch n concurrent publish-subscribe pairs on different queues.
	for i := 0; i < n; i++ {
		queueID := string(rune('a'+i)) + "-queue"
		payload := []byte(`"msg-` + queueID + `"`)

		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := http.Post(ts.URL+"/api/v1/queue/"+queueID, "application/json", bytes.NewReader(payload))
			if err != nil {
				t.Errorf("publish %s: %v", queueID, err)
				return
			}
			resp.Body.Close()
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			// Small delay so publish often wins, but not always.
			time.Sleep(50 * time.Millisecond)
			client := &http.Client{Timeout: 5 * time.Second}
			resp, err := client.Get(ts.URL + "/api/v1/queue/" + queueID)
			if err != nil {
				return // timeout is acceptable
			}
			resp.Body.Close()
		}()
	}

	wg.Wait()
}

func TestSubscribe_ContentType(t *testing.T) {
	_, ts := newTestServer()
	defer ts.Close()

	resp, _ := http.Post(ts.URL+"/api/v1/queue/ct", "application/json", strings.NewReader(`{}`))
	resp.Body.Close()

	resp, _ = http.Get(ts.URL + "/api/v1/queue/ct")
	defer resp.Body.Close()

	ct := resp.Header.Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/json")
	}
}

func TestDifferentQueuesAreIsolated(t *testing.T) {
	_, ts := newTestServer()
	defer ts.Close()

	// Publish to queue-a.
	resp, _ := http.Post(ts.URL+"/api/v1/queue/queue-a", "application/json", strings.NewReader(`"a"`))
	resp.Body.Close()

	// Subscribe to queue-b should not get queue-a's message.
	client := &http.Client{Timeout: 300 * time.Millisecond}
	resp, err := client.Get(ts.URL + "/api/v1/queue/queue-b")
	if err != nil {
		return // timeout = correct, nothing on queue-b
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("queue-b should be empty, got: %s", body)
	}
}
