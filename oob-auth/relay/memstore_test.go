package relay

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestMemStore_PublishSubscribe(t *testing.T) {
	ms := NewMemStore()
	ctx := context.Background()

	if err := ms.Publish(ctx, "q1", []byte("hello")); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	data, err := ms.Subscribe(ctx, "q1")
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	if string(data) != "hello" {
		t.Errorf("data = %q, want %q", data, "hello")
	}
}

func TestMemStore_SubscribeWaitsForPublish(t *testing.T) {
	ms := NewMemStore()
	ctx := context.Background()

	var got []byte
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		got, _ = ms.Subscribe(ctx, "q1")
	}()

	// Let subscriber register.
	time.Sleep(50 * time.Millisecond)
	ms.Publish(ctx, "q1", []byte("delayed"))
	wg.Wait()

	if string(got) != "delayed" {
		t.Errorf("data = %q, want %q", got, "delayed")
	}
}

func TestMemStore_SubscribeTimeout(t *testing.T) {
	ms := NewMemStore()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	data, err := ms.Subscribe(ctx, "empty")
	if err != nil {
		t.Fatalf("Subscribe error: %v", err)
	}
	if data != nil {
		t.Errorf("expected nil data on timeout, got %q", data)
	}
}

func TestMemStore_PopAndDrop(t *testing.T) {
	ms := NewMemStore()
	ctx := context.Background()

	ms.Publish(ctx, "q1", []byte("once"))

	// First pop.
	data, _ := ms.Subscribe(ctx, "q1")
	if string(data) != "once" {
		t.Fatalf("first pop = %q, want %q", data, "once")
	}

	// Second pop should find nothing.
	ctx2, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	data, _ = ms.Subscribe(ctx2, "q1")
	if data != nil {
		t.Errorf("second pop should be nil, got %q", data)
	}
}

func TestMemStore_TTLExpiry(t *testing.T) {
	now := time.Now()
	ms := NewMemStore(
		WithTTL(1*time.Second),
		WithClock(func() time.Time { return now }),
	)
	ctx := context.Background()

	ms.Publish(ctx, "q1", []byte("will expire"))

	// Advance the clock past TTL.
	now = now.Add(2 * time.Second)

	ctx2, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	data, _ := ms.Subscribe(ctx2, "q1")
	if data != nil {
		t.Errorf("expected nil for expired message, got %q", data)
	}
}

func TestMemStore_TTLNotExpired(t *testing.T) {
	now := time.Now()
	ms := NewMemStore(
		WithTTL(10*time.Second),
		WithClock(func() time.Time { return now }),
	)
	ctx := context.Background()

	ms.Publish(ctx, "q1", []byte("still fresh"))

	// Advance clock but stay within TTL.
	now = now.Add(5 * time.Second)

	data, _ := ms.Subscribe(ctx, "q1")
	if string(data) != "still fresh" {
		t.Errorf("data = %q, want %q", data, "still fresh")
	}
}

func TestMemStore_OverwritesPreviousMessage(t *testing.T) {
	ms := NewMemStore()
	ctx := context.Background()

	ms.Publish(ctx, "q1", []byte("first"))
	ms.Publish(ctx, "q1", []byte("second"))

	data, _ := ms.Subscribe(ctx, "q1")
	if string(data) != "second" {
		t.Errorf("data = %q, want %q", data, "second")
	}
}

func TestMemStore_IsolatedQueues(t *testing.T) {
	ms := NewMemStore()
	ctx := context.Background()

	ms.Publish(ctx, "q1", []byte("for-q1"))
	ms.Publish(ctx, "q2", []byte("for-q2"))

	data, _ := ms.Subscribe(ctx, "q1")
	if string(data) != "for-q1" {
		t.Errorf("q1 data = %q, want %q", data, "for-q1")
	}

	data, _ = ms.Subscribe(ctx, "q2")
	if string(data) != "for-q2" {
		t.Errorf("q2 data = %q, want %q", data, "for-q2")
	}
}

func TestMemStore_ConcurrentPublishSubscribe(t *testing.T) {
	ms := NewMemStore()
	ctx := context.Background()

	const n = 50
	var wg sync.WaitGroup

	for i := 0; i < n; i++ {
		queueID := string(rune('A' + i%26))
		wg.Add(2)

		go func() {
			defer wg.Done()
			ms.Publish(ctx, queueID, []byte("msg"))
		}()

		go func() {
			defer wg.Done()
			subCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()
			ms.Subscribe(subCtx, queueID)
		}()
	}

	wg.Wait()
}

func TestMemStore_DataIsCopied(t *testing.T) {
	ms := NewMemStore()
	ctx := context.Background()

	original := []byte("mutable")
	ms.Publish(ctx, "q1", original)

	// Mutate the original after publishing.
	original[0] = 'X'

	data, _ := ms.Subscribe(ctx, "q1")
	if string(data) != "mutable" {
		t.Errorf("stored data was mutated: got %q, want %q", data, "mutable")
	}
}

func TestMemStore_MultipleWaiters(t *testing.T) {
	ms := NewMemStore()
	ctx := context.Background()

	results := make([][]byte, 3)
	var wg sync.WaitGroup

	// Three subscribers on the same queue.
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			subCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()
			results[i], _ = ms.Subscribe(subCtx, "contested")
		}()
	}

	time.Sleep(50 * time.Millisecond)
	ms.Publish(ctx, "contested", []byte("prize"))
	wg.Wait()

	// Exactly one subscriber should get the message.
	gotCount := 0
	for _, r := range results {
		if r != nil {
			gotCount++
		}
	}
	if gotCount != 1 {
		t.Errorf("%d subscribers got the message, want exactly 1", gotCount)
	}
}
