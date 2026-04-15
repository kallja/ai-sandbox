package relay

import (
	"context"
	"sync"
	"time"
)

const defaultTTL = 5 * time.Minute

// message is an entry in the in-memory store with a creation timestamp
// for TTL-based expiry.
type message struct {
	data      []byte
	createdAt time.Time
}

// MemStore is an in-memory implementation of Store suitable for tests
// and local development. It supports long-poll notification via per-queue
// channels and automatic TTL expiry.
type MemStore struct {
	mu       sync.Mutex
	messages map[string]*message
	waiters  map[string][]chan struct{}
	ttl      time.Duration
	now      func() time.Time // injectable clock for testing
}

// MemStoreOption configures a MemStore.
type MemStoreOption func(*MemStore)

// WithTTL sets a custom message TTL (default 5 minutes).
func WithTTL(d time.Duration) MemStoreOption {
	return func(m *MemStore) { m.ttl = d }
}

// WithClock injects a custom time source for deterministic testing.
func WithClock(fn func() time.Time) MemStoreOption {
	return func(m *MemStore) { m.now = fn }
}

// NewMemStore creates a new in-memory store.
func NewMemStore(opts ...MemStoreOption) *MemStore {
	ms := &MemStore{
		messages: make(map[string]*message),
		waiters:  make(map[string][]chan struct{}),
		ttl:      defaultTTL,
		now:      time.Now,
	}
	for _, opt := range opts {
		opt(ms)
	}
	return ms
}

// Publish stores a message and notifies any waiting subscribers.
func (ms *MemStore) Publish(ctx context.Context, queueID string, data []byte) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	stored := make([]byte, len(data))
	copy(stored, data)
	ms.messages[queueID] = &message{data: stored, createdAt: ms.now()}

	// Wake up all waiters for this queue.
	for _, ch := range ms.waiters[queueID] {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
	ms.waiters[queueID] = nil

	return nil
}

// Subscribe blocks until a message arrives or the context expires.
// On success, atomically returns the message and deletes it (pop-and-drop).
func (ms *MemStore) Subscribe(ctx context.Context, queueID string) ([]byte, error) {
	// Fast path: message already present.
	if data := ms.tryPop(queueID); data != nil {
		return data, nil
	}

	// Slow path: register a waiter and block.
	ch := make(chan struct{}, 1)
	ms.mu.Lock()
	ms.waiters[queueID] = append(ms.waiters[queueID], ch)
	ms.mu.Unlock()

	select {
	case <-ch:
		if data := ms.tryPop(queueID); data != nil {
			return data, nil
		}
		// Another subscriber grabbed it — treat as timeout.
		return nil, nil
	case <-ctx.Done():
		ms.removeWaiter(queueID, ch)
		// One last check in case a publish raced with cancellation.
		return ms.tryPop(queueID), nil
	}
}

// tryPop atomically reads and deletes a non-expired message.
func (ms *MemStore) tryPop(queueID string) []byte {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	msg, ok := ms.messages[queueID]
	if !ok {
		return nil
	}
	if ms.now().Sub(msg.createdAt) > ms.ttl {
		delete(ms.messages, queueID)
		return nil
	}

	data := msg.data
	delete(ms.messages, queueID)
	return data
}

// removeWaiter cleans up a registered waiter channel.
func (ms *MemStore) removeWaiter(queueID string, ch chan struct{}) {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	waiters := ms.waiters[queueID]
	for i, w := range waiters {
		if w == ch {
			ms.waiters[queueID] = append(waiters[:i], waiters[i+1:]...)
			break
		}
	}
}
