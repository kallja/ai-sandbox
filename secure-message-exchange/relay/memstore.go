package relay

import (
	"context"
	"sync"
)

// MemStore implements Store with an in-memory FIFO queue per recipient.
type MemStore struct {
	mu     sync.Mutex
	queues map[string][][]byte
}

// NewMemStore creates a new in-memory store.
func NewMemStore() *MemStore {
	return &MemStore{queues: make(map[string][][]byte)}
}

func (m *MemStore) Push(_ context.Context, recipientFP string, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]byte, len(data))
	copy(cp, data)
	m.queues[recipientFP] = append(m.queues[recipientFP], cp)
	return nil
}

func (m *MemStore) Pop(_ context.Context, recipientFP string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	q := m.queues[recipientFP]
	if len(q) == 0 {
		return nil, nil
	}
	data := q[0]
	m.queues[recipientFP] = q[1:]
	if len(m.queues[recipientFP]) == 0 {
		delete(m.queues, recipientFP)
	}
	return data, nil
}
