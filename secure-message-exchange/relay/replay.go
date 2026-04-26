package relay

import (
	"sync"
	"time"
)

// ReplayCache tracks seen MessageIDs for replay protection.
type ReplayCache struct {
	mu   sync.Mutex
	seen map[[32]byte]time.Time
	ttl  time.Duration
	now  func() time.Time // injectable clock for testing
}

// NewReplayCache creates a replay cache with the given TTL.
func NewReplayCache(ttl time.Duration) *ReplayCache {
	return &ReplayCache{
		seen: make(map[[32]byte]time.Time),
		ttl:  ttl,
		now:  time.Now,
	}
}

// Check returns true if the messageID has been seen before and hasn't expired.
func (rc *ReplayCache) Check(messageID [32]byte) bool {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	ts, exists := rc.seen[messageID]
	if !exists {
		return false
	}
	if rc.now().Sub(ts) > rc.ttl {
		delete(rc.seen, messageID)
		return false
	}
	return true
}

// Add marks a messageID as seen.
func (rc *ReplayCache) Add(messageID [32]byte) {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	rc.seen[messageID] = rc.now()

	// Lazy eviction: clean expired entries.
	now := rc.now()
	for id, ts := range rc.seen {
		if now.Sub(ts) > rc.ttl {
			delete(rc.seen, id)
		}
	}
}
