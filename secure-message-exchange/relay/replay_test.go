package relay

import (
	"testing"
	"time"
)

func TestReplayCache_AddCheck(t *testing.T) {
	rc := NewReplayCache(5 * time.Minute)

	var id [32]byte
	id[0] = 0x42

	if rc.Check(id) {
		t.Fatal("unseen ID returned true")
	}

	rc.Add(id)

	if !rc.Check(id) {
		t.Fatal("seen ID returned false")
	}
}

func TestReplayCache_Expiry(t *testing.T) {
	now := time.Now()
	rc := NewReplayCache(5 * time.Minute)
	rc.now = func() time.Time { return now }

	var id [32]byte
	id[0] = 0x01
	rc.Add(id)

	if !rc.Check(id) {
		t.Fatal("should be seen immediately after Add")
	}

	// Advance time past TTL.
	rc.now = func() time.Time { return now.Add(6 * time.Minute) }

	if rc.Check(id) {
		t.Fatal("expired ID should return false")
	}
}

func TestReplayCache_DifferentIDs(t *testing.T) {
	rc := NewReplayCache(5 * time.Minute)

	var id1, id2 [32]byte
	id1[0] = 0x01
	id2[0] = 0x02

	rc.Add(id1)

	if !rc.Check(id1) {
		t.Fatal("id1 should be seen")
	}
	if rc.Check(id2) {
		t.Fatal("id2 should not be seen")
	}
}
