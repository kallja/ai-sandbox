package relay

import (
	"bytes"
	"context"
	"testing"
)

func TestMemStore_PushPop(t *testing.T) {
	s := NewMemStore()
	ctx := context.Background()

	if err := s.Push(ctx, "alice", []byte("hello")); err != nil {
		t.Fatal(err)
	}

	data, err := s.Pop(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, []byte("hello")) {
		t.Fatalf("got %q, want %q", data, "hello")
	}
}

func TestMemStore_PopEmpty(t *testing.T) {
	s := NewMemStore()
	data, err := s.Pop(context.Background(), "nobody")
	if err != nil {
		t.Fatal(err)
	}
	if data != nil {
		t.Fatalf("expected nil, got %v", data)
	}
}

func TestMemStore_FIFO(t *testing.T) {
	s := NewMemStore()
	ctx := context.Background()

	s.Push(ctx, "bob", []byte("first"))
	s.Push(ctx, "bob", []byte("second"))
	s.Push(ctx, "bob", []byte("third"))

	for _, want := range []string{"first", "second", "third"} {
		data, err := s.Pop(ctx, "bob")
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != want {
			t.Fatalf("got %q, want %q", data, want)
		}
	}

	// Queue should be empty now.
	data, _ := s.Pop(ctx, "bob")
	if data != nil {
		t.Fatalf("expected nil after drain, got %v", data)
	}
}

func TestMemStore_QueueIsolation(t *testing.T) {
	s := NewMemStore()
	ctx := context.Background()

	s.Push(ctx, "alice", []byte("for alice"))
	s.Push(ctx, "bob", []byte("for bob"))

	data, _ := s.Pop(ctx, "alice")
	if string(data) != "for alice" {
		t.Fatalf("alice got %q", data)
	}
	data, _ = s.Pop(ctx, "bob")
	if string(data) != "for bob" {
		t.Fatalf("bob got %q", data)
	}

	// Cross-check: alice's queue is empty.
	data, _ = s.Pop(ctx, "alice")
	if data != nil {
		t.Fatal("alice queue should be empty")
	}
}

func TestMemStore_DataCopied(t *testing.T) {
	s := NewMemStore()
	ctx := context.Background()

	original := []byte("original")
	s.Push(ctx, "test", original)

	// Mutate the original slice.
	original[0] = 0xff

	data, _ := s.Pop(ctx, "test")
	if data[0] == 0xff {
		t.Fatal("store did not copy data — mutation leaked through")
	}
}
