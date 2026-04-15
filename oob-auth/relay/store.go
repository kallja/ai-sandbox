// Package relay implements the stateless HTTP relay backend for the OOB-Auth
// system. It routes encrypted envelopes between Client A and Client B without
// ever seeing plaintext.
package relay

import "context"

// Store abstracts the message persistence layer. The relay server
// writes envelopes via Publish and reads them via Subscribe.
// Implementations must be safe for concurrent use.
type Store interface {
	// Publish stores an envelope under the given queue ID.
	// If a message already exists for this queue, it is overwritten.
	Publish(ctx context.Context, queueID string, data []byte) error

	// Subscribe blocks until a message appears for the given queue ID
	// or the context is cancelled. On success it atomically returns the
	// message and deletes it from the store (pop-and-drop).
	// Returns nil, nil when the context deadline/cancellation fires
	// before a message arrives.
	Subscribe(ctx context.Context, queueID string) ([]byte, error)
}
