// Package relay implements the E2EE Relay Protocol server.
package relay

import "context"

// Store abstracts the message persistence layer. The relay server
// writes inner envelopes via Push and reads them via Pop.
// Implementations must be safe for concurrent use.
type Store interface {
	// Push stores an inner envelope under the recipient's fingerprint.
	// Messages are ordered FIFO by insertion time.
	Push(ctx context.Context, recipientFingerprint string, data []byte) error

	// Pop atomically reads and deletes the oldest message for the given
	// recipient fingerprint. Returns nil, nil if no messages exist.
	Pop(ctx context.Context, recipientFingerprint string) ([]byte, error)
}
