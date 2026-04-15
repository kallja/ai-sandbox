package relay

import (
	"context"
	"fmt"
	"time"

	"cloud.google.com/go/firestore"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const firestoreCollection = "oob_auth_queue"

// FirestoreStore implements Store backed by Google Cloud Firestore.
// It uses snapshot listeners for long-poll and transactions for
// atomic pop-and-drop.
type FirestoreStore struct {
	client *firestore.Client
}

// NewFirestoreStore creates a Firestore-backed store.
// The caller is responsible for closing the client when done.
func NewFirestoreStore(client *firestore.Client) *FirestoreStore {
	return &FirestoreStore{client: client}
}

// Publish writes an envelope to Firestore with a created_at timestamp
// for TTL-based automatic purging.
func (fs *FirestoreStore) Publish(ctx context.Context, queueID string, data []byte) error {
	doc := fs.client.Collection(firestoreCollection).Doc(queueID)
	_, err := doc.Set(ctx, map[string]interface{}{
		"payload":    data,
		"created_at": time.Now(),
	})
	if err != nil {
		return fmt.Errorf("firestore set: %w", err)
	}
	return nil
}

// Subscribe uses a Firestore snapshot listener to wait for a document
// to appear, then atomically reads and deletes it in a transaction.
func (fs *FirestoreStore) Subscribe(ctx context.Context, queueID string) ([]byte, error) {
	doc := fs.client.Collection(firestoreCollection).Doc(queueID)

	// Try an immediate transactional pop first.
	if data, err := fs.atomicPop(ctx, doc); err != nil {
		return nil, err
	} else if data != nil {
		return data, nil
	}

	// No document yet — attach a snapshot listener and wait.
	snapIter := doc.Snapshots(ctx)
	defer snapIter.Stop()

	for {
		snap, err := snapIter.Next()
		if err != nil {
			if ctx.Err() != nil {
				return nil, nil // timeout or cancellation
			}
			return nil, fmt.Errorf("snapshot listener: %w", err)
		}
		if !snap.Exists() {
			continue
		}

		// Document appeared — pop it transactionally.
		data, err := fs.atomicPop(ctx, doc)
		if err != nil {
			return nil, err
		}
		if data != nil {
			return data, nil
		}
		// Another subscriber grabbed it — keep listening.
	}
}

// atomicPop reads and deletes a document in a single Firestore transaction.
// Returns nil, nil if the document does not exist.
func (fs *FirestoreStore) atomicPop(ctx context.Context, doc *firestore.DocumentRef) ([]byte, error) {
	var result []byte

	err := fs.client.RunTransaction(ctx, func(ctx context.Context, tx *firestore.Transaction) error {
		snap, err := tx.Get(doc)
		if err != nil {
			if status.Code(err) == codes.NotFound {
				result = nil
				return nil
			}
			return fmt.Errorf("transaction get: %w", err)
		}

		payload, err := snap.DataAt("payload")
		if err != nil {
			return fmt.Errorf("read payload field: %w", err)
		}

		data, ok := payload.([]byte)
		if !ok {
			return fmt.Errorf("payload is %T, want []byte", payload)
		}

		result = data
		return tx.Delete(doc)
	})

	if err != nil {
		return nil, fmt.Errorf("firestore transaction: %w", err)
	}
	return result, nil
}
