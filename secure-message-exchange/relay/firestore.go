package relay

import (
	"context"
	"fmt"
	"time"

	"cloud.google.com/go/firestore"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const firestoreCollection = "e2ee_relay_queue"

// FirestoreStore implements Store backed by Google Cloud Firestore.
// It uses transactions for atomic pop-and-drop with FIFO ordering.
type FirestoreStore struct {
	client *firestore.Client
}

// NewFirestoreStore creates a Firestore-backed store.
// The caller is responsible for closing the client when done.
func NewFirestoreStore(client *firestore.Client) *FirestoreStore {
	return &FirestoreStore{client: client}
}

func (fs *FirestoreStore) Push(ctx context.Context, recipientFP string, data []byte) error {
	_, _, err := fs.client.Collection(firestoreCollection).Add(ctx, map[string]interface{}{
		"recipient":  recipientFP,
		"payload":    data,
		"created_at": time.Now(),
	})
	if err != nil {
		return fmt.Errorf("firestore push: %w", err)
	}
	return nil
}

func (fs *FirestoreStore) Pop(ctx context.Context, recipientFP string) ([]byte, error) {
	var result []byte

	err := fs.client.RunTransaction(ctx, func(ctx context.Context, tx *firestore.Transaction) error {
		q := fs.client.Collection(firestoreCollection).
			Where("recipient", "==", recipientFP).
			OrderBy("created_at", firestore.Asc).
			Limit(1)

		docs, err := tx.Documents(q).GetAll()
		if err != nil {
			return fmt.Errorf("query: %w", err)
		}
		if len(docs) == 0 {
			result = nil
			return nil
		}

		doc := docs[0]
		payload, err := doc.DataAt("payload")
		if err != nil {
			if status.Code(err) == codes.NotFound {
				result = nil
				return nil
			}
			return fmt.Errorf("read payload: %w", err)
		}

		data, ok := payload.([]byte)
		if !ok {
			return fmt.Errorf("payload is %T, want []byte", payload)
		}

		result = data
		return tx.Delete(doc.Ref)
	})

	if err != nil {
		return nil, fmt.Errorf("firestore pop: %w", err)
	}
	return result, nil
}
