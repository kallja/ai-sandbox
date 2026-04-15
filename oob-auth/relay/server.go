package relay

import (
	"context"
	"io"
	"net/http"
	"time"

	"github.com/kallja/ai-sandbox/oob-auth/protocol"
)

const longPollTimeout = 30 * time.Second

// Server is the relay HTTP server. It holds a reference to the
// message store and exposes the publish/subscribe endpoints.
type Server struct {
	store Store
	mux   *http.ServeMux
}

// NewServer creates a relay server backed by the given store.
func NewServer(store Store) *Server {
	s := &Server{store: store}
	s.mux = http.NewServeMux()
	s.mux.HandleFunc("POST /api/v1/queue/{queue_id}", s.handlePublish)
	s.mux.HandleFunc("GET /api/v1/queue/{queue_id}", s.handleSubscribe)
	return s
}

// Handler returns the server's HTTP handler, ready to be wrapped
// with middleware or passed to http.Server.
func (s *Server) Handler() http.Handler {
	return s.mux
}

// handlePublish writes an E2EE envelope to the store.
func (s *Server) handlePublish(w http.ResponseWriter, r *http.Request) {
	queueID := r.PathValue("queue_id")
	if queueID == "" {
		http.Error(w, "missing queue_id", http.StatusBadRequest)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, int64(protocol.MaxPayloadSize)+1))
	if err != nil {
		http.Error(w, "read error", http.StatusInternalServerError)
		return
	}
	if len(body) > protocol.MaxPayloadSize {
		http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
		return
	}
	if len(body) == 0 {
		http.Error(w, "empty payload", http.StatusBadRequest)
		return
	}

	if err := s.store.Publish(r.Context(), queueID, body); err != nil {
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

// handleSubscribe long-polls the store for a message.
func (s *Server) handleSubscribe(w http.ResponseWriter, r *http.Request) {
	queueID := r.PathValue("queue_id")
	if queueID == "" {
		http.Error(w, "missing queue_id", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), longPollTimeout)
	defer cancel()

	data, err := s.store.Subscribe(ctx, queueID)
	if err != nil {
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	if data == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}
