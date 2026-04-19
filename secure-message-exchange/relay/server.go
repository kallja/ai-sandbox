package relay

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/kallja/ai-sandbox/secure-message-exchange/crypto"
	"github.com/kallja/ai-sandbox/secure-message-exchange/envelope"
	"github.com/kallja/ai-sandbox/secure-message-exchange/wire"
)

// Server is the E2EE relay HTTP server.
type Server struct {
	store       Store
	replay      *ReplayCache
	registry    ClientRegistry
	serverPriv  *ecdh.PrivateKey
	serverFP    [32]byte // Server's Ed25519 fingerprint (for poll detection)
	powDiff     int
	mux         *http.ServeMux
}

// ServerConfig holds configuration for the relay server.
type ServerConfig struct {
	Store          Store
	ServerPriv     *ecdh.PrivateKey
	ServerIdentity ed25519.PublicKey // For fingerprint derivation
	Registry       ClientRegistry
	PoWDifficulty  int
	ReplayTTL      time.Duration
}

// NewServer creates a relay server with the given configuration.
func NewServer(cfg ServerConfig) *Server {
	if cfg.PoWDifficulty == 0 {
		cfg.PoWDifficulty = wire.DefaultPoWDifficulty
	}
	if cfg.ReplayTTL == 0 {
		cfg.ReplayTTL = 5 * time.Minute
	}

	s := &Server{
		store:      cfg.Store,
		replay:     NewReplayCache(cfg.ReplayTTL),
		registry:   cfg.Registry,
		serverPriv: cfg.ServerPriv,
		serverFP:   crypto.Fingerprint(cfg.ServerIdentity),
		powDiff:    cfg.PoWDifficulty,
	}

	s.mux = http.NewServeMux()
	s.mux.HandleFunc("POST /", s.handleRequest)

	return s
}

// Handler returns the server's HTTP handler.
func (s *Server) Handler() http.Handler {
	return s.mux
}

func (s *Server) handleRequest(w http.ResponseWriter, r *http.Request) {
	// Step 1: Read exactly 4096 bytes.
	body, err := io.ReadAll(io.LimitReader(r.Body, wire.OuterEnvelopeSize+1))
	if err != nil || len(body) != wire.OuterEnvelopeSize {
		// Silently drop — no response.
		hj, ok := w.(http.Hijacker)
		if ok {
			conn, _, _ := hj.Hijack()
			if conn != nil {
				conn.Close()
			}
		}
		return
	}

	// Step 2: PoW check.
	powNonce := r.Header.Get("X-PoW-Nonce")
	if !crypto.VerifyPoW(powNonce, body, s.powDiff) {
		// Drop connection without HTTP response.
		hj, ok := w.(http.Hijacker)
		if ok {
			conn, _, _ := hj.Hijack()
			if conn != nil {
				conn.Close()
			}
		}
		return
	}

	// Step 3: Decrypt outer envelope.
	var envelope4096 [wire.OuterEnvelopeSize]byte
	copy(envelope4096[:], body)

	routingBytes, innerBytes, ephPub, err := envelope.OpenOuterEnvelope(envelope4096, s.serverPriv)
	if err != nil {
		slog.Warn("decrypt failed", "error", err)
		s.sendResponse(w, wire.StatusErrAuthFail, nil, ephPub)
		return
	}

	// Step 4: Parse routing header and verify signature.
	rh := envelope.ParseRoutingHeader(routingBytes)

	senderPub, ok := s.registry.LookupByFingerprint(rh.SenderFingerprint)
	if !ok {
		slog.Warn("unknown sender", "fingerprint", hex.EncodeToString(rh.SenderFingerprint[:]))
		s.sendResponse(w, wire.StatusErrAuthFail, nil, ephPub)
		return
	}

	if !rh.Verify(senderPub, innerBytes[:]) {
		slog.Warn("signature verification failed")
		s.sendResponse(w, wire.StatusErrAuthFail, nil, ephPub)
		return
	}

	// Step 5: Replay protection.
	if s.replay.Check(rh.MessageID) {
		s.sendResponse(w, wire.StatusQueueEmpty, nil, ephPub)
		return
	}
	s.replay.Add(rh.MessageID)

	// Step 6: Route.
	if rh.RecipientFingerprint == s.serverFP {
		// This is a poll request.
		data, err := s.store.Pop(r.Context(), hex.EncodeToString(rh.SenderFingerprint[:]))
		if err != nil {
			slog.Error("store pop", "error", err)
			s.sendResponse(w, wire.StatusQueueEmpty, nil, ephPub)
			return
		}
		if data == nil {
			s.sendResponse(w, wire.StatusQueueEmpty, nil, ephPub)
			return
		}
		s.sendResponse(w, wire.StatusDataFollows, data, ephPub)
	} else {
		// This is a send request — store inner envelope for recipient.
		recipientFP := hex.EncodeToString(rh.RecipientFingerprint[:])
		if err := s.store.Push(r.Context(), recipientFP, innerBytes[:]); err != nil {
			slog.Error("store push", "error", err)
		}
		s.sendResponse(w, wire.StatusQueueEmpty, nil, ephPub)
	}
}

func (s *Server) sendResponse(w http.ResponseWriter, status byte, payload []byte, clientEphPub [wire.EphKeySize]byte) {
	resp, err := envelope.SealResponse(status, payload, s.serverPriv, clientEphPub)
	if err != nil {
		slog.Error("seal response", "error", err)
		// Even on error, try to send 4096 bytes of noise.
		w.WriteHeader(http.StatusOK)
		noise := make([]byte, wire.ResponseSize)
		io.ReadFull(io.LimitReader(nil, 0), noise) // won't read, but let's just write zeros
		w.Write(make([]byte, wire.ResponseSize))
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	w.Write(resp[:])
}

// LoggingMiddleware logs method, status, and duration for each request.
func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &responseWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rw, r)
		slog.Info("request",
			"method", r.Method,
			"status", rw.status,
			"duration", time.Since(start),
		)
	})
}

type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

// Unwrap allows http.Hijacker to work through the wrapper.
func (rw *responseWriter) Unwrap() http.ResponseWriter {
	return rw.ResponseWriter
}
