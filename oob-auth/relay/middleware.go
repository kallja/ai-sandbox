package relay

import (
	"log/slog"
	"net/http"
	"time"
)

// CloudflareMiddleware rejects requests that lack valid Cloudflare
// Access service-token headers. This prevents direct access to the
// Cloud Run URL, ensuring all traffic passes through Cloudflare.
func CloudflareMiddleware(clientID, clientSecret string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotID := r.Header.Get("CF-Access-Client-Id")
		gotSecret := r.Header.Get("CF-Access-Client-Secret")

		if gotID != clientID || gotSecret != clientSecret {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// LoggingMiddleware logs request metadata while explicitly omitting
// sensitive fields (IPs, queue IDs, payload sizes) per the spec's
// logging blackout requirement.
func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		wrapped := &statusRecorder{ResponseWriter: w, status: http.StatusOK}

		next.ServeHTTP(wrapped, r)

		slog.Info("request",
			"method", r.Method,
			"status", wrapped.status,
			"duration_ms", time.Since(start).Milliseconds(),
		)
	})
}

// statusRecorder captures the HTTP status code written by downstream handlers.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (sr *statusRecorder) WriteHeader(code int) {
	sr.status = code
	sr.ResponseWriter.WriteHeader(code)
}
