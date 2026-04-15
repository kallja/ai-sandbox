package relay

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func TestCloudflareMiddleware_ValidHeaders(t *testing.T) {
	handler := CloudflareMiddleware("my-id", "my-secret", okHandler())
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("CF-Access-Client-Id", "my-id")
	req.Header.Set("CF-Access-Client-Secret", "my-secret")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestCloudflareMiddleware_MissingHeaders(t *testing.T) {
	handler := CloudflareMiddleware("my-id", "my-secret", okHandler())
	req := httptest.NewRequest("GET", "/", nil)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestCloudflareMiddleware_WrongID(t *testing.T) {
	handler := CloudflareMiddleware("my-id", "my-secret", okHandler())
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("CF-Access-Client-Id", "wrong-id")
	req.Header.Set("CF-Access-Client-Secret", "my-secret")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestCloudflareMiddleware_WrongSecret(t *testing.T) {
	handler := CloudflareMiddleware("my-id", "my-secret", okHandler())
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("CF-Access-Client-Id", "my-id")
	req.Header.Set("CF-Access-Client-Secret", "wrong-secret")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestCloudflareMiddleware_EmptyCredentials(t *testing.T) {
	handler := CloudflareMiddleware("", "", okHandler())
	req := httptest.NewRequest("GET", "/", nil)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Empty configured credentials should still match empty headers.
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestLoggingMiddleware_SetsStatus(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})
	handler := LoggingMiddleware(inner)

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusTeapot {
		t.Errorf("status = %d, want %d", w.Code, http.StatusTeapot)
	}
}

func TestStatusRecorder_DefaultStatus(t *testing.T) {
	w := httptest.NewRecorder()
	sr := &statusRecorder{ResponseWriter: w, status: http.StatusOK}

	// Write body without explicit WriteHeader — status should stay 200.
	sr.Write([]byte("hello"))
	if sr.status != http.StatusOK {
		t.Errorf("default status = %d, want %d", sr.status, http.StatusOK)
	}
}
