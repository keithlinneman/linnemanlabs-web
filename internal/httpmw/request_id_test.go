package httpmw

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Context helpers

func TestWithRequestID_Basic(t *testing.T) {
	ctx := WithRequestID(context.Background(), "test-id-123")
	got := RequestIDFromContext(ctx)
	if got != "test-id-123" {
		t.Fatalf("RequestIDFromContext = %q, want %q", got, "test-id-123")
	}
}

func TestWithRequestID_Empty(t *testing.T) {
	ctx := WithRequestID(context.Background(), "")
	got := RequestIDFromContext(ctx)
	if got != "" {
		t.Fatalf("expected empty request ID for empty input, got %q", got)
	}
}

func TestRequestIDFromContext_NoValue(t *testing.T) {
	got := RequestIDFromContext(context.Background())
	if got != "" {
		t.Fatalf("expected empty string from bare context, got %q", got)
	}
}

// Middleware

func TestRequestID_GeneratesWhenMissing(t *testing.T) {
	var ctxID string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctxID = RequestIDFromContext(r.Context())
	})

	mw := RequestID("X-Request-Id")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", http.NoBody)

	mw(handler).ServeHTTP(rec, req)

	// Should generate a 32-char hex ID (16 bytes)
	if len(ctxID) != 32 {
		t.Fatalf("generated ID length = %d, want 32, value = %q", len(ctxID), ctxID)
	}

	// Response header should match context
	if got := rec.Header().Get("X-Request-Id"); got != ctxID {
		t.Fatalf("response header = %q, context = %q", got, ctxID)
	}
}

func TestRequestID_PropagatesExisting(t *testing.T) {
	var ctxID string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctxID = RequestIDFromContext(r.Context())
	})

	mw := RequestID("X-Request-Id")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", http.NoBody)
	req.Header.Set("X-Request-Id", "upstream-id-abc")

	mw(handler).ServeHTTP(rec, req)

	if ctxID != "upstream-id-abc" {
		t.Fatalf("context ID = %q, want %q", ctxID, "upstream-id-abc")
	}
	if got := rec.Header().Get("X-Request-Id"); got != "upstream-id-abc" {
		t.Fatalf("response header = %q, want %q", got, "upstream-id-abc")
	}
}

func TestRequestID_CustomHeaderName(t *testing.T) {
	var ctxID string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctxID = RequestIDFromContext(r.Context())
	})

	mw := RequestID("X-Correlation-Id")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", http.NoBody)
	req.Header.Set("X-Correlation-Id", "corr-999")

	mw(handler).ServeHTTP(rec, req)

	if ctxID != "corr-999" {
		t.Fatalf("context ID = %q, want %q", ctxID, "corr-999")
	}
	if got := rec.Header().Get("X-Correlation-Id"); got != "corr-999" {
		t.Fatalf("response header = %q, want %q", got, "corr-999")
	}
}

func TestRequestID_DefaultHeaderName(t *testing.T) {
	var ctxID string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctxID = RequestIDFromContext(r.Context())
	})

	// Empty string should default to X-Request-Id
	mw := RequestID("")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", http.NoBody)
	req.Header.Set("X-Request-Id", "default-header-test")

	mw(handler).ServeHTTP(rec, req)

	if ctxID != "default-header-test" {
		t.Fatalf("context ID = %q, want %q", ctxID, "default-header-test")
	}
}

func TestRequestID_UniquePerRequest(t *testing.T) {
	ids := make(map[string]bool)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	mw := RequestID("X-Request-Id")

	for i := 0; i < 100; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/", http.NoBody)
		mw(handler).ServeHTTP(rec, req)

		id := rec.Header().Get("X-Request-Id")
		if ids[id] {
			t.Fatalf("duplicate request ID generated: %q on iteration %d", id, i)
		}
		ids[id] = true
	}
}
