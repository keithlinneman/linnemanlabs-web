package httpmw

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

type stubContentInfo struct {
	version string
	hash    string
}

func (s *stubContentInfo) ContentVersion() string { return s.version }
func (s *stubContentInfo) ContentHash() string    { return s.hash }

func TestContentHeaders_BothSet(t *testing.T) {
	info := &stubContentInfo{
		version: "v1.2.3",
		hash:    "abcdef1234567890abcdef",
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mw := ContentHeaders(info)
	rec := httptest.NewRecorder()
	mw(handler).ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))

	if got := rec.Header().Get("X-Content-Bundle-Version"); got != "v1.2.3" {
		t.Fatalf("X-Content-Bundle-Version = %q, want %q", got, "v1.2.3")
	}
	// Hash should be truncated to 12 chars
	if got := rec.Header().Get("X-Content-Hash"); got != "abcdef123456" {
		t.Fatalf("X-Content-Hash = %q, want %q", got, "abcdef123456")
	}
}

func TestContentHeaders_ShortHash(t *testing.T) {
	info := &stubContentInfo{
		version: "v1.0.0",
		hash:    "abc123",
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	mw := ContentHeaders(info)
	rec := httptest.NewRecorder()
	mw(handler).ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))

	// Hash <= 12 chars should not be truncated
	if got := rec.Header().Get("X-Content-Hash"); got != "abc123" {
		t.Fatalf("X-Content-Hash = %q, want %q", got, "abc123")
	}
}

func TestContentHeaders_ExactlyTwelveCharHash(t *testing.T) {
	info := &stubContentInfo{
		version: "v1.0.0",
		hash:    "abcdef123456",
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	mw := ContentHeaders(info)
	rec := httptest.NewRecorder()
	mw(handler).ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))

	if got := rec.Header().Get("X-Content-Hash"); got != "abcdef123456" {
		t.Fatalf("X-Content-Hash = %q, want %q", got, "abcdef123456")
	}
}

func TestContentHeaders_EmptyVersion(t *testing.T) {
	info := &stubContentInfo{
		version: "",
		hash:    "abcdef1234567890",
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	mw := ContentHeaders(info)
	rec := httptest.NewRecorder()
	mw(handler).ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))

	if got := rec.Header().Get("X-Content-Bundle-Version"); got != "" {
		t.Fatalf("expected no version header, got %q", got)
	}
	if got := rec.Header().Get("X-Content-Hash"); got == "" {
		t.Fatal("expected hash header to be set")
	}
}

func TestContentHeaders_EmptyHash(t *testing.T) {
	info := &stubContentInfo{
		version: "v2.0.0",
		hash:    "",
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	mw := ContentHeaders(info)
	rec := httptest.NewRecorder()
	mw(handler).ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))

	if got := rec.Header().Get("X-Content-Bundle-Version"); got != "v2.0.0" {
		t.Fatalf("version = %q, want %q", got, "v2.0.0")
	}
	if got := rec.Header().Get("X-Content-Hash"); got != "" {
		t.Fatalf("expected no hash header, got %q", got)
	}
}

func TestContentHeaders_NilInfo(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mw := ContentHeaders(nil)
	rec := httptest.NewRecorder()
	mw(handler).ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))

	if got := rec.Header().Get("X-Content-Bundle-Version"); got != "" {
		t.Fatalf("expected no version header with nil info, got %q", got)
	}
	if got := rec.Header().Get("X-Content-Hash"); got != "" {
		t.Fatalf("expected no hash header with nil info, got %q", got)
	}
}

func TestContentHeaders_SetsSpanAttributes(t *testing.T) {
	info := &stubContentInfo{
		version: "v1.2.3",
		hash:    "abcdef1234567890abcdef",
	}

	ctx, sr := newRecordingSpan(t, "content-headers-test")

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// End the span inside the handler so attributes are captured
		trace.SpanFromContext(r.Context()).End()
	})

	mw := ContentHeaders(info)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil).WithContext(ctx)
	mw(handler).ServeHTTP(rec, req)

	spans := sr.Ended()
	if len(spans) == 0 {
		t.Fatal("no spans recorded")
	}

	attrs := make(map[attribute.Key]string)
	for _, attr := range spans[0].Attributes() {
		attrs[attr.Key] = attr.Value.AsString()
	}

	if v, ok := attrs["content.version"]; !ok || v != "v1.2.3" {
		t.Fatalf("content.version = %q, want %q", v, "v1.2.3")
	}
	// Span attribute uses full hash (not truncated)
	if h, ok := attrs["content.hash"]; !ok || h != "abcdef1234567890abcdef" {
		t.Fatalf("content.hash = %q, want %q", h, "abcdef1234567890abcdef")
	}
}

func TestContentHeaders_NoSpan_NoPanic(t *testing.T) {
	info := &stubContentInfo{
		version: "v1.0.0",
		hash:    "abc123",
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mw := ContentHeaders(info)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil) // no span in context
	mw(handler).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestContentHeaders_HandlerCalled(t *testing.T) {
	called := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	mw := ContentHeaders(&stubContentInfo{version: "v1", hash: "abc"})
	mw(handler).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))

	if !called {
		t.Fatal("next handler not called")
	}
}
