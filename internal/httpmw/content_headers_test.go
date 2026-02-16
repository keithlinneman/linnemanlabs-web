package httpmw

import (
	"net/http"
	"net/http/httptest"
	"testing"
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
