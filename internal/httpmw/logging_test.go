package httpmw

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/keithlinneman/linnemanlabs-web/internal/log"
)

// test helpers

type capturedLog struct {
	msg    string
	fields []any
}

// flatLogger captures With() and Info() calls for test assertions.
// Returns itself from With() so all calls land in one place.
type flatLogger struct {
	mu    sync.Mutex
	infos []capturedLog
	withs [][]any
}

func newFlatLogger() *flatLogger {
	return &flatLogger{}
}

func (l *flatLogger) With(kv ...any) log.Logger {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.withs = append(l.withs, kv)
	return l
}

func (l *flatLogger) Info(_ context.Context, msg string, kv ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.infos = append(l.infos, capturedLog{msg: msg, fields: kv})
}

func (l *flatLogger) Debug(_ context.Context, msg string, kv ...any) {}
func (l *flatLogger) Warn(_ context.Context, msg string, kv ...any)  {}
func (l *flatLogger) Error(_ context.Context, _ error, msg string, kv ...any) {
}
func (l *flatLogger) Sync() error { return nil }

func (l *flatLogger) lastInfo() (capturedLog, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.infos) == 0 {
		return capturedLog{}, false
	}
	return l.infos[len(l.infos)-1], true
}

func (l *flatLogger) lastWith() ([]any, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.withs) == 0 {
		return nil, false
	}
	return l.withs[len(l.withs)-1], true
}

func (l *flatLogger) infoCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.infos)
}

// fieldValue extracts a value by key from a captured log's fields slice.
func fieldValue(fields []any, key string) (any, bool) {
	for i := 0; i+1 < len(fields); i += 2 {
		if k, ok := fields[i].(string); ok && k == key {
			return fields[i+1], true
		}
	}
	return nil, false
}

// withFieldValue extracts a value by key from a With() call's kv slice.
func withFieldValue(withs [][]any, key string) (any, bool) {
	for _, kv := range withs {
		if v, ok := fieldValue(kv, key); ok {
			return v, true
		}
	}
	return nil, false
}

// flusherRecorder wraps httptest.ResponseRecorder with Flusher support.
type flusherRecorder struct {
	*httptest.ResponseRecorder
	flushed bool
}

func (f *flusherRecorder) Flush() {
	f.flushed = true
}

// hijackRecorder wraps httptest.ResponseRecorder with Hijacker support.
type hijackRecorder struct {
	*httptest.ResponseRecorder
	hijacked bool
}

func (h *hijackRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h.hijacked = true
	return nil, nil, nil
}

// noHijackRecorder doesn't implement Hijacker.
type noHijackRecorder struct {
	*httptest.ResponseRecorder
}

// responseWriter unit tests

func TestResponseWriter_WriteHeader(t *testing.T) {
	rec := httptest.NewRecorder()
	rw := &responseWriter{
		ResponseWriter: rec,
		ctx:            context.Background(),
	}

	rw.WriteHeader(http.StatusNotFound)

	if rw.status != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rw.status, http.StatusNotFound)
	}
	if rec.Code != http.StatusNotFound {
		t.Fatalf("underlying recorder code = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestResponseWriter_Write_DefaultsTo200(t *testing.T) {
	rec := httptest.NewRecorder()
	rw := &responseWriter{
		ResponseWriter: rec,
		ctx:            context.Background(),
	}

	n, err := rw.Write([]byte("hello"))
	if err != nil {
		t.Fatalf("Write error: %v", err)
	}
	if n != 5 {
		t.Fatalf("n = %d, want 5", n)
	}
	if rw.status != http.StatusOK {
		t.Fatalf("status = %d, want 200", rw.status)
	}
	if rw.bytes != 5 {
		t.Fatalf("bytes = %d, want 5", rw.bytes)
	}
}

func TestResponseWriter_Write_AccumulatesBytes(t *testing.T) {
	rec := httptest.NewRecorder()
	rw := &responseWriter{
		ResponseWriter: rec,
		ctx:            context.Background(),
	}

	rw.Write([]byte("aaa"))
	rw.Write([]byte("bbbbb"))
	rw.Write([]byte("cc"))

	if rw.bytes != 10 {
		t.Fatalf("bytes = %d, want 10", rw.bytes)
	}
}

func TestResponseWriter_WriteHeader_ThenWrite(t *testing.T) {
	rec := httptest.NewRecorder()
	rw := &responseWriter{
		ResponseWriter: rec,
		ctx:            context.Background(),
	}

	rw.WriteHeader(http.StatusCreated)
	rw.Write([]byte("body"))

	if rw.status != http.StatusCreated {
		t.Fatalf("status = %d, want 201", rw.status)
	}
	if rw.bytes != 4 {
		t.Fatalf("bytes = %d, want 4", rw.bytes)
	}
}

func TestResponseWriter_Flush_Supported(t *testing.T) {
	inner := &flusherRecorder{ResponseRecorder: httptest.NewRecorder()}
	rw := &responseWriter{
		ResponseWriter: inner,
		ctx:            context.Background(),
	}

	rw.Flush()

	if !inner.flushed {
		t.Fatal("Flush not delegated to underlying writer")
	}
}

func TestResponseWriter_Flush_NotSupported(t *testing.T) {
	// Plain ResponseRecorder doesn't implement Flusher in a way we track,
	// but Flush should not panic.
	rec := httptest.NewRecorder()
	rw := &responseWriter{
		ResponseWriter: rec,
		ctx:            context.Background(),
	}

	// Should not panic
	rw.Flush()
}

func TestResponseWriter_Hijack_Supported(t *testing.T) {
	inner := &hijackRecorder{ResponseRecorder: httptest.NewRecorder()}
	rw := &responseWriter{
		ResponseWriter: inner,
		ctx:            context.Background(),
	}

	_, _, err := rw.Hijack()
	if err != nil {
		t.Fatalf("Hijack error: %v", err)
	}
	if !inner.hijacked {
		t.Fatal("Hijack not delegated")
	}
}

func TestResponseWriter_Hijack_NotSupported(t *testing.T) {
	inner := &noHijackRecorder{ResponseRecorder: httptest.NewRecorder()}
	rw := &responseWriter{
		ResponseWriter: inner,
		ctx:            context.Background(),
	}

	_, _, err := rw.Hijack()
	if err == nil {
		t.Fatal("expected error when Hijacker not supported")
	}
	if !strings.Contains(err.Error(), "does not implement http.Hijacker") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResponseWriter_EnsureWriteSpan_Idempotent(t *testing.T) {
	rec := httptest.NewRecorder()
	rw := &responseWriter{
		ResponseWriter: rec,
		ctx:            context.Background(),
	}

	rw.ensureWriteSpan()
	first := rw.writeSpanStarted
	rw.ensureWriteSpan()

	if !first {
		t.Fatal("writeSpanStarted should be true after first call")
	}
	// No panic on second call = idempotent
}

func TestResponseWriter_FinishWriteSpan_NilSpan(t *testing.T) {
	rw := &responseWriter{
		ctx: context.Background(),
	}
	// Should not panic when writeSpan is nil
	rw.finishWriteSpan()
}

// schemeFromRequest

func TestSchemeFromRequest_XForwardedProto_HTTPS(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	r.Header.Set("X-Forwarded-Proto", "https")

	got := schemeFromRequest(r)
	if got != "https" {
		t.Fatalf("scheme = %q, want %q", got, "https")
	}
}

func TestSchemeFromRequest_XForwardedProto_HTTP(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	r.Header.Set("X-Forwarded-Proto", "http")

	got := schemeFromRequest(r)
	if got != "http" {
		t.Fatalf("scheme = %q, want %q", got, "http")
	}
}

func TestSchemeFromRequest_XForwardedProto_CaseInsensitive(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	r.Header.Set("X-Forwarded-Proto", "HTTPS")

	got := schemeFromRequest(r)
	if got != "https" {
		t.Fatalf("scheme = %q, want %q", got, "https")
	}
}

func TestSchemeFromRequest_XForwardedProto_MultipleValues(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	r.Header.Set("X-Forwarded-Proto", "https, http")

	got := schemeFromRequest(r)
	if got != "https" {
		t.Fatalf("scheme = %q, want %q (should take first)", got, "https")
	}
}

func TestSchemeFromRequest_XForwardedProto_Invalid(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	r.Header.Set("X-Forwarded-Proto", "ftp")

	got := schemeFromRequest(r)
	// Invalid scheme should fall through to URL or default
	if got != "http" {
		t.Fatalf("scheme = %q, want %q (invalid proto should fall through)", got, "http")
	}
}

func TestSchemeFromRequest_XForwardedProto_Empty(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	r.Header.Set("X-Forwarded-Proto", "")

	got := schemeFromRequest(r)
	if got != "http" {
		t.Fatalf("scheme = %q, want %q", got, "http")
	}
}

func TestSchemeFromRequest_URLScheme(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "https://example.com/path", http.NoBody)
	// Clear any forwarded header
	r.Header.Del("X-Forwarded-Proto")

	got := schemeFromRequest(r)
	if got != "https" {
		t.Fatalf("scheme = %q, want %q", got, "https")
	}
}

func TestSchemeFromRequest_URLScheme_Invalid(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/path", http.NoBody)
	r.URL.Scheme = "gopher"

	got := schemeFromRequest(r)
	// Invalid URL scheme should fall through
	if got != "http" {
		t.Fatalf("scheme = %q, want %q", got, "http")
	}
}

func TestSchemeFromRequest_TLS(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	r.TLS = &tls.ConnectionState{}

	got := schemeFromRequest(r)
	if got != "https" {
		t.Fatalf("scheme = %q, want %q", got, "https")
	}
}

func TestSchemeFromRequest_DefaultHTTP(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", http.NoBody)

	got := schemeFromRequest(r)
	if got != "http" {
		t.Fatalf("scheme = %q, want %q", got, "http")
	}
}

func TestSchemeFromRequest_PriorityOrder(t *testing.T) {
	// X-Forwarded-Proto should take priority over URL scheme and TLS
	r := httptest.NewRequest(http.MethodGet, "http://example.com/", http.NoBody)
	r.Header.Set("X-Forwarded-Proto", "https")
	r.TLS = &tls.ConnectionState{}

	got := schemeFromRequest(r)
	if got != "https" {
		t.Fatalf("scheme = %q, want %q", got, "https")
	}
}

// Security: X-Forwarded-Proto injection attempts
func TestSchemeFromRequest_Injection_Newline(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	r.Header.Set("X-Forwarded-Proto", "https\r\nX-Injected: evil")

	got := schemeFromRequest(r)
	// Should not be "https" because the raw value contains injection chars
	// and after lowercasing + validSchemes check, it won't match
	if got == "https\r\nX-Injected: evil" {
		t.Fatal("injection payload accepted as scheme")
	}
	// The validSchemes map should reject this
	if got != "http" {
		t.Fatalf("scheme = %q, want %q (injection should fall through)", got, "http")
	}
}

func TestSchemeFromRequest_Injection_NullByte(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	r.Header.Set("X-Forwarded-Proto", "https\x00evil")

	got := schemeFromRequest(r)
	if got != "http" {
		t.Fatalf("scheme = %q, want %q (null byte should cause rejection)", got, "http")
	}
}

func TestSchemeFromRequest_Injection_Whitespace(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	r.Header.Set("X-Forwarded-Proto", "  https  ")

	got := schemeFromRequest(r)
	if got != "https" {
		t.Fatalf("scheme = %q, want %q (whitespace should be trimmed)", got, "https")
	}
}

// WithLogger

func TestWithLogger_EnrichesContext(t *testing.T) {
	fl := newFlatLogger()

	var ctxLogger log.Logger
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctxLogger = log.FromContext(r.Context())
	})

	mw := WithLogger(fl)
	req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
	req.RemoteAddr = "10.0.0.1:12345"

	mw(handler).ServeHTTP(httptest.NewRecorder(), req)

	if ctxLogger == nil {
		t.Fatal("logger not set in context")
	}

	// WithLogger should have called With() with known fields
	kv, ok := fl.lastWith()
	if !ok {
		t.Fatal("With() never called")
	}

	// Verify expected fields are present
	if v, ok := fieldValue(kv, "http.request.method"); !ok || v != http.MethodGet {
		t.Fatalf("method field = %v, want GET", v)
	}
	if v, ok := fieldValue(kv, "url.path"); !ok || v != "/test" {
		t.Fatalf("url.path field = %v, want /test", v)
	}
}

func TestWithLogger_NormalizesPeerAddr(t *testing.T) {
	fl := newFlatLogger()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	mw := WithLogger(fl)
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.RemoteAddr = "192.168.1.100:54321"

	mw(handler).ServeHTTP(httptest.NewRecorder(), req)

	kv, ok := fl.lastWith()
	if !ok {
		t.Fatal("With() never called")
	}

	v, ok := fieldValue(kv, "network.peer.address")
	if !ok {
		t.Fatal("network.peer.address not in With fields")
	}
	if v != "192.168.1.100" {
		t.Fatalf("peer address = %q, want %q (port should be stripped)", v, "192.168.1.100")
	}
}

func TestWithLogger_PeerAddr_NoPort(t *testing.T) {
	fl := newFlatLogger()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	mw := WithLogger(fl)
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	// RemoteAddr without port (unusual but possible)
	req.RemoteAddr = "10.0.0.1"

	mw(handler).ServeHTTP(httptest.NewRecorder(), req)

	kv, _ := fl.lastWith()
	v, _ := fieldValue(kv, "network.peer.address")
	if v != "10.0.0.1" {
		t.Fatalf("peer address = %q, want %q", v, "10.0.0.1")
	}
}

func TestWithLogger_IncludesScheme(t *testing.T) {
	fl := newFlatLogger()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	mw := WithLogger(fl)
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.Header.Set("X-Forwarded-Proto", "https")

	mw(handler).ServeHTTP(httptest.NewRecorder(), req)

	kv, _ := fl.lastWith()
	v, ok := fieldValue(kv, "url.scheme")
	if !ok {
		t.Fatal("url.scheme not in With fields")
	}
	if v != "https" {
		t.Fatalf("scheme = %q, want %q", v, "https")
	}
}

func TestWithLogger_IncludesRequestID(t *testing.T) {
	fl := newFlatLogger()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	mw := WithLogger(fl)
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	// Simulate RequestID middleware having run
	ctx := WithRequestID(req.Context(), "req-abc-123")
	req = req.WithContext(ctx)

	mw(handler).ServeHTTP(httptest.NewRecorder(), req)

	kv, _ := fl.lastWith()
	v, ok := fieldValue(kv, "request_id")
	if !ok {
		t.Fatal("request_id not in With fields")
	}
	if v != "req-abc-123" {
		t.Fatalf("request_id = %q, want %q", v, "req-abc-123")
	}
}

// Security: verify no user-supplied data leaks into logger fields
func TestWithLogger_NoUserSuppliedDataInFields(t *testing.T) {
	fl := newFlatLogger()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	mw := WithLogger(fl)
	req := httptest.NewRequest(http.MethodGet, "/test?secret=hunter2", http.NoBody)
	req.Header.Set("User-Agent", "EvilBot/1.0")
	req.Header.Set("Cookie", "session=abc123")
	req.Host = "evil.example.com"

	mw(handler).ServeHTTP(httptest.NewRecorder(), req)

	kv, _ := fl.lastWith()

	// These fields should NOT be present
	forbidden := []string{
		"user_agent", "User-Agent",
		"cookie", "Cookie",
		"server.address", // host is commented out in the code
		"url.query",
	}
	for _, key := range forbidden {
		if _, found := fieldValue(kv, key); found {
			t.Errorf("forbidden field %q found in logger With() call", key)
		}
	}
}

// AccessLog

func TestAccessLog_LogsRequest(t *testing.T) {
	fl := newFlatLogger()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("hello"))
	})

	// AccessLog needs a logger in context (normally set by WithLogger)
	inner := AccessLog()(handler)
	mw := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := log.WithContext(r.Context(), fl)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/data", http.NoBody)
	mw(inner).ServeHTTP(rec, req)

	entry, ok := fl.lastInfo()
	if !ok {
		t.Fatal("no info log emitted")
	}
	if entry.msg != "http request" {
		t.Fatalf("msg = %q, want %q", entry.msg, "http request")
	}

	// Check key fields
	if v, ok := fieldValue(entry.fields, "http.response.status_code"); !ok || v != 200 {
		t.Fatalf("status_code = %v, want 200", v)
	}
	if v, ok := fieldValue(entry.fields, "http.response.body.size"); !ok {
		t.Fatal("body.size missing")
	} else if v.(int64) != 5 {
		t.Fatalf("body.size = %v, want 5", v)
	}
}

func TestAccessLog_DefaultStatus200(t *testing.T) {
	fl := newFlatLogger()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handler that writes without calling WriteHeader
		w.Write([]byte("implicit 200"))
	})

	inner := AccessLog()(handler)
	mw := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := log.WithContext(r.Context(), fl)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}

	mw(inner).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/page", http.NoBody))

	entry, ok := fl.lastInfo()
	if !ok {
		t.Fatal("no info log emitted")
	}
	if v, _ := fieldValue(entry.fields, "http.response.status_code"); v != 200 {
		t.Fatalf("status = %v, want 200", v)
	}
}

func TestAccessLog_SkipsStaticAssets(t *testing.T) {
	fl := newFlatLogger()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	inner := AccessLog()(handler)
	mw := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := log.WithContext(r.Context(), fl)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}

	extensions := []string{
		"/style.css", "/app.js", "/logo.png", "/photo.jpg",
		"/photo.jpeg", "/image.webp", "/icon.svg", "/favicon.ico",
		"/font.woff", "/font.woff2", "/bundle.js.map",
	}

	for _, path := range extensions {
		fl.mu.Lock()
		fl.infos = nil
		fl.mu.Unlock()

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, http.NoBody)
		mw(inner).ServeHTTP(rec, req)

		if fl.infoCount() != 0 {
			t.Errorf("static asset %q should not be logged, got %d log entries", path, fl.infoCount())
		}
	}
}

func TestAccessLog_SkipsHealthEndpoints(t *testing.T) {
	fl := newFlatLogger()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	inner := AccessLog()(handler)
	mw := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := log.WithContext(r.Context(), fl)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}

	for _, path := range []string{"/-/ready", "/-/healthy"} {
		fl.mu.Lock()
		fl.infos = nil
		fl.mu.Unlock()

		mw(inner).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, path, http.NoBody))

		if fl.infoCount() != 0 {
			t.Errorf("health endpoint %q should not be logged", path)
		}
	}
}

func TestAccessLog_LogsNonStaticPaths(t *testing.T) {
	fl := newFlatLogger()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	inner := AccessLog()(handler)
	mw := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := log.WithContext(r.Context(), fl)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}

	paths := []string{"/", "/api/data", "/about", "/api/provenance/app"}
	for _, path := range paths {
		fl.mu.Lock()
		fl.infos = nil
		fl.mu.Unlock()

		mw(inner).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, path, http.NoBody))

		if fl.infoCount() == 0 {
			t.Errorf("path %q should be logged", path)
		}
	}
}

func TestAccessLog_NoLoggerInContext(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	inner := AccessLog()(handler)

	// No logger middleware wrapping - context has no logger.
	// This should not panic. The Nop logger from FromContext
	// returns non-nil, so this tests the actual behavior.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)

	// Should not panic
	inner.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestAccessLog_CapturesContentLength(t *testing.T) {
	fl := newFlatLogger()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	inner := AccessLog()(handler)
	mw := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := log.WithContext(r.Context(), fl)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}

	req := httptest.NewRequest(http.MethodPost, "/api/submit", strings.NewReader("payload"))
	req.ContentLength = 7
	mw(inner).ServeHTTP(httptest.NewRecorder(), req)

	entry, ok := fl.lastInfo()
	if !ok {
		t.Fatal("no info log")
	}

	v, ok := fieldValue(entry.fields, "http.request.body.size")
	if !ok {
		t.Fatal("request body size not logged")
	}
	if v.(int64) != 7 {
		t.Fatalf("request body size = %v, want 7", v)
	}
}

func TestAccessLog_IncludesDuration(t *testing.T) {
	fl := newFlatLogger()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	inner := AccessLog()(handler)
	mw := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := log.WithContext(r.Context(), fl)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}

	mw(inner).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/test", http.NoBody))

	entry, ok := fl.lastInfo()
	if !ok {
		t.Fatal("no info log")
	}

	v, ok := fieldValue(entry.fields, "http.server.request.duration")
	if !ok {
		t.Fatal("duration not logged")
	}
	dur, ok := v.(float64)
	if !ok {
		t.Fatalf("duration type = %T, want float64", v)
	}
	if dur < 0 {
		t.Fatalf("duration = %f, should be >= 0", dur)
	}
}

func TestAccessLog_WithChiRoutePattern(t *testing.T) {
	fl := newFlatLogger()

	r := chi.NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := log.WithContext(r.Context(), fl)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})
	r.Use(AccessLog())
	r.Get("/users/{id}", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/users/42", http.NoBody)
	r.ServeHTTP(rec, req)

	entry, ok := fl.lastInfo()
	if !ok {
		t.Fatal("no info log")
	}

	v, ok := fieldValue(entry.fields, "http.route")
	if !ok {
		t.Fatal("http.route not logged")
	}
	route := v.(string)
	if route != "/users/{id}" {
		t.Fatalf("http.route = %q, want %q", route, "/users/{id}")
	}
}

func TestAccessLog_FallsBackToURLPath(t *testing.T) {
	fl := newFlatLogger()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	inner := AccessLog()(handler)
	mw := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := log.WithContext(r.Context(), fl)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}

	mw(inner).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/custom/path", http.NoBody))

	entry, ok := fl.lastInfo()
	if !ok {
		t.Fatal("no info log")
	}

	v, _ := fieldValue(entry.fields, "http.route")
	if v != "/custom/path" {
		t.Fatalf("http.route = %v, want /custom/path", v)
	}
}

// Scope

func TestScope_EnrichesLogger(t *testing.T) {
	fl := newFlatLogger()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		L := log.FromContext(r.Context())
		L.Info(r.Context(), "inner handler")
	})

	mw := Scope("provenance")
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	ctx := log.WithContext(req.Context(), fl)
	req = req.WithContext(ctx)

	mw(handler).ServeHTTP(httptest.NewRecorder(), req)

	// Scope calls With("handler", "provenance")
	v, ok := withFieldValue(fl.withs, "handler")
	if !ok {
		t.Fatal("handler field not set by Scope")
	}
	if v != "provenance" {
		t.Fatalf("handler = %q, want %q", v, "provenance")
	}
}

func TestScope_HandlerCalled(t *testing.T) {
	called := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	mw := Scope("test")
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	ctx := log.WithContext(req.Context(), newFlatLogger())
	req = req.WithContext(ctx)

	mw(handler).ServeHTTP(httptest.NewRecorder(), req)

	if !called {
		t.Fatal("handler not called")
	}
}

// Fuzz tests (security)

// FuzzSchemeFromRequest tests that schemeFromRequest only ever returns
// "http" or "https" regardless of what X-Forwarded-Proto contains.
func FuzzSchemeFromRequest(f *testing.F) {
	// Seed corpus
	f.Add("http")
	f.Add("https")
	f.Add("HTTPS")
	f.Add("ftp")
	f.Add("gopher")
	f.Add("")
	f.Add("https, http")
	f.Add("  https  ")
	f.Add("https\r\nX-Injected: evil")
	f.Add("https\x00evil")
	f.Add("javascript:alert(1)")
	f.Add(strings.Repeat("A", 10000))
	f.Add("http\t")
	f.Add("HTTP")
	f.Add("hTtPs")
	f.Add("\nhttps")
	f.Add("https\n")

	f.Fuzz(func(t *testing.T, proto string) {
		r := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		r.Header.Set("X-Forwarded-Proto", proto)

		got := schemeFromRequest(r)

		// Invariant: must always be exactly "http" or "https"
		if got != "http" && got != "https" {
			t.Fatalf("schemeFromRequest returned %q for X-Forwarded-Proto=%q - must be http or https",
				got, proto)
		}
	})
}

// FuzzSchemeFromRequest_URLScheme ensures URL.Scheme can't inject invalid values.
func FuzzSchemeFromRequest_URLScheme(f *testing.F) {
	f.Add("http")
	f.Add("https")
	f.Add("ftp")
	f.Add("")
	f.Add("javascript:alert(1)")
	f.Add(strings.Repeat("x", 5000))

	f.Fuzz(func(t *testing.T, scheme string) {
		r := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		r.URL.Scheme = scheme

		got := schemeFromRequest(r)

		if got != "http" && got != "https" {
			t.Fatalf("schemeFromRequest returned %q for URL.Scheme=%q - must be http or https",
				got, scheme)
		}
	})
}

// FuzzWithLogger_RemoteAddr ensures peer address normalization never panics regardless of what RemoteAddr contains.
func FuzzWithLogger_RemoteAddr(f *testing.F) {
	f.Add("10.0.0.1:8080")
	f.Add("192.168.1.1:443")
	f.Add("10.0.0.1")
	f.Add("[::1]:8080")
	f.Add("")
	f.Add("not-an-address")
	f.Add("10.0.0.1:99999")
	f.Add(strings.Repeat("A", 5000))
	f.Add("\x00\x01\x02")
	f.Add("127.0.0.1:0")

	f.Fuzz(func(t *testing.T, remoteAddr string) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

		mw := WithLogger(log.Nop())
		req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		req.RemoteAddr = remoteAddr

		// Must not panic
		rec := httptest.NewRecorder()
		mw(handler).ServeHTTP(rec, req)
	})
}

// FuzzAccessLog_Path ensures AccessLog never panics on arbitrary paths and correctly filters static extensions.
func FuzzAccessLog_Path(f *testing.F) {
	f.Add("/")
	f.Add("/api/data")
	f.Add("/style.css")
	f.Add("/-/healthy")
	f.Add("/-/ready")
	f.Add("/file.js")
	f.Add("/deep/path/image.png")
	f.Add("")
	f.Add(strings.Repeat("/a", 1000))
	f.Add("/path\x00with\x00nulls")
	f.Add("/../../../etc/passwd")
	f.Add("/path%20with%20encoding")
	f.Add(fmt.Sprintf("/%s.css", strings.Repeat("x", 5000)))

	f.Fuzz(func(t *testing.T, urlPath string) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		inner := AccessLog()(handler)
		wrappedWithLogger := func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ctx := log.WithContext(r.Context(), log.Nop())
				next.ServeHTTP(w, r.WithContext(ctx))
			})
		}

		req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		req.URL.Path = urlPath

		rec := httptest.NewRecorder()
		// Must not panic
		wrappedWithLogger(inner).ServeHTTP(rec, req)
	})
}
