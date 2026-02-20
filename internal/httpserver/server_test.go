package httpserver

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/keithlinneman/linnemanlabs-web/internal/log"
)

// test helpers

// stubContentInfo implements httpmw.ContentInfo.
type stubContentInfo struct {
	version string
	hash    string
}

func (s *stubContentInfo) ContentVersion() string { return s.version }
func (s *stubContentInfo) ContentHash() string    { return s.hash }

// stubProbe implements health.Probe for testing.
type stubProbe struct {
	err error
}

func (p *stubProbe) Check(ctx context.Context) error { return p.err }

// defaultOpts returns minimal valid Options for testing.
func defaultOpts() Options {
	return Options{
		Logger: log.Nop(),
	}
}

// doRequest is a helper to send a request through a handler and return the recorder.
func doRequest(t *testing.T, h http.Handler, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, nil)
	h.ServeHTTP(rec, req)
	return rec
}

// getFreePort finds a free TCP port.
func getFreePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp4", ":0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}

// NewHandler - middleware stack

func TestNewHandler_SecurityHeaders(t *testing.T) {
	h := NewHandler(defaultOpts())
	rec := doRequest(t, h, "GET", "/anything")

	required := []string{
		"Strict-Transport-Security",
		"Content-Security-Policy",
		"X-Content-Type-Options",
		"X-Frame-Options",
		"Referrer-Policy",
		"Cross-Origin-Embedder-Policy",
		"Cross-Origin-Opener-Policy",
		"Cross-Origin-Resource-Policy",
	}
	for _, hdr := range required {
		if rec.Header().Get(hdr) == "" {
			t.Errorf("missing security header: %s", hdr)
		}
	}
}

func TestNewHandler_SecurityHeaders_On404(t *testing.T) {
	h := NewHandler(defaultOpts())
	rec := doRequest(t, h, "GET", "/nonexistent-path-12345")

	if rec.Header().Get("Strict-Transport-Security") == "" {
		t.Fatal("HSTS missing on 404 response")
	}
	if rec.Header().Get("X-Content-Type-Options") == "" {
		t.Fatal("X-Content-Type-Options missing on 404 response")
	}
}

func TestNewHandler_SecurityHeaders_AllMethods(t *testing.T) {
	opts := defaultOpts()
	opts.APIRoutes = func(r chi.Router) {
		r.Post("/api/submit", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
	}

	h := NewHandler(opts)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/submit", nil)
	h.ServeHTTP(rec, req)

	if rec.Header().Get("Strict-Transport-Security") == "" {
		t.Fatal("HSTS missing on POST response")
	}
}

func TestNewHandler_RequestID_Generated(t *testing.T) {
	h := NewHandler(defaultOpts())
	rec := doRequest(t, h, "GET", "/")

	id := rec.Header().Get("X-Request-Id")
	if id == "" {
		t.Fatal("X-Request-Id not set on response")
	}
	if len(id) != 32 {
		t.Fatalf("X-Request-Id length = %d, want 32 (16 hex bytes)", len(id))
	}
}

func TestNewHandler_RequestID_Propagated(t *testing.T) {
	h := NewHandler(defaultOpts())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Request-Id", "upstream-abc-123")
	h.ServeHTTP(rec, req)

	if got := rec.Header().Get("X-Request-Id"); got != "upstream-abc-123" {
		t.Fatalf("X-Request-Id = %q, want %q", got, "upstream-abc-123")
	}
}

func TestNewHandler_RequestID_UniquePerRequest(t *testing.T) {
	h := NewHandler(defaultOpts())
	ids := make(map[string]bool)

	for i := 0; i < 50; i++ {
		rec := doRequest(t, h, "GET", "/")
		id := rec.Header().Get("X-Request-Id")
		if ids[id] {
			t.Fatalf("duplicate request ID: %q", id)
		}
		ids[id] = true
	}
}

// NewHandler - APIRoutes

func TestNewHandler_APIRoutes(t *testing.T) {
	opts := defaultOpts()
	opts.APIRoutes = func(r chi.Router) {
		r.Get("/api/test", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("test-ok"))
		})
	}

	h := NewHandler(opts)
	rec := doRequest(t, h, "GET", "/api/test")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "test-ok") {
		t.Fatalf("body = %q, want 'test-ok'", rec.Body.String())
	}
}

func TestNewHandler_APIRoutes_MultipleRoutes(t *testing.T) {
	opts := defaultOpts()
	opts.APIRoutes = func(r chi.Router) {
		r.Get("/api/one", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("one"))
		})
		r.Get("/api/two", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("two"))
		})
	}

	h := NewHandler(opts)

	rec1 := doRequest(t, h, "GET", "/api/one")
	if !strings.Contains(rec1.Body.String(), "one") {
		t.Fatalf("route /api/one: body = %q", rec1.Body.String())
	}

	rec2 := doRequest(t, h, "GET", "/api/two")
	if !strings.Contains(rec2.Body.String(), "two") {
		t.Fatalf("route /api/two: body = %q", rec2.Body.String())
	}
}

func TestNewHandler_APIRoutes_Nil(t *testing.T) {
	opts := defaultOpts()
	opts.APIRoutes = nil

	h := NewHandler(opts)
	rec := doRequest(t, h, "GET", "/")

	if rec.Code == 0 {
		t.Fatal("no response")
	}
}

// NewHandler - SiteHandler

func TestNewHandler_SiteHandler(t *testing.T) {
	opts := defaultOpts()
	opts.SiteHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("site-content"))
	})

	h := NewHandler(opts)
	rec := doRequest(t, h, "GET", "/anything")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "site-content") {
		t.Fatalf("body = %q, want 'site-content'", rec.Body.String())
	}
}

func TestNewHandler_SiteHandler_Nil(t *testing.T) {
	opts := defaultOpts()
	opts.SiteHandler = nil

	h := NewHandler(opts)
	rec := doRequest(t, h, "GET", "/unknown")

	// chi default 404
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestNewHandler_APIRoutes_TakePrecedenceOverFallback(t *testing.T) {
	opts := defaultOpts()
	opts.APIRoutes = func(r chi.Router) {
		r.Get("/api/data", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("api-response"))
		})
	}
	opts.SiteHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("fallback"))
	})

	h := NewHandler(opts)

	// Explicit route should be served by APIRoutes
	rec := doRequest(t, h, "GET", "/api/data")
	if !strings.Contains(rec.Body.String(), "api-response") {
		t.Fatalf("explicit route should hit APIRoutes, got: %q", rec.Body.String())
	}

	// Unknown route should fall through to SiteHandler
	rec = doRequest(t, h, "GET", "/unknown")
	if !strings.Contains(rec.Body.String(), "fallback") {
		t.Fatalf("unknown route should hit SiteHandler, got: %q", rec.Body.String())
	}
}

func TestNewHandler_SiteHandler_MethodNotAllowed(t *testing.T) {
	fallbackCalled := false
	opts := defaultOpts()
	opts.SiteHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fallbackCalled = true
		w.WriteHeader(http.StatusMethodNotAllowed)
	})

	h := NewHandler(opts)
	doRequest(t, h, "DELETE", "/anything")

	if !fallbackCalled {
		t.Fatal("SiteHandler should handle MethodNotAllowed")
	}
}

// NewHandler - health and readiness

func TestNewHandler_HealthEndpoint(t *testing.T) {
	opts := defaultOpts()
	opts.Health = &stubProbe{err: nil}

	h := NewHandler(opts)
	rec := doRequest(t, h, "GET", "/-/healthy")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "ok") {
		t.Fatalf("body = %q, want 'ok'", rec.Body.String())
	}
}

func TestNewHandler_HealthEndpoint_Unhealthy(t *testing.T) {
	opts := defaultOpts()
	opts.Health = &stubProbe{err: fmt.Errorf("broken")}

	h := NewHandler(opts)
	rec := doRequest(t, h, "GET", "/-/healthy")

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

func TestNewHandler_HealthEndpoint_NilProbe(t *testing.T) {
	opts := defaultOpts()
	opts.Health = nil

	h := NewHandler(opts)
	rec := doRequest(t, h, "GET", "/-/healthy")

	// No probe registered, chi returns 404
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (no health probe registered)", rec.Code)
	}
}

func TestNewHandler_ReadyEndpoint(t *testing.T) {
	opts := defaultOpts()
	opts.Readiness = &stubProbe{err: nil}

	h := NewHandler(opts)
	rec := doRequest(t, h, "GET", "/-/ready")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "ready") {
		t.Fatalf("body = %q, want 'ready'", rec.Body.String())
	}
}

func TestNewHandler_ReadyEndpoint_NotReady(t *testing.T) {
	opts := defaultOpts()
	opts.Readiness = &stubProbe{err: fmt.Errorf("content: no active snapshot")}

	h := NewHandler(opts)
	rec := doRequest(t, h, "GET", "/-/ready")

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

func TestNewHandler_ReadyEndpoint_NilProbe(t *testing.T) {
	opts := defaultOpts()
	opts.Readiness = nil

	h := NewHandler(opts)
	rec := doRequest(t, h, "GET", "/-/ready")

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (no readiness probe registered)", rec.Code)
	}
}

func TestNewHandler_HealthEndpoints_NotOverriddenByFallback(t *testing.T) {
	opts := defaultOpts()
	opts.Health = &stubProbe{err: nil}
	opts.Readiness = &stubProbe{err: nil}
	opts.SiteHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("site"))
	})

	h := NewHandler(opts)

	rec := doRequest(t, h, "GET", "/-/healthy")
	if !strings.Contains(rec.Body.String(), "ok") {
		t.Fatalf("/-/healthy should be served by health probe, got: %q", rec.Body.String())
	}

	rec = doRequest(t, h, "GET", "/-/ready")
	if !strings.Contains(rec.Body.String(), "ready") {
		t.Fatalf("/-/ready should be served by readiness probe, got: %q", rec.Body.String())
	}
}

// NewHandler - optional middleware

func TestNewHandler_ContentHeaders_WhenProvided(t *testing.T) {
	opts := defaultOpts()
	opts.ContentInfo = &stubContentInfo{
		version: "v1.2.3",
		hash:    "abcdef1234567890abcdef",
	}

	h := NewHandler(opts)
	rec := doRequest(t, h, "GET", "/")

	if got := rec.Header().Get("X-Content-Bundle-Version"); got != "v1.2.3" {
		t.Fatalf("X-Content-Bundle-Version = %q, want %q", got, "v1.2.3")
	}
	if got := rec.Header().Get("X-Content-Hash"); got == "" {
		t.Fatal("X-Content-Hash not set")
	}
}

func TestNewHandler_ContentHeaders_NilSkipped(t *testing.T) {
	opts := defaultOpts()
	opts.ContentInfo = nil

	h := NewHandler(opts)
	rec := doRequest(t, h, "GET", "/")

	if got := rec.Header().Get("X-Content-Bundle-Version"); got != "" {
		t.Fatalf("X-Content-Bundle-Version should be empty, got %q", got)
	}
}

func TestNewHandler_RateLimitMW_Applied(t *testing.T) {
	rateLimited := false
	opts := defaultOpts()
	opts.RateLimitMW = func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rateLimited = true
			next.ServeHTTP(w, r)
		})
	}

	h := NewHandler(opts)
	doRequest(t, h, "GET", "/")

	if !rateLimited {
		t.Fatal("rate limit middleware not applied")
	}
}

func TestNewHandler_RateLimitMW_NilSkipped(t *testing.T) {
	opts := defaultOpts()
	opts.RateLimitMW = nil

	h := NewHandler(opts)
	rec := doRequest(t, h, "GET", "/")
	if rec.Code == 0 {
		t.Fatal("no response")
	}
}

func TestNewHandler_MetricsMW_Applied(t *testing.T) {
	metricsHit := false
	opts := defaultOpts()
	opts.MetricsMW = func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			metricsHit = true
			next.ServeHTTP(w, r)
		})
	}

	h := NewHandler(opts)
	doRequest(t, h, "GET", "/")

	if !metricsHit {
		t.Fatal("metrics middleware not applied")
	}
}

func TestNewHandler_RecoverMW_Enabled(t *testing.T) {
	opts := defaultOpts()
	opts.UseRecoverMW = true
	opts.APIRoutes = func(r chi.Router) {
		r.Get("/panic", func(w http.ResponseWriter, r *http.Request) {
			panic("test panic")
		})
	}

	h := NewHandler(opts)
	rec := doRequest(t, h, "GET", "/panic")

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (recover should catch panic)", rec.Code)
	}
}

func TestNewHandler_RecoverMW_Disabled(t *testing.T) {
	opts := defaultOpts()
	opts.UseRecoverMW = false
	opts.APIRoutes = func(r chi.Router) {
		r.Get("/panic", func(w http.ResponseWriter, r *http.Request) {
			panic("test panic")
		})
	}

	h := NewHandler(opts)

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic to propagate when recover MW is disabled")
		}
	}()

	doRequest(t, h, "GET", "/panic")
}

func TestNewHandler_RecoverMW_CallsOnPanic(t *testing.T) {
	var called bool
	opts := defaultOpts()
	opts.UseRecoverMW = true
	opts.OnPanic = func() { called = true }
	opts.APIRoutes = func(r chi.Router) {
		r.Get("/panic", func(w http.ResponseWriter, r *http.Request) {
			panic("test panic")
		})
	}

	h := NewHandler(opts)
	doRequest(t, h, "GET", "/panic")

	if !called {
		t.Fatal("OnPanic not called")
	}
}

// NewHandler - middleware ordering

func TestNewHandler_MiddlewareOrder_SecurityHeadersOutermost(t *testing.T) {
	opts := defaultOpts()
	opts.UseRecoverMW = true
	opts.APIRoutes = func(r chi.Router) {
		r.Get("/boom", func(w http.ResponseWriter, r *http.Request) {
			panic("test panic")
		})
	}

	h := NewHandler(opts)
	rec := doRequest(t, h, "GET", "/boom")

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}

	if rec.Header().Get("Strict-Transport-Security") == "" {
		t.Fatal("HSTS missing after panic recovery")
	}
}

func TestNewHandler_ClientIP_InContext(t *testing.T) {
	opts := defaultOpts()
	opts.APIRoutes = func(r chi.Router) {
		r.Get("/ip", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
	}

	h := NewHandler(opts)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/ip", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
}

// NewHandler - compression

func TestNewHandler_CompressesJSON(t *testing.T) {
	opts := defaultOpts()
	opts.APIRoutes = func(r chi.Router) {
		r.Get("/api/data", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"data":"` + strings.Repeat("abcdefghij", 200) + `"}`))
		})
	}

	h := NewHandler(opts)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/data", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}

	ce := rec.Header().Get("Content-Encoding")
	if ce != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip", ce)
	}
}

func TestNewHandler_NoCompressionWithoutAcceptEncoding(t *testing.T) {
	opts := defaultOpts()
	opts.APIRoutes = func(r chi.Router) {
		r.Get("/api/data", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"data":"` + strings.Repeat("abcdefghij", 200) + `"}`))
		})
	}

	h := NewHandler(opts)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/data", nil)
	h.ServeHTTP(rec, req)

	ce := rec.Header().Get("Content-Encoding")
	if ce == "gzip" {
		t.Fatal("should not compress without Accept-Encoding header")
	}
}

// NewHandler - no options

func TestNewHandler_NoOptions(t *testing.T) {
	h := NewHandler(defaultOpts())
	rec := doRequest(t, h, "GET", "/")

	if rec.Header().Get("Strict-Transport-Security") == "" {
		t.Fatal("security headers missing with no options set")
	}
}

// NewServer

func TestNewServer_Configuration(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	srv := NewServer(":8080", handler)

	if srv.Addr != ":8080" {
		t.Fatalf("Addr = %q, want %q", srv.Addr, ":8080")
	}
	if srv.ReadHeaderTimeout != 5*time.Second {
		t.Fatalf("ReadHeaderTimeout = %v, want 5s", srv.ReadHeaderTimeout)
	}
	if srv.ReadTimeout != 10*time.Second {
		t.Fatalf("ReadTimeout = %v, want 10s", srv.ReadTimeout)
	}
	if srv.WriteTimeout != 10*time.Second {
		t.Fatalf("WriteTimeout = %v, want 10s", srv.WriteTimeout)
	}
	if srv.IdleTimeout != 60*time.Second {
		t.Fatalf("IdleTimeout = %v, want 60s", srv.IdleTimeout)
	}
	if srv.MaxHeaderBytes != 1<<20 {
		t.Fatalf("MaxHeaderBytes = %d, want %d", srv.MaxHeaderBytes, 1<<20)
	}
	if srv.Handler == nil {
		t.Fatal("Handler is nil")
	}
}

func TestNewServer_TimeoutsNonZero(t *testing.T) {
	srv := NewServer(":0", http.NotFoundHandler())

	if srv.ReadHeaderTimeout == 0 {
		t.Fatal("ReadHeaderTimeout is zero - vulnerable to slowloris")
	}
	if srv.ReadTimeout == 0 {
		t.Fatal("ReadTimeout is zero")
	}
	if srv.WriteTimeout == 0 {
		t.Fatal("WriteTimeout is zero")
	}
	if srv.IdleTimeout == 0 {
		t.Fatal("IdleTimeout is zero")
	}
}

// Start - lifecycle

func TestStart_CustomPort(t *testing.T) {
	port := getFreePort(t)

	opts := defaultOpts()
	opts.Port = port

	ctx := context.Background()
	stop, err := Start(ctx, opts)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer stop(ctx)

	addr := fmt.Sprintf("http://127.0.0.1:%d/", port)
	resp, err := http.Get(addr)
	if err != nil {
		t.Fatalf("GET %s: %v", addr, err)
	}
	resp.Body.Close()

	if resp.Header.Get("Strict-Transport-Security") == "" {
		t.Fatal("security headers missing from live server response")
	}
}

func TestStart_GracefulShutdown(t *testing.T) {
	port := getFreePort(t)

	opts := defaultOpts()
	opts.Port = port

	ctx := context.Background()
	stop, err := Start(ctx, opts)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	addr := fmt.Sprintf("http://127.0.0.1:%d/", port)
	resp, err := http.Get(addr)
	if err != nil {
		t.Fatalf("server not accepting: %v", err)
	}
	resp.Body.Close()

	shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if err := stop(shutdownCtx); err != nil {
		t.Fatalf("stop: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	_, err = http.Get(addr)
	if err == nil {
		t.Fatal("server still accepting connections after shutdown")
	}
}

func TestStart_StopIdempotent(t *testing.T) {
	port := getFreePort(t)

	opts := defaultOpts()
	opts.Port = port

	ctx := context.Background()
	stop, err := Start(ctx, opts)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	if err := stop(ctx); err != nil {
		t.Fatalf("first stop: %v", err)
	}
	if err := stop(ctx); err != nil {
		t.Fatalf("second stop: %v", err)
	}
	if err := stop(ctx); err != nil {
		t.Fatalf("third stop: %v", err)
	}
}

func TestStart_PortConflict(t *testing.T) {
	port := getFreePort(t)

	opts := defaultOpts()
	opts.Port = port

	ctx := context.Background()

	stop1, err := Start(ctx, opts)
	if err != nil {
		t.Fatalf("first Start: %v", err)
	}
	defer stop1(ctx)

	_, err = Start(ctx, opts)
	if err == nil {
		t.Fatal("expected error for port conflict")
	}
}

func TestStart_RequestID_OnLiveServer(t *testing.T) {
	port := getFreePort(t)

	opts := defaultOpts()
	opts.Port = port

	ctx := context.Background()
	stop, err := Start(ctx, opts)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer stop(ctx)

	addr := fmt.Sprintf("http://127.0.0.1:%d/", port)
	resp, err := http.Get(addr)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()

	id := resp.Header.Get("X-Request-Id")
	if id == "" {
		t.Fatal("X-Request-Id missing from live server response")
	}
	if len(id) != 32 {
		t.Fatalf("X-Request-Id length = %d, want 32", len(id))
	}
}

func TestStart_WithAPIRoutes(t *testing.T) {
	port := getFreePort(t)

	opts := defaultOpts()
	opts.Port = port
	opts.APIRoutes = func(r chi.Router) {
		r.Get("/api/health", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("alive"))
		})
	}

	ctx := context.Background()
	stop, err := Start(ctx, opts)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer stop(ctx)

	addr := fmt.Sprintf("http://127.0.0.1:%d/api/health", port)
	resp, err := http.Get(addr)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(string(body), "alive") {
		t.Fatalf("body = %q, want 'alive'", string(body))
	}
}
