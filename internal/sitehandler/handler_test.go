package sitehandler

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/keithlinneman/linnemanlabs-web/internal/content"
	"github.com/keithlinneman/linnemanlabs-web/internal/log"
)

// ---------------------------------------------------------------------------
// test fixtures
// ---------------------------------------------------------------------------

// fallbackFS has maintenance.html and optional 404.html
func testFallbackFS() fs.FS {
	return fstest.MapFS{
		"maintenance.html": &fstest.MapFile{Data: []byte("<h1>Maintenance</h1>")},
		"404.html":         &fstest.MapFile{Data: []byte("<h1>Fallback 404</h1>")},
	}
}

// fallbackFSNoFallback404 has maintenance.html but no 404.html
func testFallbackFSNo404() fs.FS {
	return fstest.MapFS{
		"maintenance.html": &fstest.MapFile{Data: []byte("<h1>Maintenance</h1>")},
	}
}

// siteFS simulates an active content snapshot filesystem
func testSiteFS() fs.FS {
	return fstest.MapFS{
		"index.html":             &fstest.MapFile{Data: []byte("<h1>Home</h1>")},
		"about/index.html":       &fstest.MapFile{Data: []byte("<h1>About</h1>")},
		"style.css":              &fstest.MapFile{Data: []byte("body{}")},
		"app.js":                 &fstest.MapFile{Data: []byte("console.log('hi')")},
		"image.png":              &fstest.MapFile{Data: []byte("PNG")},
		"404.html":               &fstest.MapFile{Data: []byte("<h1>Site 404</h1>")},
		"posts/hello/index.html": &fstest.MapFile{Data: []byte("<h1>Hello Post</h1>")},
		"data.json":              &fstest.MapFile{Data: []byte(`{"k":"v"}`)},
	}
}

// siteFSNo404 is a site content FS without its own 404.html
func testSiteFSNo404() fs.FS {
	return fstest.MapFS{
		"index.html": &fstest.MapFile{Data: []byte("<h1>Home</h1>")},
	}
}

// stubProvider implements SnapshotProvider for testing
type stubProvider struct {
	snap *content.Snapshot
	ok   bool
}

func (s *stubProvider) Get() (*content.Snapshot, bool) {
	return s.snap, s.ok
}

func activeProvider(siteFS fs.FS) *stubProvider {
	return &stubProvider{
		snap: &content.Snapshot{FS: siteFS},
		ok:   true,
	}
}

func noProvider() *stubProvider {
	return &stubProvider{nil, false}
}

// newTestHandler builds a Handler for tests. Panics on error.
func newTestHandler(cp SnapshotProvider, fallback fs.FS) *Handler {
	h, err := New(Options{
		Logger:     log.Nop(),
		Content:    cp,
		FallbackFS: fallback,
	})
	if err != nil {
		panic(err)
	}
	return h
}

// ---------------------------------------------------------------------------
// New — validation
// ---------------------------------------------------------------------------

func TestNew_ValidOptions(t *testing.T) {
	h, err := New(Options{
		Logger:     log.Nop(),
		Content:    activeProvider(testSiteFS()),
		FallbackFS: testFallbackFS(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if h == nil {
		t.Fatal("handler is nil")
	}
}

func TestNew_NilContent(t *testing.T) {
	_, err := New(Options{
		Logger:     log.Nop(),
		Content:    nil,
		FallbackFS: testFallbackFS(),
	})
	if err == nil {
		t.Fatal("expected error for nil Content")
	}
	if !strings.Contains(err.Error(), "Content is nil") {
		t.Fatalf("error = %q", err.Error())
	}
}

func TestNew_NilFallbackFS(t *testing.T) {
	_, err := New(Options{
		Logger:     log.Nop(),
		Content:    activeProvider(testSiteFS()),
		FallbackFS: nil,
	})
	if err == nil {
		t.Fatal("expected error for nil FallbackFS")
	}
	if !strings.Contains(err.Error(), "FallbackFS is nil") {
		t.Fatalf("error = %q", err.Error())
	}
}

func TestNew_MissingMaintenanceFile(t *testing.T) {
	emptyFS := fstest.MapFS{}
	_, err := New(Options{
		Logger:     log.Nop(),
		Content:    activeProvider(testSiteFS()),
		FallbackFS: emptyFS,
	})
	if err == nil {
		t.Fatal("expected error for missing maintenance.html")
	}
	if !strings.Contains(err.Error(), "maintenance.html") {
		t.Fatalf("error = %q", err.Error())
	}
}

func TestNew_CustomMaintenanceFile(t *testing.T) {
	customFS := fstest.MapFS{
		"custom-maintenance.html": &fstest.MapFile{Data: []byte("custom")},
	}
	h, err := New(Options{
		Logger:          log.Nop(),
		Content:         activeProvider(testSiteFS()),
		FallbackFS:      customFS,
		MaintenanceFile: "custom-maintenance.html",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if h == nil {
		t.Fatal("handler is nil")
	}
}

func TestNew_SetsDefaults(t *testing.T) {
	h, _ := New(Options{
		Logger:     log.Nop(),
		Content:    activeProvider(testSiteFS()),
		FallbackFS: testFallbackFS(),
	})

	if h.opts.MaintenanceFile != "maintenance.html" {
		t.Fatalf("MaintenanceFile = %q", h.opts.MaintenanceFile)
	}
	if h.opts.Site404File != "404.html" {
		t.Fatalf("Site404File = %q", h.opts.Site404File)
	}
	if h.opts.Fallback404File != "404.html" {
		t.Fatalf("Fallback404File = %q", h.opts.Fallback404File)
	}
	if h.opts.HTMLCacheControl != "no-cache" {
		t.Fatalf("HTMLCacheControl = %q", h.opts.HTMLCacheControl)
	}
	if h.opts.AssetCacheControl != "public, max-age=31536000, immutable" {
		t.Fatalf("AssetCacheControl = %q", h.opts.AssetCacheControl)
	}
}

func TestNew_ErrInvalidOptions(t *testing.T) {
	_, err := New(Options{})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "sitehandler: invalid options") {
		t.Fatalf("error = %q, want ErrInvalidOptions", err.Error())
	}
}

// ---------------------------------------------------------------------------
// ServeHTTP — method hardening
// ---------------------------------------------------------------------------

func TestServeHTTP_GET_OK(t *testing.T) {
	h := newTestHandler(activeProvider(testSiteFS()), testFallbackFS())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestServeHTTP_HEAD_OK(t *testing.T) {
	h := newTestHandler(activeProvider(testSiteFS()), testFallbackFS())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("HEAD", "/", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestServeHTTP_POST_MethodNotAllowed(t *testing.T) {
	h := newTestHandler(activeProvider(testSiteFS()), testFallbackFS())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
	if rec.Header().Get("Allow") != "GET, HEAD" {
		t.Fatalf("Allow = %q", rec.Header().Get("Allow"))
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", rec.Header().Get("Cache-Control"))
	}
}

func TestServeHTTP_AllBlockedMethods(t *testing.T) {
	h := newTestHandler(activeProvider(testSiteFS()), testFallbackFS())

	methods := []string{"POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
	for _, m := range methods {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(m, "/", nil)
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: status = %d, want 405", m, rec.Code)
		}
	}
}

func TestServeHTTP_BlockedMethod_EmptyBody(t *testing.T) {
	h := newTestHandler(activeProvider(testSiteFS()), testFallbackFS())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("DELETE", "/", nil)
	h.ServeHTTP(rec, req)

	// Should not leak any content in the body
	if rec.Body.Len() > 0 {
		t.Fatalf("body should be empty for blocked methods, got %d bytes", rec.Body.Len())
	}
}

// ---------------------------------------------------------------------------
// ServeHTTP — serving content
// ---------------------------------------------------------------------------

func TestServeHTTP_RootServesIndexHTML(t *testing.T) {
	h := newTestHandler(activeProvider(testSiteFS()), testFallbackFS())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Home") {
		t.Fatalf("body = %q, want Home", rec.Body.String())
	}
}

func TestServeHTTP_SubdirIndexHTML(t *testing.T) {
	h := newTestHandler(activeProvider(testSiteFS()), testFallbackFS())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/about/", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "About") {
		t.Fatalf("body = %q", rec.Body.String())
	}
}

func TestServeHTTP_StaticFile(t *testing.T) {
	h := newTestHandler(activeProvider(testSiteFS()), testFallbackFS())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/style.css", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "body{}") {
		t.Fatalf("body = %q", rec.Body.String())
	}
}

func TestServeHTTP_PrettyURL_Redirect(t *testing.T) {
	h := newTestHandler(activeProvider(testSiteFS()), testFallbackFS())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/about", nil)
	h.ServeHTTP(rec, req)

	// Should redirect /about → /about/ (pretty URL with trailing slash)
	if rec.Code != http.StatusPermanentRedirect {
		t.Fatalf("status = %d, want 308", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if loc != "/about/" {
		t.Fatalf("Location = %q, want /about/", loc)
	}
}

func TestServeHTTP_DeepPrettyURL(t *testing.T) {
	h := newTestHandler(activeProvider(testSiteFS()), testFallbackFS())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/posts/hello", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusPermanentRedirect {
		t.Fatalf("status = %d, want 308", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if loc != "/posts/hello/" {
		t.Fatalf("Location = %q", loc)
	}
}

// ---------------------------------------------------------------------------
// ServeHTTP — not found
// ---------------------------------------------------------------------------

func TestServeHTTP_NotFound_Site404(t *testing.T) {
	h := newTestHandler(activeProvider(testSiteFS()), testFallbackFS())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/nonexistent", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Site 404") {
		t.Fatalf("should use site's 404.html, body = %q", rec.Body.String())
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", rec.Header().Get("Cache-Control"))
	}
}

func TestServeHTTP_NotFound_FallbackTo404(t *testing.T) {
	// Site FS has no 404.html → should fall back to fallback FS 404
	h := newTestHandler(activeProvider(testSiteFSNo404()), testFallbackFS())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/nonexistent", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Fallback 404") {
		t.Fatalf("should use fallback 404.html, body = %q", rec.Body.String())
	}
}

func TestServeHTTP_NotFound_PlainText(t *testing.T) {
	// Neither site nor fallback has 404.html → plain text
	h := newTestHandler(activeProvider(testSiteFSNo404()), testFallbackFSNo404())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/nonexistent", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "404 page not found") {
		t.Fatalf("should get plain text 404, body = %q", rec.Body.String())
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/plain") {
		t.Fatalf("Content-Type = %q, want text/plain", ct)
	}
}

// ---------------------------------------------------------------------------
// ServeHTTP — maintenance
// ---------------------------------------------------------------------------

func TestServeHTTP_Maintenance(t *testing.T) {
	h := newTestHandler(noProvider(), testFallbackFS())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Maintenance") {
		t.Fatalf("body = %q", rec.Body.String())
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", rec.Header().Get("Cache-Control"))
	}
	if rec.Header().Get("Retry-After") != "60" {
		t.Fatalf("Retry-After = %q, want 60", rec.Header().Get("Retry-After"))
	}
}

func TestServeHTTP_Maintenance_AnyPath(t *testing.T) {
	h := newTestHandler(noProvider(), testFallbackFS())

	paths := []string{"/", "/about", "/style.css", "/api/data"}
	for _, p := range paths {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", p, nil)
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("%s: status = %d, want 503", p, rec.Code)
		}
	}
}

// ---------------------------------------------------------------------------
// ServeHTTP — cache-control policy
// ---------------------------------------------------------------------------

func TestServeHTTP_CacheControl_HTML(t *testing.T) {
	h := newTestHandler(activeProvider(testSiteFS()), testFallbackFS())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	h.ServeHTTP(rec, req)

	cc := rec.Header().Get("Cache-Control")
	if cc != "no-cache" {
		t.Fatalf("Cache-Control for HTML = %q, want no-cache", cc)
	}
}

func TestServeHTTP_CacheControl_CSS(t *testing.T) {
	h := newTestHandler(activeProvider(testSiteFS()), testFallbackFS())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/style.css", nil)
	h.ServeHTTP(rec, req)

	cc := rec.Header().Get("Cache-Control")
	if !strings.Contains(cc, "immutable") {
		t.Fatalf("Cache-Control for CSS = %q, want immutable", cc)
	}
}

func TestServeHTTP_CacheControl_JS(t *testing.T) {
	h := newTestHandler(activeProvider(testSiteFS()), testFallbackFS())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/app.js", nil)
	h.ServeHTTP(rec, req)

	cc := rec.Header().Get("Cache-Control")
	if !strings.Contains(cc, "immutable") {
		t.Fatalf("Cache-Control for JS = %q, want immutable", cc)
	}
}

func TestServeHTTP_CacheControl_Other(t *testing.T) {
	h := newTestHandler(activeProvider(testSiteFS()), testFallbackFS())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/data.json", nil)
	h.ServeHTTP(rec, req)

	cc := rec.Header().Get("Cache-Control")
	if !strings.Contains(cc, "max-age=3600") {
		t.Fatalf("Cache-Control for JSON = %q, want max-age=3600", cc)
	}
}

func TestServeHTTP_CacheControl_Custom(t *testing.T) {
	h, _ := New(Options{
		Logger:            log.Nop(),
		Content:           activeProvider(testSiteFS()),
		FallbackFS:        testFallbackFS(),
		HTMLCacheControl:  "private, no-cache",
		AssetCacheControl: "public, max-age=600",
		OtherCacheControl: "no-store",
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	h.ServeHTTP(rec, req)

	if rec.Header().Get("Cache-Control") != "private, no-cache" {
		t.Fatalf("custom HTML cache = %q", rec.Header().Get("Cache-Control"))
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/style.css", nil)
	h.ServeHTTP(rec, req)

	if rec.Header().Get("Cache-Control") != "public, max-age=600" {
		t.Fatalf("custom asset cache = %q", rec.Header().Get("Cache-Control"))
	}
}

// ---------------------------------------------------------------------------
// statusOverrideWriter
// ---------------------------------------------------------------------------

func TestStatusOverrideWriter_OverridesFirstWrite(t *testing.T) {
	rec := httptest.NewRecorder()
	sw := &statusOverrideWriter{ResponseWriter: rec, status: http.StatusNotFound}

	sw.WriteHeader(http.StatusOK) // handler tries 200, should be overridden to 404

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	if !sw.wroteHeader {
		t.Fatal("wroteHeader should be true")
	}
}

func TestStatusOverrideWriter_SecondWritePassthrough(t *testing.T) {
	rec := httptest.NewRecorder()
	sw := &statusOverrideWriter{ResponseWriter: rec, status: http.StatusNotFound}

	sw.WriteHeader(http.StatusOK) // overridden to 404
	sw.WriteHeader(http.StatusOK) // second call passes through (httptest only keeps first)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, should still be 404", rec.Code)
	}
}

func TestStatusOverrideWriter_503(t *testing.T) {
	rec := httptest.NewRecorder()
	sw := &statusOverrideWriter{ResponseWriter: rec, status: http.StatusServiceUnavailable}

	sw.WriteHeader(http.StatusOK)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// Security — path traversal via handler
// ---------------------------------------------------------------------------

func TestServeHTTP_Security_DotDot(t *testing.T) {
	h := newTestHandler(activeProvider(testSiteFS()), testFallbackFS())

	paths := []string{
		"/../../../etc/passwd",
		"/about/../../../etc/shadow",
	}

	for _, p := range paths {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", p, nil)
		h.ServeHTTP(rec, req)

		if rec.Code == http.StatusOK {
			t.Errorf("path traversal returned 200: %s", p)
		}
	}
}

func TestServeHTTP_Security_Backslash(t *testing.T) {
	h := newTestHandler(activeProvider(testSiteFS()), testFallbackFS())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/about\\index.html", nil)
	h.ServeHTTP(rec, req)

	// Should not serve content via backslash paths
	if rec.Code == http.StatusOK && strings.Contains(rec.Body.String(), "About") {
		t.Fatal("backslash path should not serve content")
	}
}

// serveNotFound — Cache-Control always set

func TestServeNotFound_NoCacheOnAllVariants(t *testing.T) {
	variants := []struct {
		name     string
		siteFS   fs.FS
		fallback fs.FS
	}{
		{"site 404", testSiteFS(), testFallbackFS()},
		{"fallback 404", testSiteFSNo404(), testFallbackFS()},
		{"plain text", testSiteFSNo404(), testFallbackFSNo404()},
	}

	for _, v := range variants {
		h := newTestHandler(activeProvider(v.siteFS), v.fallback)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/nonexistent-page", nil)
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusNotFound {
			t.Errorf("%s: status = %d, want 404", v.name, rec.Code)
		}
		if rec.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("%s: Cache-Control = %q, want no-store", v.name, rec.Header().Get("Cache-Control"))
		}
	}
}

// Integration: handler implements http.Handler

func TestHandler_ImplementsHTTPHandler(t *testing.T) {
	h := newTestHandler(activeProvider(testSiteFS()), testFallbackFS())

	var _ http.Handler = h // compile-time check
}
