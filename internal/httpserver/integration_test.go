package httpserver_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/keithlinneman/linnemanlabs-web/internal/content"
	"github.com/keithlinneman/linnemanlabs-web/internal/httpserver"
	"github.com/keithlinneman/linnemanlabs-web/internal/log"
	"github.com/keithlinneman/linnemanlabs-web/internal/sitehandler"
)

// TestIntegration_FullStack wires up httpserver.NewHandler with a real
// sitehandler.Handler backed by an in-memory content Manager, then verifies
// that security headers, status codes, and content serving work end-to-end.
func TestIntegration_FullStack(t *testing.T) {
	t.Parallel()

	// Set up in-memory content
	siteFS := fstest.MapFS{
		"index.html":       {Data: []byte("<html><body>Hello World</body></html>")},
		"about/index.html": {Data: []byte("<html><body>About</body></html>")},
		"style.css":        {Data: []byte("body { color: red; }")},
		"404.html":         {Data: []byte("<html><body>Not Found</body></html>")},
	}

	mgr := content.NewManager()
	mgr.Set(content.Snapshot{
		FS:   siteFS,
		Meta: content.Meta{Version: "v1.0.0", Hash: "abc123def456"},
	})

	fallbackFS := fstest.MapFS{
		"maintenance.html": {Data: []byte("<html><body>Maintenance</body></html>")},
		"404.html":         {Data: []byte("<html><body>Fallback 404</body></html>")},
	}

	siteH, err := sitehandler.New(&sitehandler.Options{
		Logger:     log.Nop(),
		Content:    mgr,
		FallbackFS: fallbackFS,
	})
	if err != nil {
		t.Fatalf("sitehandler.New: %v", err)
	}

	handler := httpserver.NewHandler(&httpserver.Options{
		Logger:      log.Nop(),
		SiteHandler: siteH,
		ContentInfo: mgr,
	})

	// Subtests cover the full request lifecycle through all middleware layers.

	t.Run("serves index.html with security headers", func(t *testing.T) {
		t.Parallel()
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}

		body, _ := io.ReadAll(rec.Body)
		if !strings.Contains(string(body), "Hello World") {
			t.Fatalf("body = %q, want content containing 'Hello World'", body)
		}

		// Verify security headers are present on content responses
		securityHeaders := []string{
			"Strict-Transport-Security",
			"Content-Security-Policy",
			"X-Content-Type-Options",
			"X-Frame-Options",
			"Referrer-Policy",
			"Cross-Origin-Embedder-Policy",
			"Cross-Origin-Opener-Policy",
			"Cross-Origin-Resource-Policy",
			"Permissions-Policy",
		}
		for _, hdr := range securityHeaders {
			if rec.Header().Get(hdr) == "" {
				t.Errorf("missing security header: %s", hdr)
			}
		}

		// Verify content version headers
		if got := rec.Header().Get("X-Content-Bundle-Version"); got != "v1.0.0" {
			t.Errorf("X-Content-Bundle-Version = %q, want %q", got, "v1.0.0")
		}
		if got := rec.Header().Get("X-Content-Hash"); got == "" {
			t.Error("X-Content-Hash not set")
		}

		// Verify request ID is generated
		if got := rec.Header().Get("X-Request-Id"); got == "" {
			t.Error("X-Request-Id not set")
		}
	})

	t.Run("serves sub-path content", func(t *testing.T) {
		t.Parallel()
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/about/", http.NoBody)
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}

		body, _ := io.ReadAll(rec.Body)
		if !strings.Contains(string(body), "About") {
			t.Fatalf("body = %q, want content containing 'About'", body)
		}
	})

	t.Run("serves static assets with security headers", func(t *testing.T) {
		t.Parallel()
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/style.css", http.NoBody)
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		if rec.Header().Get("Strict-Transport-Security") == "" {
			t.Fatal("HSTS missing on static asset response")
		}
	})

	t.Run("returns 404 for missing path", func(t *testing.T) {
		t.Parallel()
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/does-not-exist", http.NoBody)
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
		// Security headers must be present even on 404
		if rec.Header().Get("Strict-Transport-Security") == "" {
			t.Fatal("HSTS missing on 404 response")
		}
	})

	t.Run("rejects POST with 405", func(t *testing.T) {
		t.Parallel()
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/", http.NoBody)
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("status = %d, want 405", rec.Code)
		}
		if rec.Header().Get("Strict-Transport-Security") == "" {
			t.Fatal("HSTS missing on 405 response")
		}
	})

	t.Run("HEAD returns same status as GET without body", func(t *testing.T) {
		t.Parallel()
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodHead, "/", http.NoBody)
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		if rec.Header().Get("Strict-Transport-Security") == "" {
			t.Fatal("HSTS missing on HEAD response")
		}
	})
}
