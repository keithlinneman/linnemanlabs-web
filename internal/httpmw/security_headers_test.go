package httpmw

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSecurityHeaders_DocumentHeadersPresent(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	rec := httptest.NewRecorder()
	SecurityHeaders(handler).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", http.NoBody))

	required := map[string]string{
		"Strict-Transport-Security":         "max-age=31536000; includeSubDomains; preload",
		"X-Content-Type-Options":            "nosniff",
		"Referrer-Policy":                   "strict-origin-when-cross-origin",
		"X-Frame-Options":                   "DENY",
		"X-Permitted-Cross-Domain-Policies": "none",
		"Cross-Origin-Resource-Policy":      "same-origin",
		"Cross-Origin-Opener-Policy":        "same-origin",
		"Origin-Agent-Cluster":              "?1",
	}

	for header, want := range required {
		got := rec.Header().Get(header)
		if got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}

}

func TestSecurityHeaders_DocumentCSP(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	rec := httptest.NewRecorder()
	SecurityHeaders(handler).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", http.NoBody))

	csp := rec.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("Content-Security-Policy header missing")
	}

	directives := []string{
		"default-src 'self'",
		"script-src 'self'",
		"style-src 'self'",
		"img-src 'self'",
		"font-src 'self'",
		"base-uri 'self'",
		"form-action 'self'",
		"frame-ancestors 'none'",
		"object-src 'none'",
		"upgrade-insecure-requests",
	}

	for _, d := range directives {
		if !strings.Contains(csp, d) {
			t.Errorf("CSP missing directive %q, full CSP: %s", d, csp)
		}
	}
}

func TestSecurityHeaders_DocumentPermissionsPolicy(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	rec := httptest.NewRecorder()
	SecurityHeaders(handler).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", http.NoBody))

	pp := rec.Header().Get("Permissions-Policy")
	if pp == "" {
		t.Fatal("Permissions-Policy header missing")
	}

	disabled := []string{
		"accelerometer=()",
		"camera=()",
		"geolocation=()",
		"gyroscope=()",
		"magnetometer=()",
		"microphone=()",
		"payment=()",
		"usb=()",
	}

	for _, d := range disabled {
		if !strings.Contains(pp, d) {
			t.Errorf("Permissions-Policy missing %q, full policy: %s", d, pp)
		}
	}
}

func TestSecurityHeaders_StaticImagesAreCrossOrigin(t *testing.T) {
	cases := []string{
		"/img/og/home.png",
		"/img/og/blog/post-slug.webp",
		"/img/other/photo.png",
		"/img/logo.svg",
		"/favicon.ico",
		"/assets/image.JPG",
		"/assets/image.PNG",
		"/assets/image.jpeg",
		"/assets/image.gif",
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	for _, path := range cases {
		rec := httptest.NewRecorder()
		SecurityHeaders(handler).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, http.NoBody))

		required := map[string]string{
			"Strict-Transport-Security":    "max-age=31536000; includeSubDomains; preload",
			"X-Content-Type-Options":       "nosniff",
			"Referrer-Policy":              "strict-origin-when-cross-origin",
			"Cross-Origin-Resource-Policy": "cross-origin",
		}

		for header, want := range required {
			if got := rec.Header().Get(header); got != want {
				t.Errorf("path %q: %s = %q, want %q", path, header, got, want)
			}
		}
	}
}

func TestSecurityHeaders_StaticImagesDoNotGetDocumentHeaders(t *testing.T) {
	cases := []string{
		"/img/og/home.png",
		"/img/og/blog/post-slug.webp",
		"/img/other/photo.png",
		"/img/logo.svg",
		"/favicon.ico",
		"/assets/image.JPG",
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	for _, path := range cases {
		rec := httptest.NewRecorder()
		SecurityHeaders(handler).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, http.NoBody))

		absent := []string{
			"Content-Security-Policy",
			"Permissions-Policy",
			"X-Frame-Options",
			"X-Permitted-Cross-Domain-Policies",
			"Cross-Origin-Opener-Policy",
			"Cross-Origin-Embedder-Policy",
			"Origin-Agent-Cluster",
		}

		for _, header := range absent {
			if got := rec.Header().Get(header); got != "" {
				t.Errorf("path %q: %s = %q, want unset", path, header, got)
			}
		}
	}
}

func TestSecurityHeaders_NonImagePathsGetDocumentHeaders(t *testing.T) {
	cases := []string{
		"/",
		"/posts/hello-my-name-is-orca/",
		"/img/og",
		"/img/og/",
		"/api/provenance/app",
		"/api/provenance/app.json",
		"/assets/style.css",
		"/assets/app.js",
		"/fonts/ibm-plex.woff2",
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	for _, path := range cases {
		rec := httptest.NewRecorder()
		SecurityHeaders(handler).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, http.NoBody))

		required := map[string]string{
			"Cross-Origin-Resource-Policy": "same-origin",
			"Cross-Origin-Opener-Policy":   "same-origin",
			"Origin-Agent-Cluster":         "?1",
			"X-Frame-Options":              "DENY",
		}

		for header, want := range required {
			if got := rec.Header().Get(header); got != want {
				t.Errorf("path %q: %s = %q, want %q", path, header, got, want)
			}
		}

		if got := rec.Header().Get("Content-Security-Policy"); got == "" {
			t.Errorf("path %q: Content-Security-Policy missing", path)
		}

		if got := rec.Header().Get("Permissions-Policy"); got == "" {
			t.Errorf("path %q: Permissions-Policy missing", path)
		}

		if got := rec.Header().Get("Cross-Origin-Embedder-Policy"); got != "" {
			t.Errorf("path %q: Cross-Origin-Embedder-Policy = %q, want unset", path, got)
		}
	}
}

func TestSecurityHeaders_HandlerCalled(t *testing.T) {
	called := false

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusTeapot)
	})

	rec := httptest.NewRecorder()
	SecurityHeaders(handler).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", http.NoBody))

	if !called {
		t.Fatal("next handler not called")
	}

	if rec.Code != http.StatusTeapot {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusTeapot)
	}
}

func TestSecurityHeaders_HeadersSetBeforeHandler(t *testing.T) {
	var hstsInHandler string
	var corpInHandler string
	var oacInHandler string

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hstsInHandler = w.Header().Get("Strict-Transport-Security")
		corpInHandler = w.Header().Get("Cross-Origin-Resource-Policy")
		oacInHandler = w.Header().Get("Origin-Agent-Cluster")
	})

	SecurityHeaders(handler).ServeHTTP(
		httptest.NewRecorder(),
		httptest.NewRequest(http.MethodGet, "/", http.NoBody),
	)

	if hstsInHandler == "" {
		t.Fatal("Strict-Transport-Security header not visible to downstream handler")
	}

	if corpInHandler != "same-origin" {
		t.Fatalf("Cross-Origin-Resource-Policy visible to downstream handler = %q, want %q", corpInHandler, "same-origin")
	}

	if oacInHandler != "?1" {
		t.Fatalf("Origin-Agent-Cluster visible to downstream handler = %q, want %q", oacInHandler, "?1")
	}
}
