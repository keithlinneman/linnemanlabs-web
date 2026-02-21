package httpmw

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSecurityHeaders_AllPresent(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	rec := httptest.NewRecorder()
	SecurityHeaders(handler).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", http.NoBody))

	required := map[string]string{
		"Strict-Transport-Security":         "max-age=31536000; includeSubDomains; preload",
		"X-Content-Type-Options":            "nosniff",
		"X-Frame-Options":                   "DENY",
		"Referrer-Policy":                   "strict-origin-when-cross-origin",
		"X-Permitted-Cross-Domain-Policies": "none",
		"Cross-Origin-Embedder-Policy":      "require-corp",
		"Cross-Origin-Opener-Policy":        "same-origin",
		"Cross-Origin-Resource-Policy":      "same-origin",
	}

	for header, want := range required {
		got := rec.Header().Get(header)
		if got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
}

func TestSecurityHeaders_CSP(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	rec := httptest.NewRecorder()
	SecurityHeaders(handler).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", http.NoBody))

	csp := rec.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("Content-Security-Policy header missing")
	}

	// Verify key CSP directives are present
	directives := []string{
		"default-src 'self'",
		"script-src 'self'",
		"style-src 'self'",
		"frame-ancestors 'none'",
		"object-src 'none'",
		"upgrade-insecure-requests",
		"base-uri 'self'",
		"form-action 'self'",
	}
	for _, d := range directives {
		if !strings.Contains(csp, d) {
			t.Errorf("CSP missing directive %q, full CSP: %s", d, csp)
		}
	}
}

func TestSecurityHeaders_PermissionsPolicy(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	rec := httptest.NewRecorder()
	SecurityHeaders(handler).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", http.NoBody))

	pp := rec.Header().Get("Permissions-Policy")
	if pp == "" {
		t.Fatal("Permissions-Policy header missing")
	}

	disabled := []string{"camera=()", "microphone=()", "geolocation=()", "payment=()"}
	for _, d := range disabled {
		if !strings.Contains(pp, d) {
			t.Errorf("Permissions-Policy missing %q", d)
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
	// Verify headers are available to the handler (set before ServeHTTP)
	var hstsInHandler string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hstsInHandler = w.Header().Get("Strict-Transport-Security")
	})

	SecurityHeaders(handler).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", http.NoBody))

	if hstsInHandler == "" {
		t.Fatal("HSTS header not visible to downstream handler")
	}
}
