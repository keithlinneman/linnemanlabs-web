package sitehttp

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
)

// helpers

// stubHandler records whether it was called and with what method/path.
type stubHandler struct {
	called bool
	method string
	path   string
}

func (h *stubHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.called = true
	h.method = r.Method
	h.path = r.URL.Path
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("stub"))
}

// New

func TestNew_ReturnsRoutes(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	rt := New(h)

	if rt == nil {
		t.Fatal("New returned nil")
	}
	if rt.Site == nil {
		t.Fatal("Site handler not set")
	}
}

func TestNew_NilHandler(t *testing.T) {
	rt := New(nil)

	if rt == nil {
		t.Fatal("New(nil) returned nil")
	}
	if rt.Site != nil {
		t.Fatal("Site should be nil")
	}
}

// RegisterRoutes — NotFound

func TestRegisterRoutes_NotFound_DelegatesToSite(t *testing.T) {
	stub := &stubHandler{}
	rt := New(stub)

	r := chi.NewRouter()
	rt.RegisterRoutes(r)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/nonexistent/path", nil)
	r.ServeHTTP(rec, req)

	if !stub.called {
		t.Fatal("site handler should be called for unmatched routes")
	}
	if stub.path != "/nonexistent/path" {
		t.Fatalf("path = %q, want /nonexistent/path", stub.path)
	}
}

func TestRegisterRoutes_NotFound_PreservesMethod(t *testing.T) {
	stub := &stubHandler{}
	rt := New(stub)

	r := chi.NewRouter()
	rt.RegisterRoutes(r)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/does-not-exist", nil)
	r.ServeHTTP(rec, req)

	if !stub.called {
		t.Fatal("site handler should be called")
	}
	if stub.method != "POST" {
		t.Fatalf("method = %q, want POST", stub.method)
	}
}

// RegisterRoutes — coexists with explicit routes

func TestRegisterRoutes_ExplicitRouteTakesPrecedence(t *testing.T) {
	stub := &stubHandler{}
	rt := New(stub)

	r := chi.NewRouter()

	// Register an explicit route before the catch-all
	explicitCalled := false
	r.Get("/api/health", func(w http.ResponseWriter, r *http.Request) {
		explicitCalled = true
		w.WriteHeader(http.StatusOK)
	})

	rt.RegisterRoutes(r)

	// Explicit route should be handled by its own handler
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/health", nil)
	r.ServeHTTP(rec, req)

	if !explicitCalled {
		t.Fatal("explicit route should take precedence")
	}
	if stub.called {
		t.Fatal("site handler should NOT be called for explicit routes")
	}

	// Unknown route should fall through to site handler
	stub.called = false
	explicitCalled = false
	rec = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/unknown", nil)
	r.ServeHTTP(rec, req)

	if !stub.called {
		t.Fatal("site handler should be called for unknown routes")
	}
	if explicitCalled {
		t.Fatal("explicit handler should not be called for /unknown")
	}
}

// RegisterRoutes — various HTTP methods on unmatched paths

func TestRegisterRoutes_AllMethods_FallToSite(t *testing.T) {
	methods := []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}

	for _, method := range methods {
		stub := &stubHandler{}
		rt := New(stub)

		r := chi.NewRouter()
		rt.RegisterRoutes(r)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(method, "/anything", nil)
		r.ServeHTTP(rec, req)

		if !stub.called {
			t.Errorf("%s /anything: site handler not called", method)
		}
	}
}

// RegisterRoutes — MethodNotAllowed delegation

func TestRegisterRoutes_MethodNotAllowed_DelegatesToSite(t *testing.T) {
	stub := &stubHandler{}
	rt := New(stub)

	r := chi.NewRouter()

	// Register GET only for /resource
	r.Get("/resource", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	rt.RegisterRoutes(r)

	// POST to /resource should trigger MethodNotAllowed → site handler
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/resource", nil)
	r.ServeHTTP(rec, req)

	if !stub.called {
		t.Fatal("site handler should handle method-not-allowed via MethodNotAllowed override")
	}
}

// RegisterRoutes — deep paths

func TestRegisterRoutes_DeepPath(t *testing.T) {
	stub := &stubHandler{}
	rt := New(stub)

	r := chi.NewRouter()
	rt.RegisterRoutes(r)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/a/b/c/d/e/f", nil)
	r.ServeHTTP(rec, req)

	if !stub.called {
		t.Fatal("deep paths should fall through to site handler")
	}
	if stub.path != "/a/b/c/d/e/f" {
		t.Fatalf("path = %q", stub.path)
	}
}

// RegisterRoutes — root path

func TestRegisterRoutes_RootPath(t *testing.T) {
	stub := &stubHandler{}
	rt := New(stub)

	r := chi.NewRouter()
	rt.RegisterRoutes(r)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	r.ServeHTTP(rec, req)

	// Root with no explicit route should fall to NotFound → site handler
	if !stub.called {
		t.Fatal("root path should fall through to site handler when no explicit route")
	}
}

// Implements RouteRegistrar interface

func TestRoutes_ImplementsRouteRegistrar(t *testing.T) {
	// This is a compile-time check expressed as a test.
	// Routes must satisfy the chi.Router registration pattern.
	rt := New(http.NotFoundHandler())

	r := chi.NewRouter()

	// Should not panic
	rt.RegisterRoutes(r)
}
