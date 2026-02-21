package httpmw

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestChain_OrderOuterToInner(t *testing.T) {
	var order []string

	mwA := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			order = append(order, "A-before")
			next.ServeHTTP(w, r)
			order = append(order, "A-after")
		})
	}
	mwB := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			order = append(order, "B-before")
			next.ServeHTTP(w, r)
			order = append(order, "B-after")
		})
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		order = append(order, "handler")
	})

	h := Chain(handler, mwA, mwB)
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", http.NoBody))

	want := []string{"A-before", "B-before", "handler", "B-after", "A-after"}
	if len(order) != len(want) {
		t.Fatalf("order = %v, want %v", order, want)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("order[%d] = %q, want %q", i, order[i], want[i])
		}
	}
}

func TestChain_NoMiddleware(t *testing.T) {
	called := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	h := Chain(handler)
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", http.NoBody))

	if !called {
		t.Fatal("handler not called")
	}
}

func TestChain_NilMiddlewareSkipped(t *testing.T) {
	called := false
	mw := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			next.ServeHTTP(w, r)
		})
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	h := Chain(handler, nil, mw, nil) // nolint:gocritic // test that nil middlewares are skipped without panicking
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", http.NoBody))

	if !called {
		t.Fatal("non-nil middleware was not called")
	}
}

func TestChain_SingleMiddleware(t *testing.T) {
	headerSet := false
	mw := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Test", "yes")
			headerSet = true
			next.ServeHTTP(w, r)
		})
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	rec := httptest.NewRecorder()
	h := Chain(handler, mw)
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", http.NoBody))

	if !headerSet {
		t.Fatal("middleware not called")
	}
	if rec.Header().Get("X-Test") != "yes" {
		t.Fatal("header not set")
	}
}
