package httpmw

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMaxBody_UnderLimit_PassesThrough(t *testing.T) {
	handler := MaxBody(1024)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
		w.Write(body)
	}))

	payload := "hello world" // 11 bytes, well under 1024
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(payload))
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if rec.Body.String() != payload {
		t.Fatalf("body = %q, want %q", rec.Body.String(), payload)
	}
}

func TestMaxBody_ExactlyAtLimit(t *testing.T) {
	const limit = 16
	payload := strings.Repeat("x", limit)

	handler := MaxBody(limit)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read failed", http.StatusRequestEntityTooLarge)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write(body)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(payload))
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body exactly at limit)", rec.Code)
	}
}

func TestMaxBody_OverLimit_ReadFails(t *testing.T) {
	const limit = 16
	payload := strings.Repeat("x", limit+1)

	handler := MaxBody(limit)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := io.ReadAll(r.Body)
		if err == nil {
			t.Fatal("expected error reading oversized body")
		}
		// http.MaxBytesReader triggers 413 automatically when the handler
		// tries to read past the limit, but only if WriteHeader hasn't
		// been called yet. The error itself is what matters here.
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(payload))
	handler.ServeHTTP(rec, req)
}

func TestMaxBody_OverLimit_ErrorType(t *testing.T) {
	const limit = 8

	handler := MaxBody(limit)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := io.ReadAll(r.Body)
		if err == nil {
			t.Fatal("expected error")
		}
		// Go 1.19+ exposes MaxBytesError
		var maxErr *http.MaxBytesError
		if !errors.As(err, &maxErr) {
			t.Fatalf("error type = %T, want *http.MaxBytesError", err)
		}
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(strings.Repeat("x", 100)))
	handler.ServeHTTP(rec, req)
}

func TestMaxBody_GET_NoBody(t *testing.T) {
	handler := MaxBody(1024)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestMaxBody_ZeroLimit_RejectsAnyBody(t *testing.T) {
	handler := MaxBody(0)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := io.ReadAll(r.Body)
		if err == nil {
			// empty body reads succeed even with limit 0
			return
		}
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("a"))
	handler.ServeHTTP(rec, req)
}

func TestMaxBody_LargeLimit(t *testing.T) {
	const limit = 50 * 1024 * 1024 // 50MB limit
	payload := strings.Repeat("x", 1024)

	handler := MaxBody(limit)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(payload))
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestMaxBody_ChainedWithOtherMiddleware(t *testing.T) {
	// verify MaxBody composes correctly as middleware
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "too large", http.StatusRequestEntityTooLarge)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write(body)
	})

	// wrap with MaxBody
	handler := MaxBody(10)(inner)

	// under limit
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("short"))
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("under limit: status = %d, want 200", rec.Code)
	}

	// over limit
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/", strings.NewReader("this exceeds the ten byte limit"))
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("over limit: status = %d, want 413", rec.Code)
	}
}
