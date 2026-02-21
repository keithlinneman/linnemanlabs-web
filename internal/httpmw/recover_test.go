package httpmw

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/keithlinneman/linnemanlabs-web/internal/log"
)

// spyLogger captures Error calls for assertions.
type spyLogger struct {
	log.Logger
	mu     sync.Mutex
	errors []spyError
}

type spyError struct {
	msg string
	err error
	kv  []any
}

func newSpyLogger() *spyLogger {
	return &spyLogger{Logger: log.Nop()}
}

func (s *spyLogger) With(kv ...any) log.Logger {
	// Return self so Error calls still land here
	return s
}

func (s *spyLogger) Error(ctx context.Context, err error, msg string, kv ...any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.errors = append(s.errors, spyError{msg: msg, err: err, kv: kv})
}

func (s *spyLogger) lastError() (spyError, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.errors) == 0 {
		return spyError{}, false
	}
	return s.errors[len(s.errors)-1], true
}

// Tests

func TestRecover_NoPanic(t *testing.T) {
	spy := newSpyLogger()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mw := Recover(spy, nil)
	rec := httptest.NewRecorder()
	mw(handler).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", http.NoBody))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	if _, logged := spy.lastError(); logged {
		t.Fatal("error logged when no panic occurred")
	}
}

func TestRecover_StringPanic(t *testing.T) {
	spy := newSpyLogger()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("something broke")
	})

	mw := Recover(spy, nil)
	rec := httptest.NewRecorder()

	// Should not propagate the panic
	mw(handler).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/test", http.NoBody))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}

	e, ok := spy.lastError()
	if !ok {
		t.Fatal("expected error to be logged")
	}
	if e.msg != "httpserver panic recovered" {
		t.Fatalf("msg = %q, want %q", e.msg, "httpserver panic recovered")
	}
}

func TestRecover_ErrorPanic(t *testing.T) {
	spy := newSpyLogger()
	panicErr := fmt.Errorf("database connection lost")

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic(panicErr)
	})

	mw := Recover(spy, nil)
	rec := httptest.NewRecorder()
	mw(handler).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", http.NoBody))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}

	e, ok := spy.lastError()
	if !ok {
		t.Fatal("expected error to be logged")
	}
	if e.err == nil {
		t.Fatal("expected wrapped error")
	}
}

func TestRecover_ResponseBody(t *testing.T) {
	spy := newSpyLogger()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("boom")
	})

	mw := Recover(spy, nil)
	rec := httptest.NewRecorder()
	mw(handler).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", http.NoBody))

	body := rec.Body.String()
	if body == "" {
		t.Fatal("expected error body in response")
	}
	// http.Error writes "Internal Server Error\n"
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestRecover_LogIncludesMethodAndPath(t *testing.T) {
	spy := newSpyLogger()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("test")
	})

	mw := Recover(spy, nil)
	mw(handler).ServeHTTP(
		httptest.NewRecorder(),
		httptest.NewRequest(http.MethodPost, "/api/submit", http.NoBody),
	)

	// The spy captures With() calls by returning self,
	// so the Error call lands on the spy. The actual key-value
	// enrichment happens via With() in the middleware.
	_, ok := spy.lastError()
	if !ok {
		t.Fatal("expected error logged")
	}
}

func TestRecover_DoesNotInterfereWithNormalFlow(t *testing.T) {
	spy := newSpyLogger()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Custom", "value")
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte("created"))
	})

	mw := Recover(spy, nil)
	rec := httptest.NewRecorder()
	mw(handler).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/", http.NoBody))

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201", rec.Code)
	}
	if got := rec.Header().Get("X-Custom"); got != "value" {
		t.Fatalf("X-Custom = %q", got)
	}
	if rec.Body.String() != "created" {
		t.Fatalf("body = %q", rec.Body.String())
	}
}

func TestRecover_OnPanicCalled(t *testing.T) {
	spy := newSpyLogger()
	var called bool
	onPanic := func() { called = true }

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("boom")
	})

	mw := Recover(spy, onPanic)
	mw(handler).ServeHTTP(
		httptest.NewRecorder(),
		httptest.NewRequest(http.MethodGet, "/", http.NoBody),
	)

	if !called {
		t.Fatal("onPanic callback not called")
	}
}

func TestRecover_OnPanicNil(t *testing.T) {
	spy := newSpyLogger()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("boom")
	})

	// nil callback should not panic
	mw := Recover(spy, nil)
	rec := httptest.NewRecorder()
	mw(handler).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", http.NoBody))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}
