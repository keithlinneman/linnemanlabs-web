package httpmw

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

// validSpanContext returns a context with a valid (non-recording) span context for testing.
func validSpanContext() context.Context {
	traceID, _ := trace.TraceIDFromHex("0102030405060708090a0b0c0d0e0f10")
	spanID, _ := trace.SpanIDFromHex("0102030405060708")

	sc := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    traceID,
		SpanID:     spanID,
		TraceFlags: trace.FlagsSampled,
	})

	return trace.ContextWithSpanContext(context.Background(), sc)
}

func TestTraceResponseHeaders_ValidSpan(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mw := TraceResponseHeaders("X-Trace-Id", "X-Span-Id")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody).WithContext(validSpanContext())

	mw(handler).ServeHTTP(rec, req)

	traceHeader := rec.Header().Get("X-Trace-Id")
	spanHeader := rec.Header().Get("X-Span-Id")

	if traceHeader != "0102030405060708090a0b0c0d0e0f10" {
		t.Fatalf("X-Trace-Id = %q, want %q", traceHeader, "0102030405060708090a0b0c0d0e0f10")
	}
	if spanHeader != "0102030405060708" {
		t.Fatalf("X-Span-Id = %q, want %q", spanHeader, "0102030405060708")
	}
}

func TestTraceResponseHeaders_NoSpan(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mw := TraceResponseHeaders("X-Trace-Id", "X-Span-Id")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)

	mw(handler).ServeHTTP(rec, req)

	if got := rec.Header().Get("X-Trace-Id"); got != "" {
		t.Fatalf("expected no X-Trace-Id header, got %q", got)
	}
	if got := rec.Header().Get("X-Span-Id"); got != "" {
		t.Fatalf("expected no X-Span-Id header, got %q", got)
	}
}

func TestTraceResponseHeaders_NoopSpan(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	// noop tracer produces invalid span contexts
	_, span := noop.NewTracerProvider().Tracer("test").Start(context.Background(), "test")
	ctx := trace.ContextWithSpan(context.Background(), span)

	mw := TraceResponseHeaders("X-Trace-Id", "X-Span-Id")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody).WithContext(ctx)

	mw(handler).ServeHTTP(rec, req)

	// noop span context is not valid, so no headers
	if got := rec.Header().Get("X-Trace-Id"); got != "" {
		t.Fatalf("expected no trace header for noop span, got %q", got)
	}
}

func TestTraceResponseHeaders_CustomHeaderNames(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	mw := TraceResponseHeaders("X-Custom-Trace", "X-Custom-Span")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody).WithContext(validSpanContext())

	mw(handler).ServeHTTP(rec, req)

	if got := rec.Header().Get("X-Custom-Trace"); got == "" {
		t.Fatal("custom trace header not set")
	}
	if got := rec.Header().Get("X-Custom-Span"); got == "" {
		t.Fatal("custom span header not set")
	}
}

func TestTraceResponseHeaders_DefaultHeaderNames(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	// Empty strings should default to X-Trace-Id / X-Span-Id
	mw := TraceResponseHeaders("", "")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody).WithContext(validSpanContext())

	mw(handler).ServeHTTP(rec, req)

	if got := rec.Header().Get("X-Trace-Id"); got == "" {
		t.Fatal("default trace header not set")
	}
	if got := rec.Header().Get("X-Span-Id"); got == "" {
		t.Fatal("default span header not set")
	}
}

func TestTraceResponseHeaders_HandlerCalled(t *testing.T) {
	called := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	mw := TraceResponseHeaders("X-Trace-Id", "X-Span-Id")
	mw(handler).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", http.NoBody))

	if !called {
		t.Fatal("next handler not called")
	}
}
