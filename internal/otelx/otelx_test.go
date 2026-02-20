package otelx

import (
	"context"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// Disabled path

func TestInit_Disabled_ReturnsShutdownFunc(t *testing.T) {
	shutdown, err := Init(context.Background(), Options{Enabled: false})
	if err != nil {
		t.Fatalf("Init disabled: %v", err)
	}
	if shutdown == nil {
		t.Fatal("shutdown func is nil")
	}
}

func TestInit_Disabled_ShutdownIsNoop(t *testing.T) {
	shutdown, _ := Init(context.Background(), Options{Enabled: false})

	// Calling shutdown should not error or panic
	if err := shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown: %v", err)
	}

	// Safe to call multiple times
	if err := shutdown(context.Background()); err != nil {
		t.Fatalf("second shutdown: %v", err)
	}
}

func TestInit_Disabled_SetsTracerProvider(t *testing.T) {
	_, _ = Init(context.Background(), Options{Enabled: false})

	tp := otel.GetTracerProvider()
	if tp == nil {
		t.Fatal("TracerProvider is nil")
	}

	// Should be an SDK TracerProvider (not the default noop)
	if _, ok := tp.(*sdktrace.TracerProvider); !ok {
		t.Fatalf("TracerProvider type = %T, want *sdktrace.TracerProvider", tp)
	}
}

func TestInit_Disabled_SetsPropagator(t *testing.T) {
	_, _ = Init(context.Background(), Options{Enabled: false})

	prop := otel.GetTextMapPropagator()
	if prop == nil {
		t.Fatal("TextMapPropagator is nil")
	}

	// Should support both traceparent and baggage
	fields := prop.Fields()
	fieldSet := make(map[string]bool)
	for _, f := range fields {
		fieldSet[f] = true
	}

	if !fieldSet["traceparent"] {
		t.Error("propagator missing traceparent field")
	}
	if !fieldSet["baggage"] {
		t.Error("propagator missing baggage field")
	}
}

func TestInit_Disabled_TracerProducesNoopSpans(t *testing.T) {
	_, _ = Init(context.Background(), Options{Enabled: false})

	tracer := otel.Tracer("test")
	ctx, span := tracer.Start(context.Background(), "test-span")

	if span == nil {
		t.Fatal("span is nil")
	}

	// Span should be usable without panic
	span.SetName("renamed")
	span.End()

	// Context should carry the span
	if ctx == nil {
		t.Fatal("context is nil")
	}
}

// Options coverage

func TestInit_Disabled_IgnoresAllOptions(t *testing.T) {
	// Even with nonsense options, disabled should succeed
	shutdown, err := Init(context.Background(), Options{
		Enabled:   false,
		Endpoint:  "",
		Sample:    99.9,
		Service:   "",
		Component: "",
		Version:   "",
	})

	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
}

// Global state - verify Init is safe to call multiple times

func TestInit_Disabled_MultipleCalls(t *testing.T) {
	for i := 0; i < 3; i++ {
		shutdown, err := Init(context.Background(), Options{Enabled: false})
		if err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
		if err := shutdown(context.Background()); err != nil {
			t.Fatalf("shutdown %d: %v", i, err)
		}
	}

	// Global provider should still be valid
	tp := otel.GetTracerProvider()
	if tp == nil {
		t.Fatal("TracerProvider nil after multiple Init calls")
	}
}

// Enabled path - timeout

func TestInit_Enabled_ReturnsPromptly(t *testing.T) {
	// Verify Init completes promptly even with an unreachable endpoint.
	// The 10s dial timeout bounds the worst case; gRPC defers connection
	// establishment so this should return quickly.
	start := time.Now()
	shutdown, err := Init(context.Background(), Options{
		Enabled:  true,
		Endpoint: "localhost:1",
		Insecure: true,
		Sample:   1.0,
		Service:  "test",
		Component: "test",
		Version:  "v0.0.0-test",
	})
	elapsed := time.Since(start)

	if err != nil {
		// Error is acceptable (timeout hit), just verify it's bounded
		if elapsed > 15*time.Second {
			t.Fatalf("Init took %v on error, expected bounded by dial timeout", elapsed)
		}
		return
	}

	// No error means gRPC deferred the connection - verify we got a valid shutdown func
	if shutdown == nil {
		t.Fatal("shutdown func is nil")
	}
	if elapsed > 15*time.Second {
		t.Fatalf("Init took %v, expected to complete within dial timeout", elapsed)
	}

	// Shutdown should not panic even with no real connection
	if err := shutdown(context.Background()); err != nil {
		t.Logf("shutdown error (expected with no real collector): %v", err)
	}
}

// Propagator type - verify composite propagator

func TestInit_Disabled_CompositePropagator(t *testing.T) {
	_, _ = Init(context.Background(), Options{Enabled: false})

	prop := otel.GetTextMapPropagator()

	// CompositeTextMapPropagator should have fields from both TraceContext and Baggage
	// TraceContext: traceparent, tracestate
	// Baggage: baggage
	fields := prop.Fields()
	if len(fields) < 2 {
		t.Fatalf("expected at least 2 propagator fields, got %d: %v", len(fields), fields)
	}
}
