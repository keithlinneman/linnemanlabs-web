package prof

import (
	"context"
	"strings"
	"testing"

	"github.com/keithlinneman/linnemanlabs-web/internal/log"
)

// Disabled path

func TestStart_Disabled_ReturnsStopFunc(t *testing.T) {
	stop, err := Start(context.Background(), Options{Enabled: false})
	if err != nil {
		t.Fatalf("Start disabled: %v", err)
	}
	if stop == nil {
		t.Fatal("stop func is nil")
	}
}

func TestStart_Disabled_StopIsNoop(t *testing.T) {
	stop, _ := Start(context.Background(), Options{Enabled: false})

	// Should not panic
	stop()
	stop() // safe to call multiple times
}

func TestStart_Disabled_NoError(t *testing.T) {
	_, err := Start(context.Background(), Options{Enabled: false})
	if err != nil {
		t.Fatalf("disabled should never error, got: %v", err)
	}
}

func TestStart_Disabled_IgnoresAllOptions(t *testing.T) {
	// Even with nonsense values, disabled should succeed
	stop, err := Start(context.Background(), Options{
		Enabled:              false,
		AppName:              "",
		ServerAddress:        "",
		AuthToken:            "secret",
		TenantID:             "tenant",
		Tags:                 map[string]string{"k": "v"},
		ProfileMutexFraction: 999,
		BlockProfileRate:     999,
	})

	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	stop()
}

func TestStart_Disabled_WithLogger(t *testing.T) {
	ctx := log.WithContext(context.Background(), log.Nop())

	stop, err := Start(ctx, Options{Enabled: false})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	stop()
}

// Enabled - validation

func TestStart_Enabled_EmptyServerAddress_Errors(t *testing.T) {
	stop, err := Start(context.Background(), Options{
		Enabled:       true,
		ServerAddress: "",
		AppName:       "test",
	})

	if err == nil {
		t.Fatal("expected error for empty server address")
	}
	if !strings.Contains(err.Error(), "invalid server address") {
		t.Fatalf("error = %q, want 'invalid server address'", err.Error())
	}

	// Stop func should still be returned and safe to call
	if stop == nil {
		t.Fatal("stop func should be non-nil even on error")
	}
	stop()
}

func TestStart_Enabled_EmptyServerAddress_StopIdempotent(t *testing.T) {
	stop, _ := Start(context.Background(), Options{
		Enabled:       true,
		ServerAddress: "",
	})

	// Multiple calls should not panic
	stop()
	stop()
	stop()
}

// Enabled - unreachable server (pyroscope.Start behavior)

func TestStart_Enabled_UnreachableServer(t *testing.T) {
	// pyroscope.Start may or may not error for unreachable servers
	// 1. Always returns a non-nil stop func
	// 2. stop() never panics
	stop, err := Start(context.Background(), Options{
		Enabled:       true,
		ServerAddress: "http://localhost:0/nonexistent",
		AppName:       "test",
	})

	if stop == nil {
		t.Fatal("stop func should always be non-nil")
	}
	stop()

	// We don't assert on err because pyroscope behavior varies -
	// some versions connect lazily and succeed, others fail immediately
	_ = err
}

// Options - Tags, AuthToken, TenantID passthrough

func TestStart_Enabled_EmptyAddress_WithFullOptions(t *testing.T) {
	// Validates that all option fields are accepted without panic
	// before the address check rejects the call
	_, err := Start(context.Background(), Options{
		Enabled:              true,
		AppName:              "myapp",
		ServerAddress:        "", // will fail validation
		AuthToken:            "token123",
		TenantID:             "tenant456",
		Tags:                 map[string]string{"env": "test", "version": "v1"},
		ProfileMutexFraction: 5,
		BlockProfileRate:     1000,
	})

	if err == nil {
		t.Fatal("expected error for empty address")
	}
}

// Contract: error always accompanied by usable stop func

func TestStart_ErrorContract(t *testing.T) {
	// The function contract from the source:
	// return func() {}, err
	// This means even on error, stop is always a valid callable.

	stop, err := Start(context.Background(), Options{
		Enabled:       true,
		ServerAddress: "",
	})

	if err == nil {
		t.Fatal("expected error")
	}
	if stop == nil {
		t.Fatal("stop must be non-nil even on error")
	}

	// Must not panic
	stop()
}

// Context with logger - ensures FromContext path works

func TestStart_Enabled_EmptyAddress_WithContextLogger(t *testing.T) {
	ctx := log.WithContext(context.Background(), log.Nop())

	stop, err := Start(ctx, Options{
		Enabled:       true,
		ServerAddress: "",
	})

	if err == nil {
		t.Fatal("expected error")
	}
	stop()
}

func TestStart_Disabled_NoLogger(t *testing.T) {
	// No logger in context - FromContext returns Nop, should not panic
	stop, err := Start(context.Background(), Options{Enabled: false})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	stop()
}
