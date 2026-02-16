package log

import (
	"context"
	"fmt"
	"testing"
)

// Noop (exported struct)

func TestNoop_ImplementsLogger(t *testing.T) {
	var l Logger = Noop{}
	ctx := context.Background()

	l.Debug(ctx, "msg")
	l.Info(ctx, "msg")
	l.Warn(ctx, "msg")
	l.Error(ctx, fmt.Errorf("err"), "msg")

	if err := l.Sync(); err != nil {
		t.Fatalf("Noop Sync: %v", err)
	}
}

func TestNoop_WithReturnsSelf(t *testing.T) {
	var l Logger = Noop{}
	child := l.With("key", "value")

	if child == nil {
		t.Fatal("Noop.With() returned nil")
	}

	// Verify it's still a Noop
	if _, ok := child.(Noop); !ok {
		t.Fatalf("Noop.With() returned %T, want Noop", child)
	}
}

func TestNoop_WithChaining(t *testing.T) {
	var l Logger = Noop{}
	chained := l.With("a", 1).With("b", 2).With("c", 3)
	if chained == nil {
		t.Fatal("chained returned nil")
	}
	chained.Info(context.Background(), "chained noop")
}

func TestNoop_NilError(t *testing.T) {
	Noop{}.Error(context.Background(), nil, "nil error")
}
