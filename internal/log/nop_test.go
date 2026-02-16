package log

import (
	"context"
	"fmt"
	"testing"
)

// nop.go — Nop / nopLogger

func TestNop_ReturnsLogger(t *testing.T) {
	l := Nop()
	if l == nil {
		t.Fatal("Nop() returned nil")
	}
}

func TestNop_AllMethodsSafe(t *testing.T) {
	l := Nop()
	ctx := context.Background()

	// None of these should panic
	l.Debug(ctx, "msg", "k", "v")
	l.Info(ctx, "msg", "k", "v")
	l.Warn(ctx, "msg", "k", "v")
	l.Error(ctx, fmt.Errorf("err"), "msg", "k", "v")

	if err := l.Sync(); err != nil {
		t.Fatalf("Nop Sync should return nil, got: %v", err)
	}
}

func TestNop_WithReturnsSelf(t *testing.T) {
	l := Nop()
	child := l.With("key", "value", "another", 42)

	// With should return itself (or at least a nop)
	if child == nil {
		t.Fatal("Nop().With() returned nil")
	}

	// Should still be safe
	child.Info(context.Background(), "test")
}

func TestNop_WithChaining(t *testing.T) {
	l := Nop()

	// Deep chaining should not panic or accumulate state
	chained := l.With("a", 1).With("b", 2).With("c", 3)
	if chained == nil {
		t.Fatal("chained With returned nil")
	}
	chained.Info(context.Background(), "deeply chained")
}

func TestNop_NilError(t *testing.T) {
	l := Nop()
	// nil error should not panic
	l.Error(context.Background(), nil, "msg with nil error")
}

func TestNop_EmptyWith(t *testing.T) {
	l := Nop()
	child := l.With()
	if child == nil {
		t.Fatal("With() with no args returned nil")
	}
}

func TestNop_OddWith(t *testing.T) {
	l := Nop()
	// Odd number of kv args — should not panic
	child := l.With("orphan_key")
	if child == nil {
		t.Fatal("With() with odd args returned nil")
	}
}
