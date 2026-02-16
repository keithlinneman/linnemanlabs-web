package log

import (
	"context"
	"fmt"
	"io"
	"testing"
)

// context.go - WithContext / FromContext

func TestWithContext_StoresLogger(t *testing.T) {
	l := Nop()
	ctx := WithContext(context.Background(), l)

	got := FromContext(ctx)
	if got == nil {
		t.Fatal("FromContext returned nil")
	}
}

func TestFromContext_ReturnsStoredLogger(t *testing.T) {
	// Use a distinguishable logger type
	l := &nopLogger{}
	ctx := WithContext(context.Background(), l)

	got := FromContext(ctx)
	if got != l {
		t.Fatal("FromContext returned a different logger than what was stored")
	}
}

func TestFromContext_EmptyContext_ReturnsNop(t *testing.T) {
	got := FromContext(context.Background())
	if got == nil {
		t.Fatal("FromContext on empty context returned nil, want Nop()")
	}

	// Should be safe to call without panic
	got.Info(context.Background(), "test")
	got.Debug(context.Background(), "test")
	got.Warn(context.Background(), "test")
	got.Error(context.Background(), fmt.Errorf("test"), "test")
	if err := got.Sync(); err != nil {
		t.Fatalf("Sync error: %v", err)
	}
}

func TestFromContext_NilLogger_ReturnsNop(t *testing.T) {
	// Explicitly store nil
	ctx := context.WithValue(context.Background(), ctxKey{}, nil)

	got := FromContext(ctx)
	if got == nil {
		t.Fatal("FromContext with nil logger returned nil, want Nop()")
	}

	// Must be safe to use
	got.Info(context.Background(), "should not panic")
}

func TestFromContext_WrongType_ReturnsNop(t *testing.T) {
	// Store a non-Logger value with the same key
	ctx := context.WithValue(context.Background(), ctxKey{}, "not a logger")

	got := FromContext(ctx)
	if got == nil {
		t.Fatal("FromContext with wrong type returned nil, want Nop()")
	}

	got.Info(context.Background(), "should not panic")
}

func TestWithContext_Overwrites(t *testing.T) {
	l1 := Nop()
	l2 := &nopLogger{}

	ctx := WithContext(context.Background(), l1)
	ctx = WithContext(ctx, l2)

	got := FromContext(ctx)
	if got != l2 {
		t.Fatal("second WithContext should overwrite the first")
	}
}

func TestWithContext_DoesNotAffectParent(t *testing.T) {
	parent := context.Background()
	// Use a distinguishable logger (pointer type, not Nop value)
	l, _ := New(Options{App: "test", Writer: io.Discard})

	child := WithContext(parent, l)

	fromParent := FromContext(parent)
	fromChild := FromContext(child)

	// Parent returns Nop (not our logger), child returns our logger
	if fromParent == l {
		t.Fatal("parent context should not have the logger")
	}
	if fromChild != l {
		t.Fatal("child context should have the logger")
	}
}
