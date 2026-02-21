package xerrors

import (
	"errors"
	"runtime"
	"strings"
	"testing"
)

// sentinel for errors.Is / errors.As testing

var errSentinel = errors.New("sentinel")

// stackContains checks if any frame in PCs contains the given function name substring.
func stackContains(pcs []uintptr, substr string) bool {
	frames := runtime.CallersFrames(pcs)
	for {
		fr, more := frames.Next()
		if strings.Contains(fr.Function, substr) {
			return true
		}
		if !more {
			break
		}
	}
	return false
}

// New / Newf

func TestNew_ErrorMessage(t *testing.T) {
	err := New("something broke")
	if err.Error() != "something broke" {
		t.Fatalf("Error() = %q", err.Error())
	}
}

func TestNew_HasStack(t *testing.T) {
	err := New("boom")

	var hs interface{ StackPCs() []uintptr }
	if !errors.As(err, &hs) {
		t.Fatal("New error should have StackPCs")
	}
	if len(hs.StackPCs()) == 0 {
		t.Fatal("stack should be non-empty")
	}
}

func TestNew_StackContainsCaller(t *testing.T) {
	err := New("test")

	var hs interface{ StackPCs() []uintptr }
	errors.As(err, &hs)

	if !stackContains(hs.StackPCs(), "TestNew_StackContainsCaller") {
		t.Fatal("stack should contain calling function")
	}
}

func TestNewf_FormatsMessage(t *testing.T) {
	err := Newf("invalid port %d for %s", 99999, "server")
	want := "invalid port 99999 for server"
	if err.Error() != want {
		t.Fatalf("Error() = %q, want %q", err.Error(), want)
	}
}

func TestNewf_HasStack(t *testing.T) {
	err := Newf("err %d", 42)

	var hs interface{ StackPCs() []uintptr }
	if !errors.As(err, &hs) {
		t.Fatal("Newf error should have StackPCs")
	}
	if len(hs.StackPCs()) == 0 {
		t.Fatal("stack should be non-empty")
	}
}

func TestNew_IsXerrorsWrapper(t *testing.T) {
	err := New("test")

	var marker interface{ IsXerrorsWrapper() }
	if !errors.As(err, &marker) {
		t.Fatal("New error should implement IsXerrorsWrapper")
	}
}

// WithStack

func TestWithStack_NilReturnsNil(t *testing.T) {
	if WithStack(nil) != nil {
		t.Fatal("WithStack(nil) should return nil")
	}
}

func TestWithStack_AddsStack(t *testing.T) {
	base := errors.New("base")
	err := WithStack(base)

	var hs interface{ StackPCs() []uintptr }
	if !errors.As(err, &hs) {
		t.Fatal("should have stack")
	}
	if len(hs.StackPCs()) == 0 {
		t.Fatal("stack should be non-empty")
	}
}

func TestWithStack_PreservesMessage(t *testing.T) {
	base := errors.New("original message")
	err := WithStack(base)

	if err.Error() != "original message" {
		t.Fatalf("Error() = %q", err.Error())
	}
}

func TestWithStack_Unwraps(t *testing.T) {
	base := errors.New("base")
	err := WithStack(base)

	if !errors.Is(err, base) {
		t.Fatal("should unwrap to base error")
	}
}

// Wrap / Wrapf

func TestWrap_NilReturnsNil(t *testing.T) {
	if Wrap(nil, "context") != nil {
		t.Fatal("Wrap(nil) should return nil")
	}
}

func TestWrap_ErrorMessage(t *testing.T) {
	base := errors.New("connection refused")
	err := Wrap(base, "dial server")

	want := "dial server: connection refused"
	if err.Error() != want {
		t.Fatalf("Error() = %q, want %q", err.Error(), want)
	}
}

func TestWrap_Unwraps(t *testing.T) {
	err := Wrap(errSentinel, "context")

	if !errors.Is(err, errSentinel) {
		t.Fatal("should unwrap to sentinel")
	}
}

func TestWrap_HasPC(t *testing.T) {
	err := Wrap(errSentinel, "context")

	var hp interface{ PC() uintptr }
	if !errors.As(err, &hp) {
		t.Fatal("Wrap should capture PC")
	}
	if hp.PC() == 0 {
		t.Fatal("PC should be non-zero")
	}
}

func TestWrap_IsXerrorsWrapper(t *testing.T) {
	err := Wrap(errSentinel, "ctx")

	var marker interface{ IsXerrorsWrapper() }
	if !errors.As(err, &marker) {
		t.Fatal("Wrap should implement IsXerrorsWrapper")
	}
}

func TestWrapf_NilReturnsNil(t *testing.T) {
	if Wrapf(nil, "context %d", 1) != nil {
		t.Fatal("Wrapf(nil) should return nil")
	}
}

func TestWrapf_FormatsMessage(t *testing.T) {
	base := errors.New("timeout")
	err := Wrapf(base, "fetch %s after %dms", "https://example.com", 5000)

	want := "fetch https://example.com after 5000ms: timeout"
	if err.Error() != want {
		t.Fatalf("Error() = %q, want %q", err.Error(), want)
	}
}

func TestWrapf_Unwraps(t *testing.T) {
	err := Wrapf(errSentinel, "step %d", 3)

	if !errors.Is(err, errSentinel) {
		t.Fatal("should unwrap to sentinel")
	}
}

func TestWrapf_HasPC(t *testing.T) {
	err := Wrapf(errSentinel, "ctx %d", 1)

	var hp interface{ PC() uintptr }
	if !errors.As(err, &hp) {
		t.Fatal("Wrapf should capture PC")
	}
	if hp.PC() == 0 {
		t.Fatal("PC should be non-zero")
	}
}

// EnsureTrace

func TestEnsureTrace_NilReturnsNil(t *testing.T) {
	if EnsureTrace(nil) != nil {
		t.Fatal("EnsureTrace(nil) should return nil")
	}
}

func TestEnsureTrace_AddsStackToPlainError(t *testing.T) {
	base := errors.New("plain")
	err := EnsureTrace(base)

	var hs interface{ StackPCs() []uintptr }
	if !errors.As(err, &hs) {
		t.Fatal("should add stack to plain error")
	}
	if len(hs.StackPCs()) == 0 {
		t.Fatal("stack should be non-empty")
	}
}

func TestEnsureTrace_Idempotent(t *testing.T) {
	first := New("already traced")
	second := EnsureTrace(first)

	if first != second { //nolint:errorlint // testing error identity
		t.Fatal("EnsureTrace should return same error if already stacked")
	}
}

func TestEnsureTrace_IdempotentWithStack(t *testing.T) {
	base := errors.New("base")
	stacked := WithStack(base)
	result := EnsureTrace(stacked)

	if result != stacked { //nolint:errorlint // testing error identity
		t.Fatal("EnsureTrace should not re-wrap an already-stacked error")
	}
}

func TestEnsureTrace_PreservesUnwrap(t *testing.T) {
	err := EnsureTrace(errSentinel)

	if !errors.Is(err, errSentinel) {
		t.Fatal("should still unwrap to sentinel")
	}
}

func TestEnsureTrace_WrappedErrorGetsStack(t *testing.T) {
	// Wrap adds PC but not StackPCs - EnsureTrace should add a full stack
	base := errors.New("root")
	wrapped := Wrap(base, "ctx")

	traced := EnsureTrace(wrapped)

	var hs interface{ StackPCs() []uintptr }
	if !errors.As(traced, &hs) {
		t.Fatal("should have stack after EnsureTrace on wrapped error")
	}
}

// Chained wrapping

func TestChainedWrap_UnwrapsAll(t *testing.T) {
	base := errors.New("root cause")
	w1 := Wrap(base, "layer 1")
	w2 := Wrap(w1, "layer 2")
	w3 := Wrapf(w2, "layer %d", 3)

	if !errors.Is(w3, base) {
		t.Fatal("should unwrap through full chain")
	}
}

func TestChainedWrap_ErrorMessage(t *testing.T) {
	base := errors.New("eof")
	w1 := Wrap(base, "read body")
	w2 := Wrap(w1, "handle request")

	want := "handle request: read body: eof"
	if w2.Error() != want {
		t.Fatalf("Error() = %q, want %q", w2.Error(), want)
	}
}

func TestChainedWrap_ErrorsAs(t *testing.T) {
	base := New("inner")
	outer := Wrap(base, "outer")

	var hs interface{ StackPCs() []uintptr }
	if !errors.As(outer, &hs) {
		t.Fatal("errors.As should find withStack in chain")
	}
}

func TestChainedWrap_MultiplePCs(t *testing.T) {
	base := errors.New("root")
	w1 := Wrap(base, "l1")
	w2 := Wrap(w1, "l2")

	// Extract PC from outer wrap
	pc2 := w2.(*wrap).PC() //nolint:errorlint // testing internal wrap type directly
	pc1 := w1.(*wrap).PC() //nolint:errorlint // testing internal wrap type directly

	if pc1 == 0 || pc2 == 0 {
		t.Fatal("both wraps should have non-zero PCs")
	}
	if pc1 == pc2 {
		t.Fatal("PCs from different call sites should differ")
	}
}

// withStack internal

func TestWithStack_ErrorDelegates(t *testing.T) {
	base := errors.New("delegate me")
	ws := &withStack{err: base, pcs: []uintptr{1, 2, 3}}

	if ws.Error() != "delegate me" {
		t.Fatalf("Error() = %q", ws.Error())
	}
}

func TestWithStack_UnwrapReturnsInner(t *testing.T) {
	base := errors.New("inner")
	ws := &withStack{err: base, pcs: []uintptr{1}}

	if ws.Unwrap() != base { //nolint:errorlint // testing unwrap returns exact original
		t.Fatal("Unwrap should return inner error")
	}
}

func TestWithStack_StackPCsReturnsCapture(t *testing.T) {
	pcs := []uintptr{100, 200, 300}
	ws := &withStack{err: errors.New("x"), pcs: pcs}

	got := ws.StackPCs()
	if len(got) != 3 || got[0] != 100 || got[1] != 200 || got[2] != 300 {
		t.Fatalf("StackPCs() = %v", got)
	}
}

// wrap internal

func TestWrapStruct_ErrorFormat(t *testing.T) {
	base := errors.New("base")
	w := &wrap{err: base, msg: "context", pc: 12345}

	if w.Error() != "context: base" {
		t.Fatalf("Error() = %q", w.Error())
	}
}

func TestWrapStruct_UnwrapReturnsInner(t *testing.T) {
	base := errors.New("inner")
	w := &wrap{err: base, msg: "ctx"}

	if w.Unwrap() != base { //nolint:errorlint // testing unwrap returns exact original
		t.Fatal("Unwrap should return inner error")
	}
}

func TestWrapStruct_PCReturnsValue(t *testing.T) {
	w := &wrap{err: errors.New("x"), msg: "y", pc: 42}
	if w.PC() != 42 {
		t.Fatalf("PC() = %d, want 42", w.PC())
	}
}

// captureStack

func TestCaptureStack_NonEmpty(t *testing.T) {
	pcs := captureStack(0)
	if len(pcs) == 0 {
		t.Fatal("captureStack should return non-empty slice")
	}
}

func TestCaptureStack_ContainsCaller(t *testing.T) {
	pcs := captureStack(0)
	if !stackContains(pcs, "TestCaptureStack_ContainsCaller") {
		t.Fatal("stack should contain calling function")
	}
}

// callerPC

func TestCallerPC_NonZero(t *testing.T) {
	pc := callerPC(0)
	if pc == 0 {
		t.Fatal("callerPC should return non-zero PC")
	}
}

// withStackSkip - nil passthrough

func TestWithStackSkip_NilReturnsNil(t *testing.T) {
	if withStackSkip(nil, 0) != nil {
		t.Fatal("withStackSkip(nil) should return nil")
	}
}

func TestWithStackSkip_AddsStack(t *testing.T) {
	err := withStackSkip(errors.New("test"), 0)

	var hs interface{ StackPCs() []uintptr }
	if !errors.As(err, &hs) {
		t.Fatal("should have stack")
	}
}
