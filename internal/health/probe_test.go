package health

import (
	"context"
	"fmt"
	"sync"
	"testing"
)

// CheckFunc

func TestCheckFunc_PassingProbe(t *testing.T) {
	p := CheckFunc(func(ctx context.Context) error { return nil })
	if err := p.Check(context.Background()); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

func TestCheckFunc_FailingProbe(t *testing.T) {
	p := CheckFunc(func(ctx context.Context) error { return fmt.Errorf("broken") })
	if err := p.Check(context.Background()); err == nil {
		t.Fatal("expected error")
	}
}

func TestCheckFunc_ImplementsProbe(t *testing.T) {
	var _ Probe = CheckFunc(func(ctx context.Context) error { return nil })
}

// Fixed

func TestFixed_OK(t *testing.T) {
	p := Fixed(true, "")
	if err := p.Check(context.Background()); err != nil {
		t.Fatalf("Fixed(true) should pass, got %v", err)
	}
}

func TestFixed_Fail_WithReason(t *testing.T) {
	p := Fixed(false, "db offline")
	err := p.Check(context.Background())
	if err == nil {
		t.Fatal("Fixed(false) should fail")
	}
	if err.Error() != "db offline" {
		t.Fatalf("reason = %q, want 'db offline'", err.Error())
	}
}

func TestFixed_Fail_DefaultReason(t *testing.T) {
	p := Fixed(false, "")
	err := p.Check(context.Background())
	if err == nil {
		t.Fatal("Fixed(false, '') should fail")
	}
	if err.Error() != "unhealthy" {
		t.Fatalf("reason = %q, want 'unhealthy'", err.Error())
	}
}

func TestFixed_OK_IgnoresReason(t *testing.T) {
	p := Fixed(true, "this reason should be ignored")
	if err := p.Check(context.Background()); err != nil {
		t.Fatalf("Fixed(true) should pass regardless of reason, got %v", err)
	}
}

func TestFixed_Deterministic(t *testing.T) {
	p := Fixed(false, "always fails")
	for i := 0; i < 10; i++ {
		if err := p.Check(context.Background()); err == nil {
			t.Fatal("Fixed(false) should always fail")
		}
	}
}

// All

func TestAll_AllPass(t *testing.T) {
	p := All(
		Fixed(true, ""),
		Fixed(true, ""),
		Fixed(true, ""),
	)
	if err := p.Check(context.Background()); err != nil {
		t.Fatalf("All(pass, pass, pass) should pass, got %v", err)
	}
}

func TestAll_FirstFails(t *testing.T) {
	p := All(
		Fixed(false, "first"),
		Fixed(true, ""),
	)
	err := p.Check(context.Background())
	if err == nil {
		t.Fatal("All should fail if first fails")
	}
	if err.Error() != "first" {
		t.Fatalf("should return first error, got %q", err.Error())
	}
}

func TestAll_SecondFails(t *testing.T) {
	p := All(
		Fixed(true, ""),
		Fixed(false, "second"),
	)
	err := p.Check(context.Background())
	if err == nil {
		t.Fatal("All should fail if second fails")
	}
	if err.Error() != "second" {
		t.Fatalf("should return second error, got %q", err.Error())
	}
}

func TestAll_MultipleFail_ReturnsFirst(t *testing.T) {
	p := All(
		Fixed(false, "first"),
		Fixed(false, "second"),
	)
	err := p.Check(context.Background())
	if err == nil {
		t.Fatal("All should fail")
	}
	if err.Error() != "first" {
		t.Fatalf("should return first error, got %q", err.Error())
	}
}

func TestAll_Empty(t *testing.T) {
	p := All()
	if err := p.Check(context.Background()); err != nil {
		t.Fatalf("All() with no probes should pass, got %v", err)
	}
}

func TestAll_NilProbesSkipped(t *testing.T) {
	p := All(nil, Fixed(true, ""), nil)
	if err := p.Check(context.Background()); err != nil {
		t.Fatalf("All with nil probes should skip them, got %v", err)
	}
}

func TestAll_NilProbeBeforeFailure(t *testing.T) {
	p := All(nil, Fixed(false, "real failure"))
	err := p.Check(context.Background())
	if err == nil {
		t.Fatal("should still fail after skipping nil")
	}
	if err.Error() != "real failure" {
		t.Fatalf("error = %q, want 'real failure'", err.Error())
	}
}

func TestAll_ShortCircuits(t *testing.T) {
	secondCalled := false
	p := All(
		Fixed(false, "stop here"),
		CheckFunc(func(ctx context.Context) error {
			secondCalled = true
			return nil
		}),
	)
	p.Check(context.Background())
	if secondCalled {
		t.Fatal("All should short-circuit after first failure")
	}
}

// Any

func TestAny_AllPass(t *testing.T) {
	p := Any(
		Fixed(true, ""),
		Fixed(true, ""),
	)
	if err := p.Check(context.Background()); err != nil {
		t.Fatalf("Any(pass, pass) should pass, got %v", err)
	}
}

func TestAny_OnePasses(t *testing.T) {
	p := Any(
		Fixed(false, "down"),
		Fixed(true, ""),
	)
	if err := p.Check(context.Background()); err != nil {
		t.Fatalf("Any should pass if one passes, got %v", err)
	}
}

func TestAny_FirstPasses(t *testing.T) {
	p := Any(
		Fixed(true, ""),
		Fixed(false, "down"),
	)
	if err := p.Check(context.Background()); err != nil {
		t.Fatalf("Any should pass if first passes, got %v", err)
	}
}

func TestAny_AllFail(t *testing.T) {
	p := Any(
		Fixed(false, "first"),
		Fixed(false, "second"),
	)
	err := p.Check(context.Background())
	if err == nil {
		t.Fatal("Any(fail, fail) should fail")
	}
}

func TestAny_AllFail_ReturnsLastError(t *testing.T) {
	p := Any(
		Fixed(false, "first"),
		Fixed(false, "last"),
	)
	err := p.Check(context.Background())
	if err.Error() != "last" {
		t.Fatalf("should return last error, got %q", err.Error())
	}
}

func TestAny_Empty(t *testing.T) {
	p := Any()
	err := p.Check(context.Background())
	if err == nil {
		t.Fatal("Any() with no probes should fail")
	}
	if err.Error() != "no healthy probes" {
		t.Fatalf("error = %q, want 'no healthy probes'", err.Error())
	}
}

func TestAny_NilProbesSkipped(t *testing.T) {
	p := Any(nil, Fixed(true, ""), nil)
	if err := p.Check(context.Background()); err != nil {
		t.Fatalf("Any with nil probes should skip them, got %v", err)
	}
}

func TestAny_OnlyNilProbes(t *testing.T) {
	p := Any(nil, nil)
	err := p.Check(context.Background())
	if err == nil {
		t.Fatal("Any with only nil probes should fail")
	}
}

// ShutdownGate

func TestShutdownGate_InitiallyOpen(t *testing.T) {
	var g ShutdownGate
	p := g.Probe()
	if err := p.Check(context.Background()); err != nil {
		t.Fatalf("new gate should be open, got %v", err)
	}
}

func TestShutdownGate_SetCloses(t *testing.T) {
	var g ShutdownGate
	g.Set("draining")
	p := g.Probe()

	err := p.Check(context.Background())
	if err == nil {
		t.Fatal("gate should be closed after Set")
	}
	if err.Error() != "draining" {
		t.Fatalf("reason = %q, want 'draining'", err.Error())
	}
}

func TestShutdownGate_SetEmptyReason(t *testing.T) {
	var g ShutdownGate
	g.Set("")
	p := g.Probe()

	err := p.Check(context.Background())
	if err == nil {
		t.Fatal("gate should be closed after Set")
	}
	if err.Error() != "draining" {
		t.Fatalf("empty reason should default to 'draining', got %q", err.Error())
	}
}

func TestShutdownGate_Clear(t *testing.T) {
	var g ShutdownGate
	g.Set("shutting down")

	// Verify closed
	p := g.Probe()
	if err := p.Check(context.Background()); err == nil {
		t.Fatal("should be closed")
	}

	// Clear and verify open
	g.Clear()
	if err := p.Check(context.Background()); err != nil {
		t.Fatalf("should be open after Clear, got %v", err)
	}
}

func TestShutdownGate_SetOverwritesReason(t *testing.T) {
	var g ShutdownGate
	g.Set("first reason")
	g.Set("second reason")
	p := g.Probe()

	err := p.Check(context.Background())
	if err.Error() != "second reason" {
		t.Fatalf("reason = %q, want 'second reason'", err.Error())
	}
}

func TestShutdownGate_ProbeReflectsCurrentState(t *testing.T) {
	var g ShutdownGate
	p := g.Probe() // get probe once, check it reflects changes

	// Initially open
	if err := p.Check(context.Background()); err != nil {
		t.Fatalf("should be open initially, got %v", err)
	}

	// Close
	g.Set("closing")
	if err := p.Check(context.Background()); err == nil {
		t.Fatal("should be closed after Set")
	}

	// Reopen
	g.Clear()
	if err := p.Check(context.Background()); err != nil {
		t.Fatalf("should be open after Clear, got %v", err)
	}
}

func TestShutdownGate_ConcurrentAccess(t *testing.T) {
	var g ShutdownGate
	p := g.Probe()

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(3)
		go func() {
			defer wg.Done()
			g.Set("draining")
		}()
		go func() {
			defer wg.Done()
			g.Clear()
		}()
		go func() {
			defer wg.Done()
			p.Check(context.Background()) // must not panic
		}()
	}
	wg.Wait()
}

// Composition

func TestAll_WithShutdownGate(t *testing.T) {
	var g ShutdownGate
	content := Fixed(true, "")

	p := All(g.Probe(), content)

	// Both pass
	if err := p.Check(context.Background()); err != nil {
		t.Fatalf("should pass when gate open and content ready, got %v", err)
	}

	// Gate closes
	g.Set("draining")
	err := p.Check(context.Background())
	if err == nil {
		t.Fatal("should fail when gate is closed")
	}
	if err.Error() != "draining" {
		t.Fatalf("reason = %q, want 'draining'", err.Error())
	}
}

func TestAll_WithShutdownGateAndContentCheck(t *testing.T) {
	var g ShutdownGate
	contentLoaded := false

	contentProbe := CheckFunc(func(ctx context.Context) error {
		if !contentLoaded {
			return fmt.Errorf("content: no active snapshot")
		}
		return nil
	})

	p := All(g.Probe(), contentProbe)

	// No content, gate open → fail (content)
	err := p.Check(context.Background())
	if err == nil || err.Error() != "content: no active snapshot" {
		t.Fatalf("should fail on content, got %v", err)
	}

	// Content loaded, gate open → pass
	contentLoaded = true
	if err := p.Check(context.Background()); err != nil {
		t.Fatalf("should pass, got %v", err)
	}

	// Content loaded, gate closed → fail (gate)
	g.Set("shutting down")
	err = p.Check(context.Background())
	if err == nil || err.Error() != "shutting down" {
		t.Fatalf("should fail on gate, got %v", err)
	}
}
