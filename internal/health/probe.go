package health

import (
	"context"
	"sync/atomic"

	"github.com/keithlinneman/linnemanlabs-web/internal/xerrors"
)

// Probe is evaluated at request time
// nil = OK non-nil = FAIL with reason.
type Probe interface{ Check(context.Context) error }

// CheckFunc adapts a function into a Probe.
type CheckFunc func(context.Context) error

func (f CheckFunc) Check(ctx context.Context) error { return f(ctx) }

// Fixed returns a probe that always returns ok or fails with the given reason
func Fixed(ok bool, reason string) CheckFunc {
	if ok {
		return func(context.Context) error { return nil }
	}
	if reason == "" {
		reason = "unhealthy"
	}
	return func(context.Context) error { return xerrors.New(reason) }
}

// All is AND: passes only if all probes pass; returns the first error.
func All(ps ...Probe) CheckFunc {
	return func(ctx context.Context) error {
		for _, p := range ps {
			if p == nil {
				continue
			}
			if err := p.Check(ctx); err != nil {
				return err
			}
		}
		return nil
	}
}

// Any is OR: passes if any probe passes; otherwise returns the last error (or a generic one).
func Any(ps ...Probe) CheckFunc {
	return func(ctx context.Context) error {
		var last error
		ok := false
		for _, p := range ps {
			if p == nil {
				continue
			}
			if err := p.Check(ctx); err != nil {
				last = err
			} else {
				ok = true
			}
		}
		if ok {
			return nil
		}
		if last != nil {
			return last
		}
		return xerrors.New("no healthy probes")
	}
}

// ShutdownGate flips readiness to false during drain/shutdown.
type ShutdownGate struct {
	draining atomic.Bool
	reason   atomic.Value
}

func (g *ShutdownGate) Set(reason string) {
	g.draining.Store(true)
	g.reason.Store(reason)
}
func (g *ShutdownGate) Clear() {
	g.draining.Store(false)
	g.reason.Store("")
}
func (g *ShutdownGate) Probe() CheckFunc {
	return func(context.Context) error {
		if !g.draining.Load() {
			return nil
		}
		r, _ := g.reason.Load().(string)
		if r == "" {
			r = "draining"
		}
		return xerrors.New(r)
	}
}
