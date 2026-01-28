package log

import (
	"context"
)

// ctxKey is an unexported key type to avoid collisions in context
type ctxKey struct{}

// WithContext returns a new context that carries the given Logger
func WithContext(ctx context.Context, l Logger) context.Context {
	return context.WithValue(ctx, ctxKey{}, l)
}

// FromContext returns the Logger stored in ctx, or a fallback if none is present
func FromContext(ctx context.Context) Logger {
	if v := ctx.Value(ctxKey{}); v != nil {
		if l, ok := v.(Logger); ok && l != nil {
			return l
		}
	}
	//   - Nop()     no-op logger, safe but silent
	//   - Default() global app logger, if it exists
	return Nop()
}
