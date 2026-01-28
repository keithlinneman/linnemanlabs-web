package log

import "context"

// nopLogger implements Logger but does nothing for mock or testing
type nopLogger struct{}

func (nopLogger) Debug(ctx context.Context, msg string, kv ...any) {}

func (nopLogger) Info(ctx context.Context, msg string, kv ...any) {}

func (nopLogger) Warn(ctx context.Context, msg string, kv ...any) {}

func (nopLogger) Error(ctx context.Context, err error, msg string, kv ...any) {}

func (nopLogger) Sync() error { return nil }

// with just returns itself, extra fields are ignored
func (n nopLogger) With(kv ...any) Logger { return n }

// Nop returns a no-op Logger.
func Nop() Logger { return nopLogger{} }
