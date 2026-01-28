package log

import "context"

type Noop struct{}

func (Noop) With(...any) Logger                           { return Noop{} }
func (Noop) Debug(context.Context, string, ...any)        {}
func (Noop) Info(context.Context, string, ...any)         {}
func (Noop) Warn(context.Context, string, ...any)         {}
func (Noop) Error(context.Context, error, string, ...any) {}
func (Noop) Sync() error                                  { return nil }
