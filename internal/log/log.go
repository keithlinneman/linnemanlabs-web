package log

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
)

type Logger interface {
	With(kv ...any) Logger

	Debug(ctx context.Context, msg string, kv ...any)
	Info(ctx context.Context, msg string, kv ...any)
	Warn(ctx context.Context, msg string, kv ...any)
	Error(ctx context.Context, err error, msg string, kv ...any)

	Sync() error
}

type Options struct {
	App               string
	Version           string
	Commit            string
	BuildId           string
	Level             slog.Level
	StacktraceLevel   slog.Level
	JsonFormat        bool
	MaxErrorLinks     int
	IncludeErrorLinks bool
	Writer            io.Writer
}

func New(opts Options) (Logger, error) { return newSlog(opts) }

func ParseLevel(s string) (slog.Level, error) {
	x := strings.ToLower(strings.TrimSpace(s))
	switch x {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("unknown log level %s (valid levels are debug|info|warn|error)", s)
	}
}
