package log

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
)

// log.go - ParseLevel

func TestParseLevel_ValidLevels(t *testing.T) {
	tests := []struct {
		input string
		want  slog.Level
	}{
		{"debug", slog.LevelDebug},
		{"info", slog.LevelInfo},
		{"warn", slog.LevelWarn},
		{"error", slog.LevelError},
	}

	for _, tt := range tests {
		got, err := ParseLevel(tt.input)
		if err != nil {
			t.Errorf("ParseLevel(%q) error: %v", tt.input, err)
			continue
		}
		if got != tt.want {
			t.Errorf("ParseLevel(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestParseLevel_CaseInsensitive(t *testing.T) {
	tests := []struct {
		input string
		want  slog.Level
	}{
		{"DEBUG", slog.LevelDebug},
		{"Info", slog.LevelInfo},
		{"WARN", slog.LevelWarn},
		{"Error", slog.LevelError},
		{"DeBuG", slog.LevelDebug},
	}

	for _, tt := range tests {
		got, err := ParseLevel(tt.input)
		if err != nil {
			t.Errorf("ParseLevel(%q) error: %v", tt.input, err)
			continue
		}
		if got != tt.want {
			t.Errorf("ParseLevel(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestParseLevel_TrimsWhitespace(t *testing.T) {
	tests := []string{
		"  info  ",
		"\tinfo\t",
		" info",
		"info ",
		"\n info \n",
	}

	for _, input := range tests {
		got, err := ParseLevel(input)
		if err != nil {
			t.Errorf("ParseLevel(%q) error: %v", input, err)
			continue
		}
		if got != slog.LevelInfo {
			t.Errorf("ParseLevel(%q) = %v, want Info", input, got)
		}
	}
}

func TestParseLevel_Invalid(t *testing.T) {
	invalid := []string{
		"",
		"trace",
		"fatal",
		"critical",
		"verbose",
		"INFO!",
		"123",
		"info error",
	}

	for _, input := range invalid {
		_, err := ParseLevel(input)
		if err == nil {
			t.Errorf("ParseLevel(%q) should return error", input)
		}
	}
}

func TestParseLevel_ErrorMessage(t *testing.T) {
	_, err := ParseLevel("bogus")
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "bogus") {
		t.Errorf("error should contain the invalid input, got: %s", msg)
	}
	if !strings.Contains(msg, "debug") || !strings.Contains(msg, "info") || !strings.Contains(msg, "warn") || !strings.Contains(msg, "error") {
		t.Errorf("error should list valid levels, got: %s", msg)
	}
}

// log.go

func TestNew_ReturnsLogger(t *testing.T) {
	l, err := New(&Options{App: "test"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if l == nil {
		t.Fatal("New returned nil logger")
	}
}

func TestNew_LoggerImplementsInterface(t *testing.T) {
	l, err := New(&Options{App: "test", Writer: io.Discard})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// All interface methods should be callable without panic
	ctx := context.Background()
	l.Debug(ctx, "debug msg")
	l.Info(ctx, "info msg")
	l.Warn(ctx, "warn msg")
	l.Error(ctx, fmt.Errorf("test"), "error msg")

	child := l.With("key", "value")
	if child == nil {
		t.Fatal("With returned nil")
	}

	if err := l.Sync(); err != nil {
		t.Fatalf("Sync: %v", err)
	}

}
