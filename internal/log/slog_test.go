package log

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel/trace"
)

// helpers

// newTestLogger builds a slogLogger writing to buf so we can inspect output.
func newTestLogger(t *testing.T, buf *bytes.Buffer, opts Options) *slogLogger {
	t.Helper()
	opts.Writer = buf
	l, err := newSlog(opts)
	if err != nil {
		t.Fatalf("newSlog: %v", err)
	}
	return l.(*slogLogger)
}

// jsonRecord parses one JSON log line (the last non-empty line in buf).
func jsonRecord(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	last := lines[len(lines)-1]
	var m map[string]any
	if err := json.Unmarshal([]byte(last), &m); err != nil {
		t.Fatalf("parse JSON log line: %v\nraw: %s", err, last)
	}
	return m
}

// newSlog construction

func TestNewSlog_DefaultWriter(t *testing.T) {
	// Should not error when Writer is nil (defaults to stdout)
	l, err := newSlog(Options{App: "test"})
	if err != nil {
		t.Fatalf("newSlog: %v", err)
	}
	if l == nil {
		t.Fatal("returned nil logger")
	}
}

func TestNewSlog_CustomWriter(t *testing.T) {
	var buf bytes.Buffer
	l := newTestLogger(t, &buf, Options{App: "myapp", JsonFormat: true, Level: slog.LevelInfo})

	l.Info(context.Background(), "hello")

	m := jsonRecord(t, &buf)
	if m["msg"] != "hello" {
		t.Fatalf("msg = %v, want hello", m["msg"])
	}
	if m["app"] != "myapp" {
		t.Fatalf("app = %v, want myapp", m["app"])
	}
}

func TestNewSlog_JsonFormat(t *testing.T) {
	var buf bytes.Buffer
	l := newTestLogger(t, &buf, Options{App: "test", JsonFormat: true, Level: slog.LevelInfo})

	l.Info(context.Background(), "json test")

	raw := buf.String()
	if !strings.Contains(raw, `"msg":"json test"`) {
		t.Fatalf("expected JSON output, got: %s", raw)
	}
}

func TestNewSlog_TextFormat(t *testing.T) {
	var buf bytes.Buffer
	l := newTestLogger(t, &buf, Options{App: "test", JsonFormat: false, Level: slog.LevelInfo})

	l.Info(context.Background(), "text test")

	raw := buf.String()
	// text format uses key=value pairs
	if !strings.Contains(raw, "msg=\"text test\"") && !strings.Contains(raw, "msg=text") {
		t.Fatalf("expected text output, got: %s", raw)
	}
}

func TestNewSlog_DefaultMaxErrorLinks(t *testing.T) {
	var buf bytes.Buffer
	l := newTestLogger(t, &buf, Options{App: "test"})

	if l.maxErrorLinks != 8 {
		t.Fatalf("maxErrorLinks = %d, want 8 (default)", l.maxErrorLinks)
	}
}

func TestNewSlog_CustomMaxErrorLinks(t *testing.T) {
	var buf bytes.Buffer
	l := newTestLogger(t, &buf, Options{App: "test", MaxErrorLinks: 20})

	if l.maxErrorLinks != 20 {
		t.Fatalf("maxErrorLinks = %d, want 20", l.maxErrorLinks)
	}
}

func TestNewSlog_DefaultStacktraceLevel(t *testing.T) {
	// When StacktraceLevel is 0, it should default to slog.LevelError
	var buf bytes.Buffer
	_ = newTestLogger(t, &buf, Options{App: "test"})
	// Can't directly inspect stackHandler level, but verify it doesn't panic
}

// Level filtering

func TestSlogLogger_LevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	l := newTestLogger(t, &buf, Options{App: "test", JsonFormat: true, Level: slog.LevelWarn})

	ctx := context.Background()

	l.Debug(ctx, "debug msg")
	l.Info(ctx, "info msg")
	if buf.Len() != 0 {
		t.Fatalf("debug/info should be filtered at warn level, got: %s", buf.String())
	}

	l.Warn(ctx, "warn msg")
	if !strings.Contains(buf.String(), "warn msg") {
		t.Fatalf("warn should pass, got: %s", buf.String())
	}

	buf.Reset()
	l.Error(ctx, fmt.Errorf("e"), "error msg")
	if !strings.Contains(buf.String(), "error msg") {
		t.Fatalf("error should pass, got: %s", buf.String())
	}
}

func TestSlogLogger_DebugLevel_AllPass(t *testing.T) {
	var buf bytes.Buffer
	l := newTestLogger(t, &buf, Options{App: "test", JsonFormat: true, Level: slog.LevelDebug})

	ctx := context.Background()
	l.Debug(ctx, "d")
	l.Info(ctx, "i")
	l.Warn(ctx, "w")
	l.Error(ctx, fmt.Errorf("e"), "e")

	out := buf.String()
	for _, msg := range []string{"d", "i", "w", "e"} {
		if !strings.Contains(out, fmt.Sprintf(`"msg":"%s"`, msg)) {
			t.Errorf("message %q not found at debug level", msg)
		}
	}
}

// With - copy-on-write

func TestSlogLogger_With_AddsAttrs(t *testing.T) {
	var buf bytes.Buffer
	l := newTestLogger(t, &buf, Options{App: "test", JsonFormat: true, Level: slog.LevelInfo})

	child := l.With("component", "api", "version", "v1")
	child.Info(context.Background(), "with test")

	m := jsonRecord(t, &buf)
	if m["component"] != "api" {
		t.Fatalf("component = %v, want api", m["component"])
	}
	if m["version"] != "v1" {
		t.Fatalf("version = %v, want v1", m["version"])
	}
}

func TestSlogLogger_With_CopyOnWrite(t *testing.T) {
	var buf bytes.Buffer
	l := newTestLogger(t, &buf, Options{App: "test", JsonFormat: true, Level: slog.LevelInfo})

	child := l.With("child_key", "child_val")

	// Parent should NOT have child's attrs
	buf.Reset()
	l.Info(context.Background(), "parent msg")
	m := jsonRecord(t, &buf)
	if _, found := m["child_key"]; found {
		t.Fatal("parent logger should not have child's attributes")
	}

	// Child should have it
	buf.Reset()
	child.Info(context.Background(), "child msg")
	m = jsonRecord(t, &buf)
	if m["child_key"] != "child_val" {
		t.Fatalf("child missing child_key, got: %v", m)
	}
}

func TestSlogLogger_With_Chaining(t *testing.T) {
	var buf bytes.Buffer
	l := newTestLogger(t, &buf, Options{App: "test", JsonFormat: true, Level: slog.LevelInfo})

	deep := l.With("a", 1).With("b", 2).With("c", 3)
	deep.Info(context.Background(), "deep")

	m := jsonRecord(t, &buf)
	// All accumulated attrs should be present
	if m["a"] != float64(1) || m["b"] != float64(2) || m["c"] != float64(3) {
		t.Fatalf("chained attrs missing, got: %v", m)
	}
}

func TestSlogLogger_With_OddArgs(t *testing.T) {
	var buf bytes.Buffer
	l := newTestLogger(t, &buf, Options{App: "test", JsonFormat: true, Level: slog.LevelInfo})

	// Odd kv args - orphan key should be dropped, not panic
	child := l.With("key1", "val1", "orphan")
	child.Info(context.Background(), "odd args")

	m := jsonRecord(t, &buf)
	if m["key1"] != "val1" {
		t.Fatalf("key1 missing, got: %v", m)
	}
}

func TestSlogLogger_With_NonStringKey(t *testing.T) {
	var buf bytes.Buffer
	l := newTestLogger(t, &buf, Options{App: "test", JsonFormat: true, Level: slog.LevelInfo})

	// Non-string key should be skipped
	child := l.With(42, "val", "real_key", "real_val")
	child.Info(context.Background(), "non-string key")

	m := jsonRecord(t, &buf)
	if m["real_key"] != "real_val" {
		t.Fatalf("real_key missing")
	}
}

func TestSlogLogger_With_PreservesConfig(t *testing.T) {
	var buf bytes.Buffer
	l := newTestLogger(t, &buf, Options{App: "test", IncludeErrorLinks: true, MaxErrorLinks: 5})

	child := l.With("k", "v").(*slogLogger)

	if child.includeErrorLinks != true {
		t.Fatal("includeErrorLinks not preserved in With child")
	}
	if child.maxErrorLinks != 5 {
		t.Fatal("maxErrorLinks not preserved in With child")
	}
}

// Error enrichment

func TestSlogLogger_Error_EnrichesWithType(t *testing.T) {
	var buf bytes.Buffer
	l := newTestLogger(t, &buf, Options{App: "test", JsonFormat: true, Level: slog.LevelError})

	l.Error(context.Background(), fmt.Errorf("test error"), "something failed")

	m := jsonRecord(t, &buf)
	if m["err"] == nil {
		t.Fatal("err field missing")
	}
	if m["error_type"] == nil {
		t.Fatal("error_type field missing")
	}
	if m["cause_type"] == nil {
		t.Fatal("cause_type field missing")
	}
}

func TestSlogLogger_Error_NilError(t *testing.T) {
	var buf bytes.Buffer
	l := newTestLogger(t, &buf, Options{App: "test", JsonFormat: true, Level: slog.LevelError})

	// nil error should still log but without err enrichment
	l.Error(context.Background(), nil, "nil error msg")

	m := jsonRecord(t, &buf)
	if m["msg"] != "nil error msg" {
		t.Fatalf("msg = %v", m["msg"])
	}
	if _, found := m["err"]; found {
		t.Fatal("err field should not be present for nil error")
	}
}

func TestSlogLogger_Error_IncludesChain(t *testing.T) {
	var buf bytes.Buffer
	l := newTestLogger(t, &buf, Options{App: "test", JsonFormat: true, Level: slog.LevelError})

	inner := fmt.Errorf("root cause")
	wrapped := fmt.Errorf("outer: %w", inner)

	l.Error(context.Background(), wrapped, "wrapped error")

	m := jsonRecord(t, &buf)
	chain, ok := m["error_chain"]
	if !ok {
		t.Fatal("error_chain missing")
	}
	// Should be an array with at least 2 entries
	arr, ok := chain.([]any)
	if !ok {
		t.Fatalf("error_chain type = %T", chain)
	}
	if len(arr) < 2 {
		t.Fatalf("error_chain length = %d, want >= 2", len(arr))
	}
}

func TestSlogLogger_Error_ErrorLinks_Disabled(t *testing.T) {
	var buf bytes.Buffer
	l := newTestLogger(t, &buf, Options{
		App:               "test",
		JsonFormat:        true,
		Level:             slog.LevelError,
		IncludeErrorLinks: false,
	})

	l.Error(context.Background(), fmt.Errorf("test"), "msg")

	m := jsonRecord(t, &buf)
	if _, found := m["error_links"]; found {
		t.Fatal("error_links should not be present when disabled")
	}
}

func TestSlogLogger_Error_ErrorLinks_Enabled(t *testing.T) {
	var buf bytes.Buffer
	l := newTestLogger(t, &buf, Options{
		App:               "test",
		JsonFormat:        true,
		Level:             slog.LevelError,
		IncludeErrorLinks: true,
		MaxErrorLinks:     8,
	})

	l.Error(context.Background(), fmt.Errorf("test"), "msg")

	m := jsonRecord(t, &buf)
	if _, found := m["error_links"]; !found {
		t.Fatal("error_links should be present when enabled")
	}
}

func TestSlogLogger_Error_ExtraKV(t *testing.T) {
	var buf bytes.Buffer
	l := newTestLogger(t, &buf, Options{App: "test", JsonFormat: true, Level: slog.LevelError})

	l.Error(context.Background(), fmt.Errorf("e"), "msg", "custom_key", "custom_val")

	m := jsonRecord(t, &buf)
	if m["custom_key"] != "custom_val" {
		t.Fatalf("custom_key = %v, want custom_val", m["custom_key"])
	}
}

// Sync

func TestSlogLogger_Sync(t *testing.T) {
	var buf bytes.Buffer
	l := newTestLogger(t, &buf, Options{App: "test"})

	if err := l.Sync(); err != nil {
		t.Fatalf("Sync: %v", err)
	}
}

// KV in log calls

func TestSlogLogger_Info_WithKV(t *testing.T) {
	var buf bytes.Buffer
	l := newTestLogger(t, &buf, Options{App: "test", JsonFormat: true, Level: slog.LevelInfo})

	l.Info(context.Background(), "test msg", "key1", "val1", "key2", 42)

	m := jsonRecord(t, &buf)
	if m["key1"] != "val1" {
		t.Fatalf("key1 = %v", m["key1"])
	}
	if m["key2"] != float64(42) {
		t.Fatalf("key2 = %v", m["key2"])
	}
}

func TestSlogLogger_Warn_WithKV(t *testing.T) {
	var buf bytes.Buffer
	l := newTestLogger(t, &buf, Options{App: "test", JsonFormat: true, Level: slog.LevelWarn})

	l.Warn(context.Background(), "warning", "severity", "high")

	m := jsonRecord(t, &buf)
	if m["severity"] != "high" {
		t.Fatalf("severity = %v", m["severity"])
	}
}

// addKV

func newRecord() slog.Record {
	return slog.NewRecord(time.Now(), slog.LevelInfo, "test", 0)
}

func countAttrs(r slog.Record) int {
	n := 0
	r.Attrs(func(a slog.Attr) bool { n++; return true })
	return n
}

func TestAddKV_Basic(t *testing.T) {
	r := newRecord()
	addKV(&r, []any{"k1", "v1", "k2", 99})

	if c := countAttrs(r); c != 2 {
		t.Fatalf("attrs count = %d, want 2", c)
	}

	var attrs []slog.Attr
	r.Attrs(func(a slog.Attr) bool {
		attrs = append(attrs, a)
		return true
	})
	if attrs[0].Key != "k1" || attrs[0].Value.String() != "v1" {
		t.Fatalf("first attr = %v", attrs[0])
	}
}

func TestAddKV_OddArgs(t *testing.T) {
	r := newRecord()
	addKV(&r, []any{"k1", "v1", "orphan"})

	if c := countAttrs(r); c != 1 {
		t.Fatalf("attrs count = %d, want 1 (orphan dropped)", c)
	}
}

func TestAddKV_NonStringKey(t *testing.T) {
	r := newRecord()
	addKV(&r, []any{42, "val", "real", "val2"})

	if c := countAttrs(r); c != 1 {
		t.Fatalf("attrs count = %d, want 1 (non-string key skipped)", c)
	}
}

func TestAddKV_Empty(t *testing.T) {
	r := newRecord()
	addKV(&r, []any{})
	addKV(&r, nil)
	// Should not panic
}

// otelHandler

func TestOtelHandler_AddsTraceFields(t *testing.T) {
	var buf bytes.Buffer
	l := newTestLogger(t, &buf, Options{App: "test", JsonFormat: true, Level: slog.LevelInfo})

	traceID, _ := trace.TraceIDFromHex("0102030405060708090a0b0c0d0e0f10")
	spanID, _ := trace.SpanIDFromHex("0102030405060708")
	sc := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    traceID,
		SpanID:     spanID,
		TraceFlags: trace.FlagsSampled,
	})
	ctx := trace.ContextWithSpanContext(context.Background(), sc)

	l.Info(ctx, "traced msg")

	m := jsonRecord(t, &buf)
	if m["trace_id"] != "0102030405060708090a0b0c0d0e0f10" {
		t.Fatalf("trace_id = %v", m["trace_id"])
	}
	if m["span_id"] != "0102030405060708" {
		t.Fatalf("span_id = %v", m["span_id"])
	}
}

func TestOtelHandler_NoTrace(t *testing.T) {
	var buf bytes.Buffer
	l := newTestLogger(t, &buf, Options{App: "test", JsonFormat: true, Level: slog.LevelInfo})

	l.Info(context.Background(), "no trace")

	m := jsonRecord(t, &buf)
	if _, found := m["trace_id"]; found {
		t.Fatal("trace_id should not be present without valid span context")
	}
}

// stackHandler

func TestStackHandler_AddsStackAtErrorLevel(t *testing.T) {
	var buf bytes.Buffer
	l := newTestLogger(t, &buf, Options{
		App:        "test",
		JsonFormat: true,
		Level:      slog.LevelError,
		// StacktraceLevel defaults to Error
	})

	l.Error(context.Background(), fmt.Errorf("boom"), "error with stack")

	m := jsonRecord(t, &buf)
	stack, ok := m["stack"]
	if !ok {
		t.Fatal("stack field missing at error level")
	}
	s, ok := stack.(string)
	if !ok || s == "" {
		t.Fatal("stack should be a non-empty string")
	}
}

func TestStackHandler_NoStackBelowLevel(t *testing.T) {
	var buf bytes.Buffer
	l := newTestLogger(t, &buf, Options{
		App:             "test",
		JsonFormat:      true,
		Level:           slog.LevelInfo,
		StacktraceLevel: slog.LevelError,
	})

	l.Info(context.Background(), "info msg")

	m := jsonRecord(t, &buf)
	if _, found := m["stack"]; found {
		t.Fatal("stack should not be present at info level")
	}
}

// errorChain

func TestErrorChain_SingleError(t *testing.T) {
	err := fmt.Errorf("single")
	chain := errorChain(err)

	if len(chain) != 1 {
		t.Fatalf("chain length = %d, want 1", len(chain))
	}
	if chain[0] != "single" {
		t.Fatalf("chain[0] = %q", chain[0])
	}
}

func TestErrorChain_WrappedError(t *testing.T) {
	inner := fmt.Errorf("root")
	outer := fmt.Errorf("wrap: %w", inner)

	chain := errorChain(outer)

	if len(chain) < 2 {
		t.Fatalf("chain length = %d, want >= 2", len(chain))
	}
	if chain[0] != "wrap: root" {
		t.Fatalf("chain[0] = %q", chain[0])
	}
	if chain[len(chain)-1] != "root" {
		t.Fatalf("chain[last] = %q", chain[len(chain)-1])
	}
}

func TestErrorChain_DeduplicatesIdenticalMessages(t *testing.T) {
	err := fmt.Errorf("same")
	// A single error with no wrapping should produce exactly one entry
	chain := errorChain(err)

	for i := 1; i < len(chain); i++ {
		if chain[i] == chain[i-1] {
			t.Fatalf("duplicate consecutive message at index %d: %q", i, chain[i])
		}
	}
}

func TestErrorChain_JoinedErrors(t *testing.T) {
	e1 := fmt.Errorf("first")
	e2 := fmt.Errorf("second")
	joined := errors.Join(e1, e2)

	chain := errorChain(joined)

	if len(chain) == 0 {
		t.Fatal("chain should not be empty for joined errors")
	}
}

func TestErrorChain_NilError(t *testing.T) {
	chain := errorChain(nil)
	if len(chain) != 0 {
		t.Fatalf("chain for nil error = %v, want empty", chain)
	}
}

// classifyTypes

func TestClassifyTypes_NilError(t *testing.T) {
	surface, root := classifyTypes(nil)
	if surface != "" || root != "" {
		t.Fatalf("classifyTypes(nil) = (%q, %q), want empty", surface, root)
	}
}

func TestClassifyTypes_SimpleError(t *testing.T) {
	err := fmt.Errorf("simple")
	surface, root := classifyTypes(err)

	if surface == "" {
		t.Fatal("surface type should not be empty")
	}
	if root == "" {
		t.Fatal("root type should not be empty")
	}
}

func TestClassifyTypes_WrappedError(t *testing.T) {
	inner := &customError{msg: "inner"}
	outer := fmt.Errorf("outer: %w", inner)

	surface, root := classifyTypes(outer)

	// Surface should skip the fmt.wrapError and find customError
	if !strings.Contains(surface, "customError") {
		t.Fatalf("surface = %q, expected customError", surface)
	}
	// Root should be customError (innermost)
	if !strings.Contains(root, "customError") {
		t.Fatalf("root = %q, expected customError", root)
	}
}

type customError struct {
	msg string
}

func (e *customError) Error() string { return e.msg }

// chainLinks

func TestChainLinks_SingleError(t *testing.T) {
	err := fmt.Errorf("single")
	links := chainLinks(err, 8)

	if len(links) == 0 {
		t.Fatal("links should not be empty")
	}
	if links[0]["msg"] != "single" {
		t.Fatalf("links[0][msg] = %v", links[0]["msg"])
	}
}

func TestChainLinks_RespectsMax(t *testing.T) {
	// Build a deep chain
	err := fmt.Errorf("base")
	for i := 0; i < 20; i++ {
		err = fmt.Errorf("wrap %d: %w", i, err)
	}

	links := chainLinks(err, 5)
	if len(links) > 5 {
		t.Fatalf("links length = %d, max should be 5", len(links))
	}
}

func TestChainLinks_ZeroMax(t *testing.T) {
	err := fmt.Errorf("base")
	for i := 0; i < 5; i++ {
		err = fmt.Errorf("wrap %d: %w", i, err)
	}

	// max <= 0 means unlimited
	links := chainLinks(err, 0)
	if len(links) == 0 {
		t.Fatal("unlimited max should produce links")
	}
}

func TestChainLinks_NilError(t *testing.T) {
	links := chainLinks(nil, 8)
	if len(links) != 0 {
		t.Fatalf("links for nil = %v, want empty", links)
	}
}

// frameFromPC

func TestFrameFromPC_ZeroPC(t *testing.T) {
	_, _, _, ok := frameFromPC(0)
	if ok {
		t.Fatal("frameFromPC(0) should return ok=false")
	}
}

// firstExtFrame

func TestFirstExtFrame_EmptyPCs(t *testing.T) {
	_, _, _, ok := firstExtFrame(nil)
	if ok {
		t.Fatal("firstExtFrame(nil) should return ok=false")
	}
}
