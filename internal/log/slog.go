package log

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"reflect"
	"runtime"
	"strings"
	"time"

	"go.opentelemetry.io/otel/trace"
)

type slogLogger struct {
	h                 slog.Handler
	attrs             []slog.Attr
	includeErrorLinks bool
	maxErrorLinks     int
}

type hasPC interface {
	PC() uintptr
}

type hasStack interface {
	StackPCs() []uintptr
}

func newSlog(opts Options) (Logger, error) {
	w := opts.Writer
	if w == nil {
		w = os.Stdout
	}

	// enable stack data enrichment if log level > StacktraceLevel app option
	if opts.StacktraceLevel == 0 {
		opts.StacktraceLevel = slog.LevelError
	}

	// json or logfmt
	var h slog.Handler
	if opts.JsonFormat {
		h = slog.NewJSONHandler(w, &slog.HandlerOptions{Level: opts.Level, AddSource: true})
	} else {
		h = slog.NewTextHandler(w, &slog.HandlerOptions{Level: opts.Level, AddSource: true})
	}

	// enrich with otel data
	h = otelHandler{next: h}

	// enrich with stack data
	h = stackHandler{next: h, level: opts.StacktraceLevel}

	// enrich with attributes
	baseAttrs := []slog.Attr{
		slog.String("app", opts.App),
	}

	if opts.MaxErrorLinks <= 0 {
		opts.MaxErrorLinks = 8
	}
	return &slogLogger{
		h:                 h,
		attrs:             baseAttrs,
		includeErrorLinks: opts.IncludeErrorLinks,
		maxErrorLinks:     opts.MaxErrorLinks,
	}, nil
}

func (s *slogLogger) With(kv ...any) Logger {
	add := make([]slog.Attr, 0, len(kv)/2)
	for i := 0; i+1 < len(kv); i += 2 {
		if k, ok := kv[i].(string); ok {
			add = append(add, slog.Any(k, kv[i+1]))
		}
	}
	// copy-on-write so loggers are safe to share concurrently
	next := make([]slog.Attr, 0, len(s.attrs)+len(add))
	next = append(next, s.attrs...)
	next = append(next, add...)
	return &slogLogger{
		h:                 s.h,
		attrs:             next,
		includeErrorLinks: s.includeErrorLinks,
		maxErrorLinks:     s.maxErrorLinks,
	}
}
func (s *slogLogger) Debug(ctx context.Context, msg string, kv ...any) {
	s.logWithPC(ctx, slog.LevelDebug, msg, kv...)
}
func (s *slogLogger) Info(ctx context.Context, msg string, kv ...any) {
	s.logWithPC(ctx, slog.LevelInfo, msg, kv...)
}
func (s *slogLogger) Warn(ctx context.Context, msg string, kv ...any) {
	s.logWithPC(ctx, slog.LevelWarn, msg, kv...)
}
func (s *slogLogger) Error(ctx context.Context, err error, msg string, kv ...any) {
	if err != nil {
		surface, root := classifyTypes(err)
		kv = append(kv,
			"err", err,
			"error_type", surface,
			"cause_type", root,
		)
		if chain := errorChain(err); len(chain) > 0 {
			kv = append(kv, "error_chain", chain)
		}
		if s.includeErrorLinks {
			kv = append(kv, "error_links", chainLinks(err, s.maxErrorLinks))
		}
	}
	s.logWithPC(ctx, slog.LevelError, msg, kv...)
}
func (s *slogLogger) Sync() error { return nil }

// for skipping past log handlers
func callerPC(skip int) uintptr {
	var pcs [1]uintptr
	if n := runtime.Callers(skip, pcs[:]); n == 0 {
		return 0
	}
	return pcs[0]
}

func addKV(r *slog.Record, kv []any) {
	for i := 0; i+1 < len(kv); i += 2 {
		k, ok := kv[i].(string)
		if !ok {
			continue
		}
		r.AddAttrs(slog.Any(k, kv[i+1]))
	}
}

func (s *slogLogger) logWithPC(ctx context.Context, lvl slog.Level, msg string, kv ...any) {
	// Respect log level: skip if handler says this level is disabled.
	if !s.h.Enabled(ctx, lvl) {
		return
	}
	const skip = 4
	pc := callerPC(skip)
	r := slog.NewRecord(time.Now(), lvl, msg, pc)
	// add persistent attrs
	for _, a := range s.attrs {
		r.AddAttrs(a)
	}

	addKV(&r, kv)
	_ = s.h.Handle(ctx, r)
}

// for otel enrichment
type otelHandler struct{ next slog.Handler }

func (h otelHandler) Enabled(ctx context.Context, lvl slog.Level) bool {
	return h.next.Enabled(ctx, lvl)
}
func (h otelHandler) Handle(ctx context.Context, r slog.Record) error {
	if sc := trace.SpanContextFromContext(ctx); sc.IsValid() {
		r.AddAttrs(
			slog.String("trace_id", sc.TraceID().String()),
			slog.String("span_id", sc.SpanID().String()),
		)
	}
	return h.next.Handle(ctx, r)
}
func (h otelHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return otelHandler{next: h.next.WithAttrs(attrs)}
}
func (h otelHandler) WithGroup(name string) slog.Handler {
	return otelHandler{next: h.next.WithGroup(name)}
}

// for stack trace enrichment
type stackHandler struct {
	next  slog.Handler
	level slog.Level
}

func (h stackHandler) Enabled(ctx context.Context, lvl slog.Level) bool {
	return h.next.Enabled(ctx, lvl)
}
func (h stackHandler) Handle(ctx context.Context, r slog.Record) error {

	if r.Level >= h.level {
		// try to pull a captured stack off the error attr
		var pcs []uintptr
		r.Attrs(func(a slog.Attr) bool {
			if a.Key == "err" {
				if hs, ok := a.Value.Any().(hasStack); ok && hs != nil {
					pcs = hs.StackPCs()
					return false
				}
			}
			return true
		})

		if len(pcs) > 0 {
			r.AddAttrs(slog.String("stack", renderPCs(pcs)))
		} else {
			r.AddAttrs(slog.String("stack", captureCleanStack()))
		}
	}
	return h.next.Handle(ctx, r)
}
func (h stackHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return stackHandler{next: h.next.WithAttrs(attrs), level: h.level}
}
func (h stackHandler) WithGroup(name string) slog.Handler {
	return stackHandler{next: h.next.WithGroup(name), level: h.level}
}
func captureCleanStack() string {
	const maxDepth = 64
	pcs := make([]uintptr, maxDepth)
	// skip: runtime.Callers, captureCleanStack, stackHandler.Handle
	n := runtime.Callers(3, pcs)
	frames := runtime.CallersFrames(pcs[:n])

	var b strings.Builder
	include := false
	for {
		fr, more := frames.Next()
		if !more {
			break
		}
		inRuntime := strings.HasPrefix(fr.Function, "runtime.")
		inSlog := strings.HasPrefix(fr.Function, "log/slog.")
		inOurLog := strings.Contains(fr.Function, "/internal/log.")
		if inRuntime {
			break
		}
		if !include && !inRuntime && !inSlog && !inOurLog {
			include = true
		}
		if include {
			fmt.Fprintf(&b, "%s\n\t%s:%d\n", fr.Function, fr.File, fr.Line)
		}
	}
	return strings.TrimSpace(b.String())
}

func errorChain(err error) []string {
	out := make([]string, 0, 8)
	var prev string
	for e := err; e != nil; e = errors.Unwrap(e) {
		msg := e.Error()
		if msg != prev {
			out = append(out, msg)
			prev = msg
		}
	}

	// handle errors.Join(...)
	type multi interface{ Unwrap() []error }
	if m, ok := any(err).(multi); ok {
		for _, e := range m.Unwrap() {
			if s := e.Error(); s != prev {
				out = append(out, s)
				prev = s
			}
		}
	}
	return out
}

func chainLinks(err error, max int) []map[string]any {
	links := make([]map[string]any, 0, 8)
	depth := 0
	for e := err; e != nil && (max <= 0 || depth < max); e = errors.Unwrap(e) {
		link := map[string]any{"msg": e.Error()}
		havePos := false

		// prefer a single-frame PC (from Wrap/New)...
		if hp, ok := any(e).(hasPC); ok {
			if fn, file, line, ok := frameFromPC(hp.PC()); ok {
				link["func"], link["file"], link["line"] = fn, file, line
				havePos = true
			}
		} else if hs, ok := any(e).(hasStack); ok {
			// use the first external frame from a captured stack, (EnsureTrace) otherwise
			if fn, file, line, ok := firstExtFrame(hs.StackPCs()); ok {
				link["func"], link["file"], link["line"] = fn, file, line
				havePos = true
			}
		}
		if depth == 0 || havePos {
			links = append(links, link)
		}
		depth++
	}
	return links
}

// render PCs from error stack collections into func:file:line lines
func renderPCs(pcs []uintptr) string {
	frames := runtime.CallersFrames(pcs)
	var b strings.Builder
	include := false
	for {
		fr, more := frames.Next()
		if !more {
			break
		}
		inRuntime := strings.HasPrefix(fr.Function, "runtime.")
		inSlog := strings.HasPrefix(fr.Function, "log/slog.")
		inOurLog := strings.Contains(fr.Function, "/internal/log.")
		if inRuntime {
			break
		}
		if !include && !inRuntime && !inSlog && !inOurLog {
			include = true
		}
		if include {
			fmt.Fprintf(&b, "%s\n\t%s:%d\n", fr.Function, fr.File, fr.Line)
		}
	}
	return b.String()
}

// for error_links with no PC at call site
func frameFromPC(pc uintptr) (fn, file string, line int, ok bool) {
	if pc == 0 {
		return "", "", 0, false
	}
	fr, _ := runtime.CallersFrames([]uintptr{pc}).Next()
	return fr.Function, fr.File, fr.Line, true
}

func firstExtFrame(pcs []uintptr) (fn, file string, line int, ok bool) {
	if len(pcs) == 0 {
		return "", "", 0, false
	}
	frames := runtime.CallersFrames(pcs)
	for {
		fr, more := frames.Next()
		inRuntime := strings.HasPrefix(fr.Function, "runtime.")
		inSlog := strings.HasPrefix(fr.Function, "log/slog.")
		inOurLog := strings.Contains(fr.Function, "/internal/log.")
		inXerr := strings.Contains(fr.Function, "/internal/xerrors.")
		if !inRuntime && !inSlog && !inOurLog && !inXerr {
			return fr.Function, fr.File, fr.Line, true
		}
		if !more {
			break
		}
	}
	return "", "", 0, false
}

// preserve error type
func classifyTypes(err error) (surface, root string) {
	if err == nil {
		return "", ""
	}

	// surface = first non-wrapper type in the chain.
	for e := err; e != nil; e = errors.Unwrap(e) {
		if t := reflect.TypeOf(e); t != nil {
			u := t
			for u.Kind() == reflect.Ptr {
				u = u.Elem()
			}
			pkg := u.PkgPath()
			name := u.Name()

			// Skip our own xerrors wrappers.
			if strings.Contains(pkg, "/internal/xerrors") {
				continue
			}
			// Skip fmt.Errorf wrappers.
			if pkg == "fmt" && name == "wrapError" {
				continue
			}

			surface = t.String()
			break
		}
	}

	if surface == "" {
		// fallback if everything was wrappers.
		surface = fmt.Sprintf("%T", err)
	}

	// root is last in the chain.
	var last error
	for e := err; e != nil; e = errors.Unwrap(e) {
		last = e
	}
	if last != nil {
		root = fmt.Sprintf("%T", last)
	}

	return surface, root
}
