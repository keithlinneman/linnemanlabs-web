package httpmw

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/keithlinneman/linnemanlabs-web/internal/log"
)

// responseWriter wraps http.ResponseWriter to capture status and bytes written
type responseWriter struct {
	http.ResponseWriter
	status int
	bytes  int64

	// response.write span (starts on first WriteHeader/Write)
	ctx      context.Context
	reqStart time.Time

	writeSpan        trace.Span
	writeSpanStarted bool
	firstWriteAt     time.Duration
	writeBlocked     time.Duration
	writeErr         error
}

func (rw *responseWriter) ensureWriteSpan() {
	if rw.writeSpanStarted {
		return
	}
	rw.writeSpanStarted = true
	rw.firstWriteAt = time.Since(rw.reqStart)

	parent := trace.SpanFromContext(rw.ctx)
	if parent == nil || !parent.IsRecording() {
		return
	}

	tracer := otel.Tracer("linnemanlabs/httpmw")
	rw.ctx, rw.writeSpan = tracer.Start(rw.ctx, "response.write",
		trace.WithAttributes(
			attribute.Float64("http.server.ttfb_seconds", float64(rw.firstWriteAt.Seconds())),
		),
	)
}

func (rw *responseWriter) finishWriteSpan() {
	if rw.writeSpan == nil {
		return
	}

	status := rw.status
	if status == 0 {
		status = http.StatusOK
	}

	rw.writeSpan.SetAttributes(
		attribute.Int("http.response.status_code", status),
		attribute.Int64("http.response.body.size", rw.bytes),
		attribute.Float64("http.server.write.block_seconds", float64(rw.writeBlocked.Seconds())),
	)
	if rw.writeErr != nil {
		rw.writeSpan.RecordError(rw.writeErr)
		rw.writeSpan.SetStatus(codes.Error, rw.writeErr.Error())
	}
	rw.writeSpan.End()
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.ensureWriteSpan()
	rw.status = code
	start := time.Now()
	rw.ResponseWriter.WriteHeader(code)
	rw.writeBlocked += time.Since(start)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	rw.ensureWriteSpan()
	// If WriteHeader hasn't been called yet, default to 200.
	if rw.status == 0 {
		rw.status = http.StatusOK
	}
	// n, err := rw.ResponseWriter.Write(b)
	start := time.Now()
	n, err := rw.ResponseWriter.Write(b)
	rw.writeBlocked += time.Since(start)
	rw.bytes += int64(n)
	if err != nil && rw.writeErr == nil {
		rw.writeErr = err
	}
	return n, err
}

// support Flush if the underlying writer does.
func (rw *responseWriter) Flush() {
	if f, ok := rw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// support Hijack (websockets, etc).
func (rw *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := rw.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("underlying ResponseWriter does not implement http.Hijacker")
	}
	return h.Hijack()
}

func WithLogger(base log.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			//start := time.Now()
			ctx := r.Context()

			// Request ID from our RequestID middleware (outer)
			reqID := RequestIDFromContext(ctx)

			// Prefer X-Forwarded-For when behind ALB
			clientAddr := r.RemoteAddr
			if xf := r.Header.Get("X-Forwarded-For"); xf != "" {
				parts := strings.Split(xf, ",")
				if len(parts) > 0 {
					clientAddr = strings.TrimSpace(parts[0])
				}
			}
			// Normalize peer address to IP only (no port)
			peerAddr := r.RemoteAddr
			if host, _, err := net.SplitHostPort(peerAddr); err == nil {
				peerAddr = host
			}

			// Set HTTP scheme
			scheme := schemeFromRequest(r)
			host := r.Host
			rawQuery := r.URL.RawQuery

			// Trace ID from OTel, if present
			//var traceID string
			if span := trace.SpanFromContext(ctx); span != nil {
				if sc := span.SpanContext(); sc.IsValid() {
					//traceID = sc.TraceID().String()
					span.SetAttributes(
						attribute.String("request_id", reqID),
						attribute.String("server.address", r.Host),
						attribute.String("client.address", clientAddr),
						attribute.String("network.peer.address", peerAddr), // ALB IP
						attribute.String("url.scheme", scheme),
					)
				}
				if rawQuery != "" {
					span.SetAttributes(
						attribute.String("url.query", rawQuery),
					)
				}
			}

			fields := []any{
				"request_id", reqID,
				"client.address", clientAddr,
				"network.peer.address", peerAddr,
				"server.address", host,
				"http.request.method", r.Method,
				"url.path", r.URL.Path,
				"url.scheme", scheme,
				//"trace_id", traceID,
			}
			if rawQuery != "" {
				fields = append(fields, "url.query", rawQuery)
			}

			L := base.With(fields...)
			ctx = log.WithContext(ctx, L)
			r = r.WithContext(ctx)

			next.ServeHTTP(w, r)
		})
	}
}

func AccessLog() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			var reqBodySize int64
			if r.ContentLength > 0 {
				reqBodySize = r.ContentLength
			}

			rw := &responseWriter{
				ResponseWriter: w,
				ctx:            r.Context(),
				reqStart:       start,
			}

			next.ServeHTTP(rw, r)

			// child span that captures time blocked on writing the response to the client
			rw.finishWriteSpan()

			// after handler: pull latest context (with user/tenant/route attached)
			ctx := r.Context()

			L := log.FromContext(ctx)
			if L == nil {
				// no logger in context: nothing to do
				return
			}

			ext := strings.ToLower(path.Ext(r.URL.Path))
			switch ext {
			case ".css", ".js", ".png", ".jpg", ".jpeg", ".webp", ".svg", ".ico", ".woff", ".woff2", ".map":
				return // skip logging, will ship these to clickhouse or s3 separately soon
			}

			duration := time.Since(start)

			status := rw.status
			if status == 0 {
				status = http.StatusOK
			}

			// skip health endpoints
			if r.URL.Path == "/-/ready" || r.URL.Path == "/-/healthy" {
				return
			}

			// get route pattern for http.route
			routePat := ""
			if rc := chi.RouteContext(ctx); rc != nil {
				routePat = rc.RoutePattern()
			}
			if routePat == "" {
				routePat = r.URL.Path
			}

			L.Info(ctx, "http request",
				"http.response.status_code", status,
				"http.server.request.duration", duration.Seconds(),
				"http.response.body.size", rw.bytes,
				"http.request.body.size", reqBodySize,
				"http.route", routePat,
			)
		})
	}
}

func schemeFromRequest(r *http.Request) string {
	// 1. Try X-Forwarded-Proto (what ALB sets)
	// todo: should check if request came from internal alb ip first, otherwise need to be very careful with this
	if xf := r.Header.Get("X-Forwarded-Proto"); xf != "" {
		// take the first if multiple in chain
		parts := strings.Split(xf, ",")
		return strings.TrimSpace(parts[0])
		// todo: should we have a list of valid schemes/limit this to a max number of bytes?
	}

	// 2. Fall back to URL scheme if set
	if r.URL != nil && r.URL.Scheme != "" {
		return r.URL.Scheme
	}

	// 3. Infer from TLS
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

func Scope(handler string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// logging: enrich + store back into context
			L := log.FromContext(ctx).With("handler", handler)
			ctx = log.WithContext(ctx, L)

			// tracing: enrich span
			if span := trace.SpanFromContext(ctx); span != nil && span.IsRecording() {
				span.SetAttributes(attribute.String("app.handler", handler))
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
