package httpmw

import (
	"net/http"

	"go.opentelemetry.io/otel/trace"
)

func TraceResponseHeaders(traceHeader, spanHeader string) func(http.Handler) http.Handler {
	if traceHeader == "" {
		traceHeader = "X-Trace-Id"
	}
	if spanHeader == "" {
		spanHeader = "X-Span-Id"
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sc := trace.SpanFromContext(r.Context()).SpanContext()
			if sc.IsValid() {
				w.Header().Set(traceHeader, sc.TraceID().String())
				w.Header().Set(spanHeader, sc.SpanID().String())
			}
			next.ServeHTTP(w, r)
		})
	}
}
