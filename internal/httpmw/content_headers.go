package httpmw

import (
	"net/http"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// ContentInfo provides content version information for headers
type ContentInfo interface {
	ContentVersion() string
	ContentHash() string
}

// ContentHeaders middleware adds X-Content-Bundle-Version and X-Content-Hash headers
// to all responses when content information is available
func ContentHeaders(info ContentInfo) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if info != nil {
				v := info.ContentVersion()
				h := info.ContentHash()
				if v != "" {
					w.Header().Set("X-Content-Bundle-Version", v)
				}
				if h != "" {
					// Use short hash for header (first 12 chars)
					headerHash := h
					if len(headerHash) > 12 {
						headerHash = headerHash[:12]
					}
					w.Header().Set("X-Content-Hash", headerHash)
				}
				// Enrich the current trace span with content version info
				if span := trace.SpanFromContext(r.Context()); span != nil && span.IsRecording() {
					if v != "" {
						span.SetAttributes(attribute.String("content.version", v))
					}
					if h != "" {
						span.SetAttributes(attribute.String("content.hash", h))
					}
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}
