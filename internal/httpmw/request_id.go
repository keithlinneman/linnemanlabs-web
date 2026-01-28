package httpmw

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
)

type requestIDKey struct{}

// WithRequestID attaches a request ID to the context.
func WithRequestID(ctx context.Context, id string) context.Context {
	if id == "" {
		return ctx
	}
	return context.WithValue(ctx, requestIDKey{}, id)
}

// RequestIDFromContext gets the request ID from context, or "" if none.
func RequestIDFromContext(ctx context.Context) string {
	if v := ctx.Value(requestIDKey{}); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// RequestID middleware:
// - propagates an existing request ID header if present
// - otherwise generates a new one
// - stores it in context
// - echoes it back on the response
func RequestID(headerName string) func(http.Handler) http.Handler {
	if headerName == "" {
		headerName = "X-Request-Id"
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := r.Header.Get(headerName)
			if id == "" {
				id = newRequestID()
			}

			ctx := WithRequestID(r.Context(), id)

			// include ID on the response too, for client/trace correlation
			w.Header().Set(headerName, id)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func newRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Extremely unlikely; in worst case just return empty and logger will cope.
		return ""
	}
	return hex.EncodeToString(b[:])
}
