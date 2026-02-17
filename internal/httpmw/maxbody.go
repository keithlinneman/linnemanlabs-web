// internal/httpmw/maxbody.go

package httpmw

import "net/http"

// MaxBody limits request body size. Requests exceeding the limit
// receive 413 Request Entity Too Large when the body is read.
func MaxBody(bytes int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, bytes)
			next.ServeHTTP(w, r)
		})
	}
}
