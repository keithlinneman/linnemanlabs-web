package httpmw

import (
	"net/http"
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
				if v := info.ContentVersion(); v != "" {
					w.Header().Set("X-Content-Bundle-Version", v)
				}
				if h := info.ContentHash(); h != "" {
					// Use short hash for header (first 12 chars)
					if len(h) > 12 {
						h = h[:12]
					}
					w.Header().Set("X-Content-Hash", h)
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}
