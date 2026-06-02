package httpmw

import (
	"net/http"
	"path"
	"strings"
)

// Security note: CSRF protection is not implemented because it is not applicable.
// This API is stateless (no cookies, no sessions, no authentication) and read-only (GET only).

// SecurityHeaders is middleware that adds common security headers to HTTP responses
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// Headers to include on all requests

		// Require HTTPS for one year, including subdomains, and allow preload
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")

		// Disable MIME type sniffing for integrity/security
		w.Header().Set("X-Content-Type-Options", "nosniff")

		// Referrer policy to control information sent in Referer header
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

		// Static image/media assets kept easy for crawlers/previews/CDNs/sharing, no more headers
		if isStaticImagePath(r.URL.Path) {
			w.Header().Set("Cross-Origin-Resource-Policy", "cross-origin")
			next.ServeHTTP(w, r)
			return
		}

		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")

		// Old Clickjacking protection - dont allow embedding in frames
		w.Header().Set("X-Frame-Options", "DENY")

		// Content Security Policy to restrict resource loading to same origin
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; "+
				"script-src 'self'; "+
				"style-src 'self'; "+
				"img-src 'self'; "+
				"font-src 'self'; "+
				"base-uri 'self'; "+
				"form-action 'self'; "+
				"frame-ancestors 'none'; "+
				"object-src 'none'; "+
				"upgrade-insecure-requests")

		// Permissions policy to disable various powerful (in)security features
		w.Header().Set("Permissions-Policy",
			"accelerometer=(), camera=(), geolocation=(), gyroscope=(), "+
				"magnetometer=(), microphone=(), payment=(), usb=()")

		// Prevent Adobe Flash and Acrobat from loading content
		w.Header().Set("X-Permitted-Cross-Domain-Policies", "none")

		// Cross-Origin-Opener-Policy to isolate browsing context
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")

		w.Header().Set("Origin-Agent-Cluster", "?1")

		next.ServeHTTP(w, r)
	})
}

func isStaticImagePath(urlPath string) bool {
	ext := strings.ToLower(path.Ext(urlPath))

	switch ext {
	case ".png", ".jpg", ".jpeg", ".webp", ".gif", ".ico", ".svg":
		return true
	default:
		return false
	}
}
