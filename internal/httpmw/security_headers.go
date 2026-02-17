package httpmw

import "net/http"

// Security note: CSRF protection is not implemented because it is not applicable.
// This API is stateless (no cookies, no sessions, no authentication) and read-only (GET only).

// SecurityHeaders is middleware that adds common security headers to HTTP responses
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Require HTTPS for one year, including subdomains, and allow preload
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")

		// Content Security Policy to restrict resource loading to same origin
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; object-src 'none'; upgrade-insecure-requests")

		// Disable MIME type sniffing for integrity/security
		w.Header().Set("X-Content-Type-Options", "nosniff")

		// Old Clickjacking protection - dont allow embedding in frames
		w.Header().Set("X-Frame-Options", "DENY")

		// Referrer policy to control information sent in Referer header
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

		// Permissions policy to disable various powerful (in)security features
		w.Header().Set("Permissions-Policy", "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()")

		// Prevent Adobe Flash and Acrobat from loading content
		w.Header().Set("X-Permitted-Cross-Domain-Policies", "none")

		// Cross-Origin Embedder-Policy to control resource embedding
		w.Header().Set("Cross-Origin-Embedder-Policy", "require-corp")

		// Cross-Origin-Opener-Policy to isolate browsing context
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")

		// Cross-Origin-Resource-Policy to restrict resource.. "sharing"
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")

		next.ServeHTTP(w, r)
	})
}
