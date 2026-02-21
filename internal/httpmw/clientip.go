package httpmw

import (
	"context"
	"net"
	"net/http"
	"strings"
)

type clientIPKey struct{}

// ClientIPOptions configures client IP extraction behavior.
type ClientIPOptions struct {
	// TrustedHops is the number of trusted reverse proxies between the client
	// and this server. 0 = no proxies (X-Forwarded-For ignored), 1 = single ALB
	// (rightmost XFF entry), 2 = CDN + ALB (second from end), etc.
	TrustedHops int
}

// ClientIP extracts the client IP address from the request and stores it in the context.
// Uses default options (TrustedHops=0: no trusted proxies, X-Forwarded-For is ignored).
func ClientIP(next http.Handler) http.Handler {
	return ClientIPWithOptions(ClientIPOptions{})(next)
}

// ClientIPWithOptions returns middleware that extracts the client IP using the
// given options.
func ClientIPWithOptions(opts ClientIPOptions) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := extractRealClientAddr(r, opts.TrustedHops)
			ctx := WithClientIP(r.Context(), ip)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// extractRealClientAddr extracts the client ip address from the request, only trusts x-forwarded-for if the request comes from a private ip. sg restricts access already, this is just an extra layer of protection.
// When trustedHops > 0, selects the Nth-from-end entry in X-Forwarded-For.
func extractRealClientAddr(r *http.Request, trustedHops int) string {
	// if we were behind ALB with OIDC would create ProxyTrust concept, where we can specify if we are running behind a trusted proxy/load balancer and oidc is enabled. however this site will never be using oidc,
	// so we do not have signatures to verify. if oidc enabled and behind alb, we will verify the signature before verifying the cidr and then trust the header
	// if alb but not oidc enabled, we will verify the cidr and then trust the header
	// otherwise we are deployed directly exposed and use the remote addr without trusting any headers
	// this also applies to the x-forwarded-scheme

	// should never happen
	if r.RemoteAddr == "" {
		return "0.0.0.0"
	}

	// get real remote ip first from remote addr
	clientAddr, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// malformed remote addr, return r.RemoteAddr
		return r.RemoteAddr
	}

	ip := net.ParseIP(clientAddr)
	if ip == nil {
		// malformed remote addr, return 0.0.0.0
		return "0.0.0.0"
	}

	if !ip.IsPrivate() {
		// not from our infrastructure, dont trust forwarded headers, clear them so no downstream middleware accidentally trusts them
		r.Header.Del("X-Forwarded-For")
		r.Header.Del("X-Forwarded-Proto")
		return clientAddr
	}

	if trustedHops <= 0 {
		// no trusted proxies configured, dont trust forwarded headers, clear them so no downstream middleware accidentally trusts them
		r.Header.Del("X-Forwarded-For")
		r.Header.Del("X-Forwarded-Proto")
		return clientAddr
	}

	// Default behavior (trustedHops=0) is to distrust x-forwarded-for entirely, trustedHops=1 means take the right-most X-Forwarded-for
	// entry which is our most common case of a single ALB in front. If trustedHops > 1, select the Nth-from-end entry, which correctly
	// handles multiple proxies (e.g. CDN -> ALB -> app = trustedHops 2). If there are fewer entries than expected fail closed and ignore the header.
	if xf := r.Header.Get("X-Forwarded-For"); xf != "" {
		parts := strings.Split(xf, ",")
		idx := len(parts) - trustedHops
		if idx < 0 {
			// fewer entries than expected proxies - misconfiguration or manipulation
			// fail closed: strip headers, use RemoteAddr
			r.Header.Del("X-Forwarded-For")
			r.Header.Del("X-Forwarded-Proto")
			return clientAddr
		}
		if candidate := strings.TrimSpace(parts[idx]); net.ParseIP(candidate) != nil {
			clientAddr = candidate
		}
	}

	return clientAddr
}

func ClientIPFromContext(ctx context.Context) string {
	ip, _ := ctx.Value(clientIPKey{}).(string)
	return ip
}

func WithClientIP(ctx context.Context, ip string) context.Context {
	if ip == "" {
		return ctx
	}
	return context.WithValue(ctx, clientIPKey{}, ip)
}
