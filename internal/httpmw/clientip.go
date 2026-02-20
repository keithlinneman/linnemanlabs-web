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
	// and this server. When > 0, the Nth-from-end entry in X-Forwarded-For is
	// used instead of the first entry. This correctly handles multi-proxy chains
	// (e.g. CDN -> ALB -> app = TrustedHops 2). When 0, uses the first entry
	// (current behavior: single ALB in front).
	TrustedHops int
}

// ClientIP extracts the client IP address from the request and stores it in the context.
// Uses default options (TrustedHops=0, first XFF entry when from private IP).
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
	// if we were behind ALB with OIDC would create ProxyTrust concept, where we can specify if we are running behind a trusted proxy/load balancer and oidc is enabled
	// if oidc enabled and behind alb, we will verify the signature before verifying the cidr and then trust the header
	// if alb but not oidc enabled, we will verify the cidr and then trust the header
	// otherwise we are deployed directly exposed and use the remote addr without trusting any headers
	// this also applies to the x-forwarded-scheme

	// get real remote ip first from remote addr
	clientAddr, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}

	ip := net.ParseIP(clientAddr)
	if ip == nil || !ip.IsPrivate() {
		// not from our infrastructure, dont trust forwarded headers
		return clientAddr
	}

	// Prefer X-Forwarded-For when behind ALB
	if xf := r.Header.Get("X-Forwarded-For"); xf != "" {
		parts := strings.Split(xf, ",")
		if len(parts) > 0 {
			// select entry based on trustedHops:
			// trustedHops=0 -> first entry (index 0), current behavior
			// trustedHops=N -> Nth from end (index len-N)
			idx := 0
			if trustedHops > 0 {
				idx = len(parts) - trustedHops
				if idx < 0 {
					idx = 0
				}
			}
			if candidate := strings.TrimSpace(parts[idx]); net.ParseIP(candidate) != nil {
				clientAddr = candidate
			}
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
