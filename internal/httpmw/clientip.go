package httpmw

import (
	"context"
	"net"
	"net/http"
	"strings"
)

type clientIPKey struct{}

// ClientIP extracts the client IP address from the request and stores it in the context
func ClientIP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := extractRealClientAddr(r)
		ctx := context.WithValue(r.Context(), clientIPKey{}, ip)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// extractRealClientAddr extracts the client ip address from the request, only trusts x-forwarded-for if the request comes from a private ip. sg restricts access already, this is just an extra layer of protection.
func extractRealClientAddr(r *http.Request) string {
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
			clientAddr = strings.TrimSpace(parts[0])
		}
	}
	return clientAddr
}

func ClientIPFromContext(ctx context.Context) string {
	ip, _ := ctx.Value(clientIPKey{}).(string)
	return ip
}
