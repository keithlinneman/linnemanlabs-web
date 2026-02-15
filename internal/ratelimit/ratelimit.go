// Package ratelimit is middleware for per-ip rate limiting
//
// # Simple in-memory implementation, not shared between instances or distributed
//
// What this does protect against:
//   - single ip flooding app (connection/goroutine exhaustion)
//   - gives observability insight into who/what/when/where/how (you still have to figure out why on your own..)
//   - single-log entry per offender to prevent log spam, metrics for counting total denied requests
//
// What this does NOT protect against:
//   - distributed attacks across many ips
//   - bandwidth-bill attacks, inbound data is already accepted by the time this runs
//
// This is designed to be a simple, self contained solution for defense in depth with upstream filtering.
// This specific app is extremely resilient (no long-lived db connections, process cache, internal states, etc), so this is an attempt to mitigate resource exhaustion and provide better visibility into abuse.
package ratelimit

import (
	"context"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/keithlinneman/linnemanlabs-web/internal/httpmw"
)

// visitor tracks a single IPs limiter and last activity
type visitor struct {
	limiter  *rate.Limiter
	lastSeen time.Time
	// logged tracks whether we have already emitted the first-denial log
	// resets when the entry is evicted and re-created
	logged bool
}

// IPLimiter holds per-IP rate limiters with background eviction
type IPLimiter struct {
	mu       sync.Mutex
	visitors map[string]*visitor

	// rate controls: requests per second and burst ceiling
	perSecond rate.Limit
	burst     int

	// ttl controls how long an idle IP stays in the map before cleanup evicts it
	ttl time.Duration

	// OnFirstDenied is called once per visitor when they first get rate limited
	// ip is the raw IP string (no port)
	OnFirstDenied func(ip string)

	// OnDenied is called on every denied request, used for incrementing prometheus counter
	OnDenied func(ip string)
}

type Option func(*IPLimiter)

// WithRate sets the request limit bucket size and the refill rate.
// burst is the total capacity of the bucket, perSecond is how many tokens are added to the bucket each second.
// WithRate(10, 50) allows 50 requests at once, then refills at a rate of 10 requests per second
func WithRate(perSecond float64, burst int) Option {
	return func(l *IPLimiter) {
		l.perSecond = rate.Limit(perSecond)
		l.burst = burst
	}
}

// WithTTL controls how long an idle IP stays in the map before cleanup
func WithTTL(d time.Duration) Option {
	return func(l *IPLimiter) {
		l.ttl = d
	}
}

// WithOnFirstDenied sets a callback for the first denial per visitor, used for logging.
// Intentionally separate from OnDenied to allow different handling - we log once, but increment prometheus counters on each denial
func WithOnFirstDenied(fn func(ip string)) Option {
	return func(l *IPLimiter) {
		l.OnFirstDenied = fn
	}
}

// WithOnDenied sets a callback for every denied request. used for incrementing prometheus counters
func WithOnDenied(fn func(ip string)) Option {
	return func(l *IPLimiter) {
		l.OnDenied = fn
	}
}

// New creates an IPLimiter and starts the background cleanup goroutine
func New(ctx context.Context, opts ...Option) *IPLimiter {
	l := &IPLimiter{
		visitors:  make(map[string]*visitor),
		perSecond: 10,
		burst:     30,
		ttl:       5 * time.Minute,
	}
	for _, o := range opts {
		o(l)
	}
	// start background cleanup goroutine, uses provided context for cancellation that will trigger on app shutdown
	go l.cleanup(ctx)
	return l
}

// allow checks whether the given IP is within its rate limit. also handles visitor creation and logging for first denial.
// Returns true if the request should proceed, false if it should be rejected.
func (l *IPLimiter) allow(ip string) bool {
	l.mu.Lock()
	v, exists := l.visitors[ip]
	if !exists {
		v = &visitor{
			limiter: rate.NewLimiter(l.perSecond, l.burst),
		}
		l.visitors[ip] = v
	}
	v.lastSeen = time.Now()
	allowed := v.limiter.Allow()

	if !allowed && !v.logged {
		v.logged = true
		// release lock before calling hooks, have to release as fast as possible to avoid blocking other requests and these calls may do slow work
		l.mu.Unlock()
		if l.OnFirstDenied != nil {
			l.OnFirstDenied(ip)
		}
		if l.OnDenied != nil {
			l.OnDenied(ip)
		}
		return false
	}

	l.mu.Unlock()

	if !allowed && l.OnDenied != nil {
		l.OnDenied(ip)
	}

	return allowed
}

// cleanup periodically evicts visitors that haven't been seen within the TTL.
// Runs every TTL/2 to avoid holding stale entries much longer than intended.
func (l *IPLimiter) cleanup(ctx context.Context) {
	ticker := time.NewTicker(l.ttl / 2)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			l.mu.Lock()
			for ip, v := range l.visitors {
				if now.Sub(v.lastSeen) > l.ttl {
					delete(l.visitors, ip)
				}
			}
			l.mu.Unlock()
		}
	}
}

// Middleware returns middleware that rejects requests over the per-ip rate limit with 429
func (l *IPLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// use the httpmw function for resolving client IP, which has extra protections for checking x-forwarded for and public ips and potentially if its a signed request due to oidc and alb
		ip := httpmw.ClientIPFromContext(r.Context())

		if !l.allow(ip) {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Header().Set("Retry-After", "30")
			w.WriteHeader(http.StatusTooManyRequests)
			// intentionally not including detail about limits, remaining budget, or when the bucket refills
			w.Write([]byte(`{"error":"too many requests"}`))
			return
		}

		next.ServeHTTP(w, r)
	})
}
