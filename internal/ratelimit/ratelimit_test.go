package ratelimit

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/keithlinneman/linnemanlabs-web/internal/httpmw"
)

// newTestLimiter creates a limiter with a short TTL and cancellable context for tests.
// Returns the limiter and a cancel func to stop the cleanup goroutine.
func newTestLimiter(opts ...Option) (*IPLimiter, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	defaults := []Option{
		WithRate(10, 5), // 10/sec, burst of 5 - small burst makes tests fast
		WithTTL(100 * time.Millisecond),
	}
	all := append(defaults, opts...)
	l := New(ctx, all...)
	return l, cancel
}

func TestAllow_BurstThenReject(t *testing.T) {
	l, cancel := newTestLimiter(WithRate(1, 5)) // 1/sec refill, burst of 5
	defer cancel()

	ip := "10.0.0.1"

	// first 5 requests should all be allowed (burst)
	for i := 0; i < 5; i++ {
		if !l.allow(ip) {
			t.Fatalf("request %d should be allowed (within burst)", i+1)
		}
	}

	// next request should be denied (burst exhausted, refill too slow)
	if l.allow(ip) {
		t.Fatal("request 6 should be denied (burst exhausted)")
	}
}

func TestAllow_SeparateIPsGetSeparateBuckets(t *testing.T) {
	l, cancel := newTestLimiter(WithRate(1, 3))
	defer cancel()

	// drain ip1's burst
	for i := 0; i < 3; i++ {
		l.allow("10.0.0.1")
	}

	// ip1 should be denied
	if l.allow("10.0.0.1") {
		t.Fatal("ip1 should be denied after burst")
	}

	// ip2 should still have a full bucket
	if !l.allow("10.0.0.2") {
		t.Fatal("ip2 should be allowed (separate bucket)")
	}
}

func TestAllow_RefillAfterTime(t *testing.T) {
	l, cancel := newTestLimiter(WithRate(100, 1)) // 100/sec refill, burst of 1
	defer cancel()

	ip := "10.0.0.1"

	// use the one token
	if !l.allow(ip) {
		t.Fatal("first request should be allowed")
	}

	// immediately denied
	if l.allow(ip) {
		t.Fatal("should be denied with empty bucket")
	}

	// wait for refill (at 100/sec, 20ms is 2 tokens)
	time.Sleep(20 * time.Millisecond)

	if !l.allow(ip) {
		t.Fatal("should be allowed after refill")
	}
}

func TestOnFirstDenied_CalledOnce(t *testing.T) {
	var firstCount atomic.Int32

	l, cancel := newTestLimiter(
		WithRate(1, 2),
		WithOnFirstDenied(func(ip string) {
			firstCount.Add(1)
		}),
	)
	defer cancel()

	ip := "10.0.0.1"

	// drain burst
	l.allow(ip)
	l.allow(ip)

	// trigger multiple denials
	for i := 0; i < 10; i++ {
		l.allow(ip)
	}

	// OnFirstDenied should have fired exactly once
	got := firstCount.Load()
	if got != 1 {
		t.Fatalf("OnFirstDenied called %d times, want 1", got)
	}
}

func TestOnDenied_CalledEveryDenial(t *testing.T) {
	var deniedCount atomic.Int32

	l, cancel := newTestLimiter(
		WithRate(1, 2),
		WithOnDenied(func(ip string) {
			deniedCount.Add(1)
		}),
	)
	defer cancel()

	ip := "10.0.0.1"

	// drain burst
	l.allow(ip)
	l.allow(ip)

	// 5 denied requests
	for i := 0; i < 5; i++ {
		l.allow(ip)
	}

	got := deniedCount.Load()
	if got != 5 {
		t.Fatalf("OnDenied called %d times, want 5", got)
	}
}

func TestOnFirstDenied_PerIP(t *testing.T) {
	seen := make(map[string]int)
	var mu sync.Mutex

	l, cancel := newTestLimiter(
		WithRate(1, 1),
		WithOnFirstDenied(func(ip string) {
			mu.Lock()
			seen[ip]++
			mu.Unlock()
		}),
	)
	defer cancel()

	// drain and trigger first denial for two different IPs
	l.allow("10.0.0.1")
	l.allow("10.0.0.1") // denied - first for this IP
	l.allow("10.0.0.1") // denied again - should not trigger OnFirstDenied

	l.allow("10.0.0.2")
	l.allow("10.0.0.2") // denied - first for this IP

	mu.Lock()
	defer mu.Unlock()

	if seen["10.0.0.1"] != 1 {
		t.Errorf("OnFirstDenied for 10.0.0.1: got %d, want 1", seen["10.0.0.1"])
	}
	if seen["10.0.0.2"] != 1 {
		t.Errorf("OnFirstDenied for 10.0.0.2: got %d, want 1", seen["10.0.0.2"])
	}
}

func TestCleanup_EvictsStaleVisitors(t *testing.T) {
	l, cancel := newTestLimiter(
		WithRate(1, 1),
		WithTTL(50*time.Millisecond),
	)
	defer cancel()

	// create a visitor
	l.allow("10.0.0.1")

	// verify visitor exists
	l.mu.Lock()
	if _, exists := l.visitors["10.0.0.1"]; !exists {
		l.mu.Unlock()
		t.Fatal("visitor should exist immediately after request")
	}
	l.mu.Unlock()

	// wait for TTL + cleanup interval (TTL/2) + buffer
	time.Sleep(120 * time.Millisecond)

	l.mu.Lock()
	_, exists := l.visitors["10.0.0.1"]
	l.mu.Unlock()

	if exists {
		t.Fatal("visitor should be evicted after TTL")
	}
}

func TestCleanup_ActiveVisitorNotEvicted(t *testing.T) {
	l, cancel := newTestLimiter(
		WithRate(100, 100), // generous limits so requests aren't denied
		WithTTL(80*time.Millisecond),
	)
	defer cancel()

	// keep visitor active across multiple cleanup cycles
	for i := 0; i < 5; i++ {
		l.allow("10.0.0.1")
		time.Sleep(30 * time.Millisecond)
	}

	l.mu.Lock()
	_, exists := l.visitors["10.0.0.1"]
	l.mu.Unlock()

	if !exists {
		t.Fatal("active visitor should not be evicted")
	}
}

func TestCleanup_StopsOnCancel(t *testing.T) {
	l, cancel := newTestLimiter(WithTTL(10 * time.Millisecond))

	l.allow("10.0.0.1")

	// cancel the context - cleanup goroutine should exit
	cancel()

	// wait for cleanup to have run if it were still alive
	time.Sleep(30 * time.Millisecond)

	// add a new visitor after cancel - it should never be cleaned up
	// since the goroutine is stopped
	l.allow("10.0.0.2")
	time.Sleep(30 * time.Millisecond)

	l.mu.Lock()
	_, exists := l.visitors["10.0.0.2"]
	l.mu.Unlock()

	if !exists {
		t.Fatal("visitor should persist when cleanup goroutine is stopped")
	}
}

func TestCleanup_OnFirstDenied_ResetsAfterEviction(t *testing.T) {
	var firstCount atomic.Int32

	l, cancel := newTestLimiter(
		WithRate(1, 1),
		WithTTL(50*time.Millisecond),
		WithOnFirstDenied(func(ip string) {
			firstCount.Add(1)
		}),
	)
	defer cancel()

	ip := "10.0.0.1"

	// trigger first denial
	l.allow(ip)
	l.allow(ip) // denied - OnFirstDenied fires (count = 1)

	if got := firstCount.Load(); got != 1 {
		t.Fatalf("after first denial: OnFirstDenied = %d, want 1", got)
	}

	// wait for eviction
	time.Sleep(120 * time.Millisecond)

	// visitor is gone - new requests create a fresh entry
	l.allow(ip)
	l.allow(ip) // denied again - OnFirstDenied should fire again (count = 2)

	if got := firstCount.Load(); got != 2 {
		t.Fatalf("after re-entry: OnFirstDenied = %d, want 2", got)
	}
}

func TestDefaults(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	l := New(ctx)

	if l.perSecond != 10 {
		t.Errorf("default perSecond = %v, want 10", l.perSecond)
	}
	if l.burst != 30 {
		t.Errorf("default burst = %d, want 30", l.burst)
	}
	if l.ttl != 5*time.Minute {
		t.Errorf("default ttl = %v, want 5m", l.ttl)
	}
}

func TestNilCallbacks_NoPanic(t *testing.T) {
	l, cancel := newTestLimiter(WithRate(1, 1))
	defer cancel()

	// no callbacks set - should not panic on denial
	l.allow("10.0.0.1")
	l.allow("10.0.0.1") // denied, no callbacks - should be fine
}

// === Middleware HTTP tests ===
//
// Client IP is injected via httpmw.WithClientIP - no dependency on the
// ClientIP middleware's XFF parsing or trust logic. These tests only
// exercise the rate limiter's HTTP behavior.

func makeRequestWithIP(handler http.Handler, clientIP string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	ctx := httpmw.WithClientIP(r.Context(), clientIP)
	r = r.WithContext(ctx)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}

func TestMiddleware_Returns429(t *testing.T) {
	l, cancel := newTestLimiter(WithRate(1, 2))
	defer cancel()

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := l.Middleware(inner)

	// first 2 requests should pass
	for i := 0; i < 2; i++ {
		w := makeRequestWithIP(handler, "203.0.113.1")
		if w.Code != http.StatusOK {
			t.Fatalf("request %d: got %d, want 200", i+1, w.Code)
		}
	}

	// next should be 429
	w := makeRequestWithIP(handler, "203.0.113.1")
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("request 3: got %d, want 429", w.Code)
	}

	// verify response headers
	if w.Header().Get("Retry-After") != "30" {
		t.Errorf("Retry-After = %q, want 30", w.Header().Get("Retry-After"))
	}
	if w.Header().Get("Content-Type") != "application/json; charset=utf-8" {
		t.Errorf("Content-Type = %q", w.Header().Get("Content-Type"))
	}

	// verify body
	want := `{"error":"too many requests"}`
	if got := w.Body.String(); got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
}

func TestMiddleware_DifferentIPsIndependent(t *testing.T) {
	l, cancel := newTestLimiter(WithRate(1, 1))
	defer cancel()

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := l.Middleware(inner)

	// exhaust ip1
	makeRequestWithIP(handler, "203.0.113.1")
	w := makeRequestWithIP(handler, "203.0.113.1")
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("ip1 second request: got %d, want 429", w.Code)
	}

	// ip2 should still work
	w = makeRequestWithIP(handler, "203.0.113.2")
	if w.Code != http.StatusOK {
		t.Fatalf("ip2 first request: got %d, want 200", w.Code)
	}
}

func TestMiddleware_AllowedRequestReachesHandler(t *testing.T) {
	l, cancel := newTestLimiter(WithRate(10, 10))
	defer cancel()

	var reached atomic.Bool
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Store(true)
		w.WriteHeader(http.StatusOK)
	})
	handler := l.Middleware(inner)

	makeRequestWithIP(handler, "203.0.113.1")

	if !reached.Load() {
		t.Fatal("inner handler was not called for allowed request")
	}
}

func TestMiddleware_DeniedRequestDoesNotReachHandler(t *testing.T) {
	l, cancel := newTestLimiter(WithRate(1, 1))
	defer cancel()

	var reachCount atomic.Int32
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reachCount.Add(1)
		w.WriteHeader(http.StatusOK)
	})
	handler := l.Middleware(inner)

	// first request reaches inner handler
	makeRequestWithIP(handler, "203.0.113.1")
	// second is denied
	makeRequestWithIP(handler, "203.0.113.1")
	// third is denied
	makeRequestWithIP(handler, "203.0.113.1")

	if got := reachCount.Load(); got != 1 {
		t.Fatalf("inner handler reached %d times, want 1", got)
	}
}

func TestMiddleware_EmptyClientIP(t *testing.T) {
	l, cancel := newTestLimiter(WithRate(1, 1))
	defer cancel()

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := l.Middleware(inner)

	// request with no client IP in context - should still work,
	// all such requests share the empty-string bucket
	makeRequestWithIP(handler, "")
	w := makeRequestWithIP(handler, "")
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("empty IP second request: got %d, want 429", w.Code)
	}
}

// MaxVisitors unit tests

func TestDefaults_MaxVisitors(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	l := New(ctx)

	if l.maxVisitors != 100000 {
		t.Fatalf("default maxVisitors = %d, want 100000", l.maxVisitors)
	}
}

func TestWithMaxVisitors(t *testing.T) {
	l, cancel := newTestLimiter(WithMaxVisitors(500))
	defer cancel()

	if l.maxVisitors != 500 {
		t.Fatalf("maxVisitors = %d, want 500", l.maxVisitors)
	}
}

func TestMaxVisitors_NewIPRejectedAtCapacity(t *testing.T) {
	l, cancel := newTestLimiter(
		WithRate(100, 100), // generous limits so denials are only from capacity
		WithMaxVisitors(3),
	)
	defer cancel()

	// fill the map with 3 unique IPs
	for i := 0; i < 3; i++ {
		ip := fmt.Sprintf("10.0.0.%d", i+1)
		if !l.allow(ip) {
			t.Fatalf("ip %s should be allowed (map not full)", ip)
		}
	}

	// 4th unique IP should be rejected
	if l.allow("10.0.0.99") {
		t.Fatal("new IP should be rejected when map is at capacity")
	}
}

func TestMaxVisitors_ExistingIPStillAllowedAtCapacity(t *testing.T) {
	l, cancel := newTestLimiter(
		WithRate(100, 100),
		WithMaxVisitors(3),
	)
	defer cancel()

	// fill the map
	l.allow("10.0.0.1")
	l.allow("10.0.0.2")
	l.allow("10.0.0.3")

	// existing IPs should still work
	if !l.allow("10.0.0.1") {
		t.Fatal("existing IP should still be allowed at capacity")
	}
	if !l.allow("10.0.0.2") {
		t.Fatal("existing IP should still be allowed at capacity")
	}
	if !l.allow("10.0.0.3") {
		t.Fatal("existing IP should still be allowed at capacity")
	}
}

func TestMaxVisitors_OnCapacityFiredOnce(t *testing.T) {
	var capCount atomic.Int32

	l, cancel := newTestLimiter(
		WithRate(100, 100),
		WithMaxVisitors(2),
		WithOnCapacity(func() {
			capCount.Add(1)
		}),
	)
	defer cancel()

	// fill the map
	l.allow("10.0.0.1")
	l.allow("10.0.0.2")

	// first rejection triggers OnCapacity
	l.allow("10.0.0.10")
	if got := capCount.Load(); got != 1 {
		t.Fatalf("after first rejection: OnCapacity count = %d, want 1", got)
	}

	// subsequent rejections should NOT fire OnCapacity again
	l.allow("10.0.0.11")
	l.allow("10.0.0.12")
	if got := capCount.Load(); got != 1 {
		t.Fatalf("after repeated rejections: OnCapacity count = %d, want 1", got)
	}
}

func TestMaxVisitors_OnCapacityNil_NoPanic(t *testing.T) {
	l, cancel := newTestLimiter(
		WithRate(100, 100),
		WithMaxVisitors(1),
		// no OnCapacity set
	)
	defer cancel()

	l.allow("10.0.0.1")
	// should not panic
	l.allow("10.0.0.2")
}

func TestMaxVisitors_EvictionFreesCapacity(t *testing.T) {
	l, cancel := newTestLimiter(
		WithRate(100, 100),
		WithMaxVisitors(2),
		WithTTL(50*time.Millisecond),
	)
	defer cancel()

	// fill the map
	l.allow("10.0.0.1")
	l.allow("10.0.0.2")

	// new IP rejected
	if l.allow("10.0.0.3") {
		t.Fatal("should be rejected at capacity")
	}

	// wait for eviction
	time.Sleep(120 * time.Millisecond)

	// map should be empty now, new IP should be allowed
	if !l.allow("10.0.0.3") {
		t.Fatal("new IP should be allowed after eviction freed capacity")
	}
}

func TestMaxVisitors_RateLimitStillAppliesAtCapacity(t *testing.T) {
	l, cancel := newTestLimiter(
		WithRate(1, 1), // tight rate limit
		WithMaxVisitors(2),
	)
	defer cancel()

	// fill map and exhaust rate limit for ip1
	l.allow("10.0.0.1") // allowed, consumes token
	l.allow("10.0.0.2")

	// ip1 should be rate-limited (not capacity-limited)
	if l.allow("10.0.0.1") {
		t.Fatal("ip1 should be rate-limited even though it's an existing visitor")
	}
}

func TestMaxVisitors_ZeroDisablesLimit(t *testing.T) {
	l, cancel := newTestLimiter(
		WithRate(100, 100),
		WithMaxVisitors(0),
	)
	defer cancel()

	// with maxVisitors=0 the check is `l.maxVisitors > 0 && ...`
	// so no capacity limit should be enforced
	for i := 0; i < 100; i++ {
		ip := fmt.Sprintf("10.0.%d.%d", i/256, i%256)
		if !l.allow(ip) {
			t.Fatalf("ip %s rejected with maxVisitors=0 (should be unlimited)", ip)
		}
	}
}

func TestMaxVisitors_Middleware_Returns429ForNewIP(t *testing.T) {
	l, cancel := newTestLimiter(
		WithRate(100, 100),
		WithMaxVisitors(2),
	)
	defer cancel()

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := l.Middleware(inner)

	// fill the map via middleware
	w1 := makeRequestWithIP(handler, "203.0.113.1")
	w2 := makeRequestWithIP(handler, "203.0.113.2")
	if w1.Code != http.StatusOK || w2.Code != http.StatusOK {
		t.Fatalf("first two IPs should pass: got %d, %d", w1.Code, w2.Code)
	}

	// new IP should get 429
	w3 := makeRequestWithIP(handler, "203.0.113.3")
	if w3.Code != http.StatusTooManyRequests {
		t.Fatalf("new IP at capacity: got %d, want 429", w3.Code)
	}
}

func TestMaxVisitors_Middleware_ExistingIPStillServed(t *testing.T) {
	l, cancel := newTestLimiter(
		WithRate(100, 100),
		WithMaxVisitors(2),
	)
	defer cancel()

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := l.Middleware(inner)

	// fill the map
	makeRequestWithIP(handler, "203.0.113.1")
	makeRequestWithIP(handler, "203.0.113.2")

	// existing IP should still get 200
	w := makeRequestWithIP(handler, "203.0.113.1")
	if w.Code != http.StatusOK {
		t.Fatalf("existing IP at capacity: got %d, want 200", w.Code)
	}
}

func TestMaxVisitors_ConcurrentAccess(t *testing.T) {
	l, cancel := newTestLimiter(
		WithRate(100, 100),
		WithMaxVisitors(50),
	)
	defer cancel()

	// hammer with 200 goroutines using unique IPs
	var wg sync.WaitGroup
	var allowed atomic.Int32
	var rejected atomic.Int32

	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			ip := fmt.Sprintf("10.%d.%d.%d", n/65536, (n/256)%256, n%256)
			if l.allow(ip) {
				allowed.Add(1)
			} else {
				rejected.Add(1)
			}
		}(i)
	}

	wg.Wait()

	// exactly 50 should have been allowed (one per unique IP, all within burst)
	if got := allowed.Load(); got != 50 {
		t.Fatalf("allowed = %d, want 50", got)
	}
	if got := rejected.Load(); got != 150 {
		t.Fatalf("rejected = %d, want 150", got)
	}

	l.mu.Lock()
	mapSize := len(l.visitors)
	l.mu.Unlock()
	if mapSize != 50 {
		t.Fatalf("map size = %d, want 50", mapSize)
	}
}
