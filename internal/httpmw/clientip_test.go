package httpmw

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExtractRealClientAddr_NoTrustedHops(t *testing.T) {
	// TrustedHops=0 means no proxies: X-Forwarded-For is always ignored,
	// headers are cleared for defense in depth.
	tests := []struct {
		name       string
		remoteAddr string
		xff        string
		want       string
	}{
		{
			name:       "private IP ignores XFF when no trusted hops",
			remoteAddr: "10.0.0.1:1234",
			xff:        "203.0.113.50",
			want:       "10.0.0.1",
		},
		{
			name:       "private 172.16 ignores XFF when no trusted hops",
			remoteAddr: "172.16.0.1:1234",
			xff:        "198.51.100.1",
			want:       "172.16.0.1",
		},
		{
			name:       "private 192.168 ignores XFF when no trusted hops",
			remoteAddr: "192.168.1.1:1234",
			xff:        "198.51.100.1",
			want:       "192.168.1.1",
		},
		{
			name:       "private IP with multi-hop XFF ignored",
			remoteAddr: "10.0.0.1:1234",
			xff:        "203.0.113.50, 10.0.0.5, 10.0.0.6",
			want:       "10.0.0.1",
		},
		{
			name:       "private IP no XFF returns RemoteAddr IP",
			remoteAddr: "10.0.0.1:1234",
			xff:        "",
			want:       "10.0.0.1",
		},
		{
			name:       "public IP ignores XFF",
			remoteAddr: "203.0.113.1:1234",
			xff:        "10.0.0.1",
			want:       "203.0.113.1",
		},
		{
			name:       "public IP no XFF",
			remoteAddr: "203.0.113.1:1234",
			xff:        "",
			want:       "203.0.113.1",
		},
		{
			name:       "loopback ignores XFF",
			remoteAddr: "127.0.0.1:1234",
			xff:        "203.0.113.50",
			want:       "127.0.0.1",
		},
		{
			name:       "link-local ignores XFF",
			remoteAddr: "169.254.1.1:1234",
			xff:        "203.0.113.50",
			want:       "169.254.1.1",
		},
		{
			name:       "IPv6 private ignores XFF when no trusted hops",
			remoteAddr: "[fd00::1]:1234",
			xff:        "2001:db8::1",
			want:       "fd00::1",
		},
		{
			name:       "IPv6 public ignores XFF",
			remoteAddr: "[2001:db8::1]:1234",
			xff:        "fd00::bad",
			want:       "2001:db8::1",
		},
		{
			name:       "IPv6 loopback ignores XFF",
			remoteAddr: "[::1]:1234",
			xff:        "203.0.113.50",
			want:       "::1",
		},

		// Edge cases
		{
			name:       "RemoteAddr without port falls back to raw value",
			remoteAddr: "203.0.113.1",
			xff:        "10.0.0.1",
			want:       "203.0.113.1",
		},
		{
			name:       "garbage RemoteAddr returns raw value",
			remoteAddr: "not-an-ip",
			xff:        "203.0.113.50",
			want:       "not-an-ip",
		},
		{
			name:       "empty RemoteAddr returns 0.0.0.0",
			remoteAddr: "",
			xff:        "203.0.113.50",
			want:       "0.0.0.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
			r.RemoteAddr = tt.remoteAddr
			if tt.xff != "" {
				r.Header.Set("X-Forwarded-For", tt.xff)
			}

			got := extractRealClientAddr(r, 0)
			if got != tt.want {
				t.Errorf("extractRealClientAddr(hops=0) = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractRealClientAddr_SingleHop(t *testing.T) {
	// TrustedHops=1: single ALB in front. Takes the rightmost (last) XFF entry
	// when RemoteAddr is private.
	tests := []struct {
		name       string
		remoteAddr string
		xff        string
		want       string
	}{
		{
			name:       "ALB: single XFF entry is the client",
			remoteAddr: "10.0.0.1:1234",
			xff:        "203.0.113.50",
			want:       "203.0.113.50",
		},
		{
			name:       "ALB: multi-hop XFF takes rightmost",
			remoteAddr: "10.0.0.1:1234",
			xff:        "203.0.113.50, 10.0.0.5, 10.0.0.6",
			want:       "10.0.0.6",
		},
		{
			name:       "ALB: whitespace in XFF trimmed",
			remoteAddr: "10.0.0.1:1234",
			xff:        "  203.0.113.50  ,  10.0.0.5  ",
			want:       "10.0.0.5",
		},
		{
			name:       "ALB: no XFF returns RemoteAddr IP",
			remoteAddr: "10.0.0.1:1234",
			xff:        "",
			want:       "10.0.0.1",
		},
		{
			name:       "ALB: private 172.16 trusts XFF",
			remoteAddr: "172.16.0.1:1234",
			xff:        "198.51.100.1",
			want:       "198.51.100.1",
		},
		{
			name:       "ALB: private 192.168 trusts XFF",
			remoteAddr: "192.168.1.1:1234",
			xff:        "198.51.100.1",
			want:       "198.51.100.1",
		},
		{
			name:       "ALB: IPv6 private trusts XFF",
			remoteAddr: "[fd00::1]:1234",
			xff:        "2001:db8::1",
			want:       "2001:db8::1",
		},

		// Public RemoteAddr: never trust XFF regardless of hops
		{
			name:       "public IP ignores XFF even with hops=1",
			remoteAddr: "203.0.113.1:1234",
			xff:        "10.0.0.1",
			want:       "203.0.113.1",
		},
		{
			name:       "loopback ignores XFF even with hops=1",
			remoteAddr: "127.0.0.1:1234",
			xff:        "203.0.113.50",
			want:       "127.0.0.1",
		},

		// Invalid XFF values: fall back to RemoteAddr
		{
			name:       "XFF garbage string falls back to RemoteAddr",
			remoteAddr: "10.0.0.1:1234",
			xff:        "not-an-ip",
			want:       "10.0.0.1",
		},
		{
			name:       "XFF partial IP falls back to RemoteAddr",
			remoteAddr: "10.0.0.1:1234",
			xff:        "192.168.1",
			want:       "10.0.0.1",
		},
		{
			name:       "XFF with port notation falls back to RemoteAddr",
			remoteAddr: "10.0.0.1:1234",
			xff:        "203.0.113.50:8080",
			want:       "10.0.0.1",
		},
		{
			name:       "XFF with CIDR notation falls back to RemoteAddr",
			remoteAddr: "10.0.0.1:1234",
			xff:        "203.0.113.0/24",
			want:       "10.0.0.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
			r.RemoteAddr = tt.remoteAddr
			if tt.xff != "" {
				r.Header.Set("X-Forwarded-For", tt.xff)
			}

			got := extractRealClientAddr(r, 1)
			if got != tt.want {
				t.Errorf("extractRealClientAddr(hops=1) = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractRealClientAddr_MultiHop(t *testing.T) {
	tests := []struct {
		name        string
		remoteAddr  string
		xff         string
		trustedHops int
		want        string
	}{
		{
			name:        "hops=2 CDN+ALB takes second from end",
			remoteAddr:  "10.0.0.1:1234",
			xff:         "203.0.113.50, 10.0.0.5, 10.0.0.6",
			trustedHops: 2,
			want:        "10.0.0.5",
		},
		{
			name:        "hops=3 takes third from end (first of 3)",
			remoteAddr:  "10.0.0.1:1234",
			xff:         "203.0.113.50, 10.0.0.5, 10.0.0.6",
			trustedHops: 3,
			want:        "203.0.113.50",
		},
		{
			name:        "hops exceeds entries fails closed to RemoteAddr",
			remoteAddr:  "10.0.0.1:1234",
			xff:         "203.0.113.50",
			trustedHops: 5,
			want:        "10.0.0.1",
		},
		{
			name:        "hops=2 with exactly 2 entries",
			remoteAddr:  "10.0.0.1:1234",
			xff:         "203.0.113.50, 10.0.0.5",
			trustedHops: 2,
			want:        "203.0.113.50",
		},
		{
			name:        "hops ignored for public remote addr",
			remoteAddr:  "203.0.113.1:1234",
			xff:         "10.0.0.1, 10.0.0.2",
			trustedHops: 2,
			want:        "203.0.113.1",
		},
		{
			name:        "hops with no XFF returns RemoteAddr",
			remoteAddr:  "10.0.0.1:1234",
			xff:         "",
			trustedHops: 2,
			want:        "10.0.0.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
			r.RemoteAddr = tt.remoteAddr
			if tt.xff != "" {
				r.Header.Set("X-Forwarded-For", tt.xff)
			}

			got := extractRealClientAddr(r, tt.trustedHops)
			if got != tt.want {
				t.Errorf("extractRealClientAddr(hops=%d) = %q, want %q", tt.trustedHops, got, tt.want)
			}
		})
	}
}

func TestExtractRealClientAddr_HeaderClearing(t *testing.T) {
	tests := []struct {
		name        string
		remoteAddr  string
		xff         string
		trustedHops int
		wantCleared bool
	}{
		{
			name:        "public RemoteAddr clears forwarded headers",
			remoteAddr:  "203.0.113.1:1234",
			xff:         "10.0.0.1",
			trustedHops: 1,
			wantCleared: true,
		},
		{
			name:        "private RemoteAddr with hops=0 clears headers",
			remoteAddr:  "10.0.0.1:1234",
			xff:         "203.0.113.50",
			trustedHops: 0,
			wantCleared: true,
		},
		{
			name:        "private RemoteAddr with hops=1 preserves headers",
			remoteAddr:  "10.0.0.1:1234",
			xff:         "203.0.113.50",
			trustedHops: 1,
			wantCleared: false,
		},
		{
			name:        "hops exceeds entries clears headers (fail closed)",
			remoteAddr:  "10.0.0.1:1234",
			xff:         "203.0.113.50",
			trustedHops: 5,
			wantCleared: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
			r.RemoteAddr = tt.remoteAddr
			if tt.xff != "" {
				r.Header.Set("X-Forwarded-For", tt.xff)
			}
			r.Header.Set("X-Forwarded-Proto", "https")

			extractRealClientAddr(r, tt.trustedHops)

			xffAfter := r.Header.Get("X-Forwarded-For")
			xfpAfter := r.Header.Get("X-Forwarded-Proto")

			if tt.wantCleared && (xffAfter != "" || xfpAfter != "") {
				t.Errorf("headers should be cleared: X-Forwarded-For=%q, X-Forwarded-Proto=%q", xffAfter, xfpAfter)
			}
			if !tt.wantCleared && xfpAfter == "" {
				t.Error("X-Forwarded-Proto should be preserved")
			}
		})
	}
}

// TestClientIP_Middleware verifies the convenience wrapper uses TrustedHops=0 (no proxies)
func TestClientIP_Middleware(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		xff        string
		wantIP     string
	}{
		{
			name:       "default middleware ignores XFF even from private",
			remoteAddr: "10.0.0.1:1234",
			xff:        "203.0.113.50",
			wantIP:     "10.0.0.1",
		},
		{
			name:       "default middleware uses RemoteAddr when public",
			remoteAddr: "203.0.113.1:1234",
			xff:        "10.0.0.1",
			wantIP:     "203.0.113.1",
		},
		{
			name:       "default middleware uses RemoteAddr when no XFF",
			remoteAddr: "10.0.0.1:1234",
			xff:        "",
			wantIP:     "10.0.0.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var captured string
			inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				captured = ClientIPFromContext(r.Context())
			})

			handler := ClientIP(inner)

			r := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
			r.RemoteAddr = tt.remoteAddr
			if tt.xff != "" {
				r.Header.Set("X-Forwarded-For", tt.xff)
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)

			if captured != tt.wantIP {
				t.Errorf("ClientIPFromContext() = %q, want %q", captured, tt.wantIP)
			}
		})
	}
}

func TestClientIPWithOptions_Middleware(t *testing.T) {
	var captured string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = ClientIPFromContext(r.Context())
	})

	// CDN -> ALB -> app: 2 hops, take 2nd from end
	handler := ClientIPWithOptions(ClientIPOptions{TrustedHops: 2})(inner)

	r := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	r.RemoteAddr = "10.0.0.1:1234"
	r.Header.Set("X-Forwarded-For", "203.0.113.50, 10.0.0.5, 10.0.0.6")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if captured != "10.0.0.5" {
		t.Errorf("ClientIPFromContext() = %q, want 10.0.0.5", captured)
	}
}

func TestClientIPWithOptions_ALB(t *testing.T) {
	var captured string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = ClientIPFromContext(r.Context())
	})

	// Single ALB: 1 hop, takes rightmost XFF entry
	handler := ClientIPWithOptions(ClientIPOptions{TrustedHops: 1})(inner)

	r := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	r.RemoteAddr = "10.0.0.1:1234"
	r.Header.Set("X-Forwarded-For", "203.0.113.50")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if captured != "203.0.113.50" {
		t.Errorf("ClientIPFromContext() = %q, want 203.0.113.50", captured)
	}
}

// TestWithClientIP_RoundTrip verifies the context setter and getter work together
func TestWithClientIP_RoundTrip(t *testing.T) {
	ctx := WithClientIP(context.Background(), "203.0.113.50")
	got := ClientIPFromContext(ctx)
	if got != "203.0.113.50" {
		t.Errorf("round trip: got %q, want 203.0.113.50", got)
	}
}

// TestWithClientIP_Empty verifies empty string doesn't set context
func TestWithClientIP_Empty(t *testing.T) {
	ctx := WithClientIP(context.Background(), "")
	got := ClientIPFromContext(ctx)
	if got != "" {
		t.Errorf("empty input: got %q, want empty", got)
	}
}

// TestClientIPFromContext_Missing verifies missing key returns empty string
func TestClientIPFromContext_Missing(t *testing.T) {
	got := ClientIPFromContext(context.Background())
	if got != "" {
		t.Errorf("missing key: got %q, want empty", got)
	}
}

func FuzzExtractClientAddr(f *testing.F) {
	// Seed: real-world edge cases
	f.Add("10.0.0.1:8080", "203.0.113.50, 10.0.0.1", 1) // private remote, multiple XFF, ALB
	f.Add("203.0.113.50:443", "192.168.1.1", 0)           // public remote, XFF, no hops
	f.Add("garbage", "", 0)                                // malformed
	f.Add("[::1]:8080", "2001:db8::1", 1)                  // IPv6
	f.Add("127.0.0.1:80", "", 0)                           // loopback, no XFF
	f.Add("10.0.0.1:1234", "a, b, c", 2)                   // multi-hop with garbage
	f.Fuzz(func(t *testing.T, remoteAddr, xff string, hops int) {
		if hops < 0 || hops > 10 {
			return
		}
		r := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		r.RemoteAddr = remoteAddr
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		result := extractRealClientAddr(r, hops)
		// INVARIANT: must never panic
		// INVARIANT: must always return a non-empty string
		if result == "" {
			t.Error("extractRealClientAddr returned empty string")
		}
	})
}
