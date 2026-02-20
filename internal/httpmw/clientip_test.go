package httpmw

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExtractRealClientAddr(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		xff        string // X-Forwarded-For header, empty = not set
		want       string
	}{
		// === Private RemoteAddr: trust X-Forwarded-For ===
		{
			name:       "private IP trusts XFF",
			remoteAddr: "10.0.0.1:1234",
			xff:        "203.0.113.50",
			want:       "203.0.113.50",
		},
		{
			name:       "private 172.16 trusts XFF",
			remoteAddr: "172.16.0.1:1234",
			xff:        "198.51.100.1",
			want:       "198.51.100.1",
		},
		{
			name:       "private 192.168 trusts XFF",
			remoteAddr: "192.168.1.1:1234",
			xff:        "198.51.100.1",
			want:       "198.51.100.1",
		},
		{
			name:       "private IP with multi-hop XFF takes first",
			remoteAddr: "10.0.0.1:1234",
			xff:        "203.0.113.50, 10.0.0.5, 10.0.0.6",
			want:       "203.0.113.50",
		},
		{
			name:       "private IP with whitespace in XFF",
			remoteAddr: "10.0.0.1:1234",
			xff:        "  203.0.113.50  ,  10.0.0.5  ",
			want:       "203.0.113.50",
		},
		{
			name:       "private IP no XFF returns RemoteAddr IP",
			remoteAddr: "10.0.0.1:1234",
			xff:        "",
			want:       "10.0.0.1",
		},
		{
			name:       "private IP empty XFF returns RemoteAddr IP",
			remoteAddr: "10.0.0.1:5555",
			xff:        "",
			want:       "10.0.0.1",
		},

		// === Public RemoteAddr: never trust X-Forwarded-For ===
		{
			name:       "public IP ignores XFF",
			remoteAddr: "203.0.113.1:1234",
			xff:        "10.0.0.1",
			want:       "203.0.113.1",
		},
		{
			name:       "public IP ignores XFF with real-looking client",
			remoteAddr: "198.51.100.1:1234",
			xff:        "203.0.113.50",
			want:       "198.51.100.1",
		},
		{
			name:       "public IP no XFF",
			remoteAddr: "203.0.113.1:1234",
			xff:        "",
			want:       "203.0.113.1",
		},

		// === Loopback: not private per net.IP.IsPrivate ===
		{
			name:       "loopback ignores XFF",
			remoteAddr: "127.0.0.1:1234",
			xff:        "203.0.113.50",
			want:       "127.0.0.1",
		},

		// === Link-local: not private per net.IP.IsPrivate ===
		{
			name:       "link-local ignores XFF",
			remoteAddr: "169.254.1.1:1234",
			xff:        "203.0.113.50",
			want:       "169.254.1.1",
		},

		// === IPv6 ===
		{
			name:       "IPv6 private trusts XFF",
			remoteAddr: "[fd00::1]:1234",
			xff:        "2001:db8::1",
			want:       "2001:db8::1",
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

		// === Edge cases ===
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
		{
			name:       "XFF with single entry from private",
			remoteAddr: "10.0.0.1:8080",
			xff:        "192.0.2.1",
			want:       "192.0.2.1",
		},

		// === Invalid XFF values: fall back to RemoteAddr ===
		{
			name:       "XFF garbage string falls back to RemoteAddr",
			remoteAddr: "10.0.0.1:1234",
			xff:        "not-an-ip",
			want:       "10.0.0.1",
		},
		{
			name:       "XFF empty after trim falls back to RemoteAddr",
			remoteAddr: "10.0.0.1:1234",
			xff:        "  ,10.0.0.2",
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
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = tt.remoteAddr
			if tt.xff != "" {
				r.Header.Set("X-Forwarded-For", tt.xff)
			}

			got := extractRealClientAddr(r, 0)
			if got != tt.want {
				t.Errorf("extractRealClientAddr() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestClientIP_Middleware verifies the full middleware sets context correctly
func TestClientIP_Middleware(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		xff        string
		wantIP     string
	}{
		{
			name:       "middleware sets context from XFF behind private",
			remoteAddr: "10.0.0.1:1234",
			xff:        "203.0.113.50",
			wantIP:     "203.0.113.50",
		},
		{
			name:       "middleware sets context from RemoteAddr when public",
			remoteAddr: "203.0.113.1:1234",
			xff:        "10.0.0.1",
			wantIP:     "203.0.113.1",
		},
		{
			name:       "middleware sets context from RemoteAddr when no XFF",
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

			r := httptest.NewRequest(http.MethodGet, "/", nil)
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

// --- TrustedHops tests ---

func TestExtractRealClientAddr_TrustedHops(t *testing.T) {
	tests := []struct {
		name        string
		remoteAddr  string
		xff         string
		trustedHops int
		want        string
	}{
		{
			name:        "hops=0 takes first entry (default behavior)",
			remoteAddr:  "10.0.0.1:1234",
			xff:         "203.0.113.50, 10.0.0.5, 10.0.0.6",
			trustedHops: 0,
			want:        "203.0.113.50",
		},
		{
			name:        "hops=1 takes last entry",
			remoteAddr:  "10.0.0.1:1234",
			xff:         "203.0.113.50, 10.0.0.5, 10.0.0.6",
			trustedHops: 1,
			want:        "10.0.0.6",
		},
		{
			name:        "hops=2 takes second from end",
			remoteAddr:  "10.0.0.1:1234",
			xff:         "203.0.113.50, 10.0.0.5, 10.0.0.6",
			trustedHops: 2,
			want:        "10.0.0.5",
		},
		{
			name:        "hops=3 takes first (3rd from end of 3)",
			remoteAddr:  "10.0.0.1:1234",
			xff:         "203.0.113.50, 10.0.0.5, 10.0.0.6",
			trustedHops: 3,
			want:        "203.0.113.50",
		},
		{
			name:        "hops exceeds entries clamps to first",
			remoteAddr:  "10.0.0.1:1234",
			xff:         "203.0.113.50",
			trustedHops: 5,
			want:        "203.0.113.50",
		},
		{
			name:        "hops=1 single entry ALB scenario",
			remoteAddr:  "10.0.0.1:1234",
			xff:         "203.0.113.50",
			trustedHops: 1,
			want:        "203.0.113.50",
		},
		{
			name:        "hops ignored for public remote addr",
			remoteAddr:  "203.0.113.1:1234",
			xff:         "10.0.0.1, 10.0.0.2",
			trustedHops: 1,
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
			r := httptest.NewRequest(http.MethodGet, "/", nil)
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

func TestClientIPWithOptions_Middleware(t *testing.T) {
	var captured string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = ClientIPFromContext(r.Context())
	})

	// CDN -> ALB -> app: 2 hops, take 2nd from end
	handler := ClientIPWithOptions(ClientIPOptions{TrustedHops: 2})(inner)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.1:1234"
	r.Header.Set("X-Forwarded-For", "203.0.113.50, 10.0.0.5, 10.0.0.6")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if captured != "10.0.0.5" {
		t.Errorf("ClientIPFromContext() = %q, want 10.0.0.5", captured)
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
	f.Add("10.0.0.1:8080", "203.0.113.50, 10.0.0.1") // private remote, multiple XFF
	f.Add("203.0.113.50:443", "192.168.1.1")         // public remote, XFF
	f.Add("garbage", "")                             // malformed
	f.Add("[::1]:8080", "2001:db8::1")               // IPv6
	f.Add("127.0.0.1:80", "")                        // loopback, no XFF
	f.Fuzz(func(t *testing.T, remoteAddr, xff string) {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = remoteAddr
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		result := extractRealClientAddr(r, 0)
		// INVARIANT: must never panic
		// INVARIANT: must always return a non-empty string
		if result == "" {
			t.Error("extractRealClientAddr returned empty string")
		}
	})
}
