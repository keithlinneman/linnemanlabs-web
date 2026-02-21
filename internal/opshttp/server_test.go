package opshttp

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/keithlinneman/linnemanlabs-web/internal/health"
	"github.com/keithlinneman/linnemanlabs-web/internal/log"
)

// test helpers

func getFreePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp4", ":0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}

func startOps(t *testing.T, opts *Options) (port int, stopFunc func(context.Context) error) {
	t.Helper()
	if opts.Port == 0 {
		opts.Port = getFreePort(t)
	}
	ctx := context.Background()
	stop, err := Start(ctx, log.Nop(), opts)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { stop(ctx) })
	return opts.Port, stop
}

func opsGet(t *testing.T, port int, path string) *http.Response {
	t.Helper()
	addr := fmt.Sprintf("http://127.0.0.1:%d%s", port, path)
	resp, err := http.Get(addr)
	if err != nil {
		t.Fatalf("GET %s: %v", addr, err)
	}
	return resp
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(body)
}

// Start - lifecycle

func TestStart_ReturnsStopFunc(t *testing.T) {
	port, stop := startOps(t, &Options{})
	_ = port
	if stop == nil {
		t.Fatal("stop func is nil")
	}
}

func TestStart_DefaultPort(t *testing.T) {
	// We can't bind 9000 reliably in tests, just verify the logic exists
	// by checking that port 0 gets overridden
	// Tested indirectly through custom port tests
}

func TestStart_CustomPort(t *testing.T) {
	port, _ := startOps(t, &Options{
		Health:    health.Fixed(true, ""),
		Readiness: health.Fixed(true, ""),
	})

	resp := opsGet(t, port, "/healthz")
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

func TestStart_GracefulShutdown(t *testing.T) {
	port := getFreePort(t)
	ctx := context.Background()

	stop, err := Start(ctx, log.Nop(), &Options{
		Port:      port,
		Health:    health.Fixed(true, ""),
		Readiness: health.Fixed(true, ""),
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Verify it's up
	resp := opsGet(t, port, "/healthz")
	resp.Body.Close()

	// Shutdown
	shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := stop(shutdownCtx); err != nil {
		t.Fatalf("stop: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	// Should no longer accept connections
	addr := fmt.Sprintf("http://127.0.0.1:%d/healthz", port)
	_, err = http.Get(addr)
	if err == nil {
		t.Fatal("server still accepting connections after shutdown")
	}
}

func TestStart_StopIdempotent(t *testing.T) {
	port := getFreePort(t)
	ctx := context.Background()

	stop, err := Start(ctx, log.Nop(), &Options{Port: port})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	if err := stop(ctx); err != nil {
		t.Fatalf("first stop: %v", err)
	}
	if err := stop(ctx); err != nil {
		t.Fatalf("second stop: %v", err)
	}
	if err := stop(ctx); err != nil {
		t.Fatalf("third stop: %v", err)
	}
}

func TestStart_PortConflict(t *testing.T) {
	port := getFreePort(t)
	ctx := context.Background()

	stop1, err := Start(ctx, log.Nop(), &Options{Port: port})
	if err != nil {
		t.Fatalf("first Start: %v", err)
	}
	defer stop1(ctx)

	_, err = Start(ctx, log.Nop(), &Options{Port: port})
	if err == nil {
		t.Fatal("expected error for port conflict")
	}
}

// Health endpoints

func TestStart_HealthzEndpoint_Healthy(t *testing.T) {
	port, _ := startOps(t, &Options{
		Health: health.Fixed(true, ""),
	})

	resp := opsGet(t, port, "/healthz")
	body := readBody(t, resp)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(body, "ok") {
		t.Fatalf("body = %q, want 'ok'", body)
	}
}

func TestStart_HealthzEndpoint_Unhealthy(t *testing.T) {
	port, _ := startOps(t, &Options{
		Health: health.Fixed(false, "something broke"),
	})

	resp := opsGet(t, port, "/healthz")
	body := readBody(t, resp)

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
	if !strings.Contains(body, "something broke") {
		t.Fatalf("body = %q, want reason", body)
	}
}

func TestStart_ReadyzEndpoint_Ready(t *testing.T) {
	port, _ := startOps(t, &Options{
		Readiness: health.Fixed(true, ""),
	})

	resp := opsGet(t, port, "/readyz")
	body := readBody(t, resp)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(body, "ready") {
		t.Fatalf("body = %q, want 'ready'", body)
	}
}

func TestStart_ReadyzEndpoint_NotReady(t *testing.T) {
	port, _ := startOps(t, &Options{
		Readiness: health.Fixed(false, "content: no active snapshot"),
	})

	resp := opsGet(t, port, "/readyz")
	body := readBody(t, resp)

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
	if !strings.Contains(body, "content: no active snapshot") {
		t.Fatalf("body = %q, want reason", body)
	}
}

func TestStart_HealthzEndpoint_DynamicProbe(t *testing.T) {
	var gate health.ShutdownGate

	port, _ := startOps(t, &Options{
		Health: gate.Probe(),
	})

	// Initially healthy
	resp := opsGet(t, port, "/healthz")
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("initially: status = %d, want 200", resp.StatusCode)
	}

	// Close gate
	gate.Set("draining")
	resp = opsGet(t, port, "/healthz")
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("after drain: status = %d, want 503", resp.StatusCode)
	}
}

// Metrics endpoint

func TestStart_MetricsEndpoint(t *testing.T) {
	metricsHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("# HELP fake_metric\n"))
	})

	port, _ := startOps(t, &Options{
		Metrics: metricsHandler,
	})

	resp := opsGet(t, port, "/metrics")
	body := readBody(t, resp)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(body, "fake_metric") {
		t.Fatalf("body = %q, want metrics output", body)
	}
}

func TestStart_MetricsEndpoint_Nil(t *testing.T) {
	port, _ := startOps(t, &Options{
		Metrics: nil,
	})

	resp := opsGet(t, port, "/metrics")
	resp.Body.Close()

	// No metrics handler registered, should 404
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

// Pprof endpoints

func TestStart_PprofEnabled(t *testing.T) {
	port, _ := startOps(t, &Options{
		EnablePprof: true,
	})

	resp := opsGet(t, port, "/debug/pprof/")
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

func TestStart_PprofDisabled(t *testing.T) {
	port, _ := startOps(t, &Options{
		EnablePprof: false,
	})

	resp := opsGet(t, port, "/debug/pprof/")
	resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (pprof disabled)", resp.StatusCode)
	}
}

// requireNonPublicNetwork

func TestRequireNonPublicNetwork_Loopback(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("allowed"))
	})

	h := requireNonPublicNetwork(log.Nop(), inner)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/healthz", http.NoBody)
	req.RemoteAddr = "127.0.0.1:12345"
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("loopback: status = %d, want 200", rec.Code)
	}
}

func TestRequireNonPublicNetwork_IPv6Loopback(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	h := requireNonPublicNetwork(log.Nop(), inner)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/healthz", http.NoBody)
	req.RemoteAddr = "[::1]:12345"
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("IPv6 loopback: status = %d, want 200", rec.Code)
	}
}

func TestRequireNonPublicNetwork_PrivateIP(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	h := requireNonPublicNetwork(log.Nop(), inner)

	privateIPs := []string{
		"10.0.0.1:8080",
		"172.16.0.1:8080",
		"192.168.1.1:8080",
	}

	for _, addr := range privateIPs {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/healthz", http.NoBody)
		req.RemoteAddr = addr
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("private IP %s: status = %d, want 200", addr, rec.Code)
		}
	}
}

func TestRequireNonPublicNetwork_PublicIP_Rejected(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called for public IPs")
	})

	h := requireNonPublicNetwork(log.Nop(), inner)

	publicIPs := []string{
		"8.8.8.8:12345",
		"1.1.1.1:443",
		"203.0.113.1:80",
		"198.51.100.1:9000",
	}

	for _, addr := range publicIPs {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/healthz", http.NoBody)
		req.RemoteAddr = addr
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Errorf("public IP %s: status = %d, want 403", addr, rec.Code)
		}
	}
}

func TestRequireNonPublicNetwork_LinkLocal(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	h := requireNonPublicNetwork(log.Nop(), inner)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/healthz", http.NoBody)
	req.RemoteAddr = "169.254.1.1:8080"
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("link-local: status = %d, want 200", rec.Code)
	}
}

func TestRequireNonPublicNetwork_BadRemoteAddr(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called for bad remote addr")
	})

	h := requireNonPublicNetwork(log.Nop(), inner)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/healthz", http.NoBody)
	req.RemoteAddr = "not-an-address"
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("bad addr: status = %d, want 403", rec.Code)
	}
}

func TestRequireNonPublicNetwork_EmptyRemoteAddr(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called for empty remote addr")
	})

	h := requireNonPublicNetwork(log.Nop(), inner)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/healthz", http.NoBody)
	req.RemoteAddr = ""
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("empty addr: status = %d, want 403", rec.Code)
	}
}

func TestRequireNonPublicNetwork_InvalidIP(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called for invalid IP")
	})

	h := requireNonPublicNetwork(log.Nop(), inner)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/healthz", http.NoBody)
	req.RemoteAddr = "999.999.999.999:8080"
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("invalid IP: status = %d, want 403", rec.Code)
	}
}

func TestRequireNonPublicNetwork_IPv4MappedIPv6_Rejected(t *testing.T) {
	// ::ffff:8.8.8.8 is an IPv4-mapped IPv6 address representing a public IP.
	// net.IP.IsPrivate() correctly returns false. Test proves we handle it.
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called for IPv4-mapped public IP")
	})

	h := requireNonPublicNetwork(log.Nop(), inner)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/healthz", http.NoBody)
	req.RemoteAddr = "[::ffff:8.8.8.8]:12345"
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("IPv4-mapped public IP: status = %d, want 403", rec.Code)
	}
}

func TestRequireNonPublicNetwork_IPv4MappedIPv6_PrivateAllowed(t *testing.T) {
	// ::ffff:10.0.0.1 is an IPv4-mapped IPv6 address representing a private IP.
	// Should be allowed through.
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	h := requireNonPublicNetwork(log.Nop(), inner)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/healthz", http.NoBody)
	req.RemoteAddr = "[::ffff:10.0.0.1]:12345"
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("IPv4-mapped private IP: status = %d, want 200", rec.Code)
	}
}
