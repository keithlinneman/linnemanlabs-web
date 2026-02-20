package metrics

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/keithlinneman/linnemanlabs-web/internal/version"
)

// New

func TestNew_ReturnsNonNil(t *testing.T) {
	m := New()
	if m == nil {
		t.Fatal("New() returned nil")
	}
}

func TestNew_RegistryPopulated(t *testing.T) {
	m := New()

	// MustRegister in New() would panic if any metric failed to register.
	// Verify the registry is functional by scraping it.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/metrics", nil)
	m.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	body := rec.Body.String()

	// Non-Vec metrics (gauge, counter) appear immediately
	immediateMetrics := []string{
		"http_inflight_requests",
		"http_panic_total",
		"http_requests_rate_limited_total",
		"profiling_active",
	}
	for _, name := range immediateMetrics {
		if !strings.Contains(body, name) {
			t.Errorf("metric %q not found in /metrics output", name)
		}
	}

	// Go/process collectors should be present
	if !strings.Contains(body, "go_goroutines") {
		t.Error("go collector metrics missing")
	}
}

func TestNew_GoCollectorPresent(t *testing.T) {
	m := New()

	families, _ := m.reg.Gather()
	names := make(map[string]bool)
	for _, f := range families {
		names[f.GetName()] = true
	}

	// Go collector should produce at least go_goroutines
	if !names["go_goroutines"] {
		t.Fatal("go_goroutines metric missing - Go collector not registered")
	}
}

func TestNew_ProcessCollectorPresent(t *testing.T) {
	m := New()

	families, _ := m.reg.Gather()
	names := make(map[string]bool)
	for _, f := range families {
		names[f.GetName()] = true
	}

	// Process collector should produce process_open_fds (on Linux)
	if !names["process_open_fds"] && !names["process_resident_memory_bytes"] {
		t.Log("process collector metrics not found - may be expected on some platforms")
	}
}

// Handler

func TestHandler_ReturnsNonNil(t *testing.T) {
	m := New()
	h := m.Handler()
	if h == nil {
		t.Fatal("Handler() returned nil")
	}
}

func TestHandler_ServesMetrics(t *testing.T) {
	m := New()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/metrics", nil)
	m.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "http_inflight_requests") {
		t.Fatal("metrics output missing http_inflight_requests")
	}
	if !strings.Contains(body, "go_goroutines") {
		t.Fatal("metrics output missing go_goroutines")
	}
}

func TestHandler_ContentType(t *testing.T) {
	m := New()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/metrics", nil)
	m.Handler().ServeHTTP(rec, req)

	ct := rec.Header().Get("Content-Type")
	// promhttp with OpenMetrics enabled produces either text/plain or application/openmetrics-text
	if !strings.Contains(ct, "text/plain") && !strings.Contains(ct, "openmetrics") {
		t.Fatalf("Content-Type = %q, want text/plain or openmetrics", ct)
	}
}

// IncHttpPanic

func TestIncHttpPanic(t *testing.T) {
	m := New()

	m.IncHttpPanic()
	m.IncHttpPanic()
	m.IncHttpPanic()

	val := counterValue(t, m.reg, "http_panic_total")
	if val != 3 {
		t.Fatalf("http_panic_total = %f, want 3", val)
	}
}

// IncRateLimitDenied

func TestIncRateLimitDenied(t *testing.T) {
	m := New()

	m.IncRateLimitDenied()
	m.IncRateLimitDenied()

	val := counterValue(t, m.reg, "http_requests_rate_limited_total")
	if val != 2 {
		t.Fatalf("http_requests_rate_limited_total = %f, want 2", val)
	}
}

// SetBuildInfoFromVersion

func TestSetBuildInfoFromVersion(t *testing.T) {
	m := New()

	dirty := true
	vi := version.Info{
		Version:    "1.2.3",
		Commit:     "abc123",
		CommitDate: "2025-01-01",
		BuildId:    "build-42",
		BuildDate:  "2025-01-01T00:00:00Z",
		GoVersion:  "go1.22.0",
		VCSDirty:   &dirty,
	}

	m.SetBuildInfoFromVersion("myapp", "server", vi)

	f := gatherMetric(t, m.reg, "build_info")
	if f == nil {
		t.Fatal("build_info metric not found")
	}

	metrics := f.GetMetric()
	if len(metrics) != 1 {
		t.Fatalf("build_info metric count = %d, want 1", len(metrics))
	}

	// Value should be 1
	if metrics[0].GetGauge().GetValue() != 1 {
		t.Fatalf("build_info value = %f, want 1", metrics[0].GetGauge().GetValue())
	}

	// Verify labels
	labels := make(map[string]string)
	for _, lp := range metrics[0].GetLabel() {
		labels[lp.GetName()] = lp.GetValue()
	}

	checks := map[string]string{
		"app":        "myapp",
		"component":  "server",
		"version":    "1.2.3",
		"commit":     "abc123",
		"build_id":   "build-42",
		"go_version": "go1.22.0",
		"vcs_dirty":  "true",
	}
	for k, want := range checks {
		if got := labels[k]; got != want {
			t.Errorf("build_info label %q = %q, want %q", k, got, want)
		}
	}
}

func TestSetBuildInfoFromVersion_NilVCSDirty(t *testing.T) {
	m := New()

	vi := version.Info{
		Version:  "dev",
		VCSDirty: nil,
	}

	m.SetBuildInfoFromVersion("app", "comp", vi)

	f := gatherMetric(t, m.reg, "build_info")
	if f == nil {
		t.Fatal("build_info not found")
	}

	labels := make(map[string]string)
	for _, lp := range f.GetMetric()[0].GetLabel() {
		labels[lp.GetName()] = lp.GetValue()
	}

	if labels["vcs_dirty"] != "unknown" {
		t.Fatalf("vcs_dirty = %q, want %q (nil should map to unknown)", labels["vcs_dirty"], "unknown")
	}
}

// Metrics handler serves after mutations

func TestHandler_ReflectsCounterIncrements(t *testing.T) {
	m := New()

	m.IncHttpPanic()
	m.IncRateLimitDenied()
	m.IncRateLimitDenied()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/metrics", nil)
	m.Handler().ServeHTTP(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, "http_panic_total") {
		t.Fatal("http_panic_total missing from /metrics output")
	}
	if !strings.Contains(body, "http_requests_rate_limited_total") {
		t.Fatal("rate limited total missing from /metrics output")
	}
}

// Isolation - each New() gets its own registry

func TestNew_IsolatedRegistries(t *testing.T) {
	m1 := New()
	m2 := New()

	m1.IncHttpPanic()
	m1.IncHttpPanic()

	val1 := counterValue(t, m1.reg, "http_panic_total")
	if val1 != 2 {
		t.Fatalf("m1 panic count = %f, want 2", val1)
	}

	// m2 should be unaffected
	// http_panic_total starts at 0 and won't appear in Gather until incremented.
	// Check by gathering and looking for it.
	f := gatherMetric(t, m2.reg, "http_panic_total")
	if f != nil {
		for _, metric := range f.GetMetric() {
			if metric.GetCounter().GetValue() != 0 {
				t.Fatalf("m2 panic count = %f, want 0", metric.GetCounter().GetValue())
			}
		}
	}
}

// Handler serves full scrape without error

func TestHandler_FullScrape(t *testing.T) {
	m := New()

	// Exercise all the metric types before scraping
	dirty := false
	m.SetBuildInfoFromVersion("test", "test", version.Info{Version: "test", VCSDirty: &dirty})
	m.IncHttpPanic()
	m.IncRateLimitDenied()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/metrics", nil)
	m.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	// Body should be substantial
	body, _ := io.ReadAll(rec.Result().Body)
	if len(body) < 500 {
		t.Fatalf("metrics body suspiciously small: %d bytes", len(body))
	}
}

// helpers

// gatherMetric collects metrics from the registry and finds one by name.
func gatherMetric(t *testing.T, reg *prometheus.Registry, name string) *dto.MetricFamily {
	t.Helper()
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, f := range families {
		if f.GetName() == name {
			return f
		}
	}
	return nil
}

// counterValue returns the value of the first metric in a counter family.
func counterValue(t *testing.T, reg *prometheus.Registry, name string) float64 {
	t.Helper()
	f := gatherMetric(t, reg, name)
	if f == nil {
		t.Fatalf("metric %q not found", name)
	}
	if len(f.GetMetric()) == 0 {
		t.Fatalf("metric %q has no samples", name)
	}
	return f.GetMetric()[0].GetCounter().GetValue()
}

// histogramCount returns the sample count of the first metric in a histogram family.
func histogramCount(t *testing.T, reg *prometheus.Registry, name string) uint64 {
	t.Helper()
	f := gatherMetric(t, reg, name)
	if f == nil {
		t.Fatalf("metric %q not found", name)
	}
	if len(f.GetMetric()) == 0 {
		t.Fatalf("metric %q has no samples", name)
	}
	return f.GetMetric()[0].GetHistogram().GetSampleCount()
}

func TestNew_ResponseSizeBuckets(t *testing.T) {
	m := New()

	// Exercise the histogram so it appears in gather output
	handler := m.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("x"))
	}))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))

	f := gatherMetric(t, m.reg, "http_response_size_bytes")
	if f == nil {
		t.Fatal("http_response_size_bytes not found")
	}
	h := f.GetMetric()[0].GetHistogram()
	buckets := h.GetBucket()
	if len(buckets) == 0 {
		t.Fatal("expected histogram buckets")
	}
	largest := buckets[len(buckets)-1].GetUpperBound()
	if largest < 50_000_000 {
		t.Fatalf("largest bucket = %f, want >= 50MB", largest)
	}
}

// Watcher metrics

func TestIncWatcherPolls(t *testing.T) {
	m := New()
	m.IncWatcherPolls()
	m.IncWatcherPolls()

	val := counterValue(t, m.reg, "content_watcher_polls_total")
	if val != 2 {
		t.Fatalf("content_watcher_polls_total = %f, want 2", val)
	}
}

func TestIncWatcherSwaps(t *testing.T) {
	m := New()
	m.IncWatcherSwaps()

	val := counterValue(t, m.reg, "content_watcher_swaps_total")
	if val != 1 {
		t.Fatalf("content_watcher_swaps_total = %f, want 1", val)
	}
}

func TestIncWatcherError(t *testing.T) {
	m := New()
	m.IncWatcherError("ssm")
	m.IncWatcherError("ssm")
	m.IncWatcherError("load")

	f := gatherMetric(t, m.reg, "content_watcher_errors_total")
	if f == nil {
		t.Fatal("content_watcher_errors_total not found")
	}
	// Should have 2 distinct label sets
	if len(f.GetMetric()) != 2 {
		t.Fatalf("expected 2 error type combos, got %d", len(f.GetMetric()))
	}
}

func TestObserveBundleLoadDuration(t *testing.T) {
	m := New()
	m.ObserveBundleLoadDuration(1.5)
	m.ObserveBundleLoadDuration(2.5)

	count := histogramCount(t, m.reg, "content_bundle_load_duration_seconds")
	if count != 2 {
		t.Fatalf("content_bundle_load_duration_seconds count = %d, want 2", count)
	}
}

func TestSetWatcherLastSuccess(t *testing.T) {
	m := New()
	m.SetWatcherLastSuccess(1700000000)

	f := gatherMetric(t, m.reg, "content_watcher_last_success_timestamp_seconds")
	if f == nil {
		t.Fatal("content_watcher_last_success_timestamp_seconds not found")
	}
	val := f.GetMetric()[0].GetGauge().GetValue()
	if val != 1700000000 {
		t.Fatalf("value = %f, want 1700000000", val)
	}
}

func TestSetProfilingActive_True(t *testing.T) {
	m := New()
	m.SetProfilingActive(true)

	f := gatherMetric(t, m.reg, "profiling_active")
	if f == nil {
		t.Fatal("profiling_active metric not found")
	}
	val := f.GetMetric()[0].GetGauge().GetValue()
	if val != 1 {
		t.Fatalf("profiling_active = %f, want 1", val)
	}
}

func TestSetProfilingActive_False(t *testing.T) {
	m := New()
	m.SetProfilingActive(false)

	f := gatherMetric(t, m.reg, "profiling_active")
	if f == nil {
		t.Fatal("profiling_active metric not found")
	}
	val := f.GetMetric()[0].GetGauge().GetValue()
	if val != 0 {
		t.Fatalf("profiling_active = %f, want 0", val)
	}
}

// 5xx error counter

func TestMiddleware_5xxIncrementsErrorCounter(t *testing.T) {
	m := New()
	handler := m.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))

	f := gatherMetric(t, m.reg, "http_errors_total")
	if f == nil {
		t.Fatal("http_errors_total not found after 500 response")
	}
	val := f.GetMetric()[0].GetCounter().GetValue()
	if val != 1 {
		t.Fatalf("http_errors_total = %f, want 1", val)
	}
}

func TestMiddleware_4xxDoesNotIncrementErrorCounter(t *testing.T) {
	m := New()
	handler := m.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))

	f := gatherMetric(t, m.reg, "http_errors_total")
	if f != nil {
		t.Fatal("http_errors_total should not be present after 404 response")
	}
}

func TestMiddleware_200DoesNotIncrementErrorCounter(t *testing.T) {
	m := New()
	handler := m.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))

	f := gatherMetric(t, m.reg, "http_errors_total")
	if f != nil {
		t.Fatal("http_errors_total should not be present after 200 response")
	}
}

// Watcher stale gauge

func TestSetWatcherStale_True(t *testing.T) {
	m := New()
	m.SetWatcherStale(true)

	f := gatherMetric(t, m.reg, "content_watcher_stale")
	if f == nil {
		t.Fatal("content_watcher_stale metric not found")
	}
	val := f.GetMetric()[0].GetGauge().GetValue()
	if val != 1 {
		t.Fatalf("content_watcher_stale = %f, want 1", val)
	}
}

func TestSetWatcherStale_False(t *testing.T) {
	m := New()
	m.SetWatcherStale(false)

	f := gatherMetric(t, m.reg, "content_watcher_stale")
	if f == nil {
		t.Fatal("content_watcher_stale metric not found")
	}
	val := f.GetMetric()[0].GetGauge().GetValue()
	if val != 0 {
		t.Fatalf("content_watcher_stale = %f, want 0", val)
	}
}

func TestSetContentBundle(t *testing.T) {
	m := New()
	m.SetContentBundle("abc123")
	m.SetContentBundle("def456") // verify Reset doesn't panic on second call
}
