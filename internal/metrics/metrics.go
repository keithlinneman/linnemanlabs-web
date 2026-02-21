package metrics

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/keithlinneman/linnemanlabs-web/internal/version"
)

type ServerMetrics struct {
	reg                    *prometheus.Registry
	handler                http.Handler
	inflight               prometheus.Gauge
	reqTotal               *prometheus.CounterVec
	reqDur                 *prometheus.HistogramVec
	respBytes              *prometheus.HistogramVec
	httpPanicTotal         prometheus.Counter
	buildInfo              *prometheus.GaugeVec
	ratelimitDeniedTotal   prometheus.Counter
	ratelimitCapacityTotal prometheus.Counter
	contentSource          *prometheus.GaugeVec
	contentLoadedTimestamp prometheus.Gauge
	contentBundleInfo      *prometheus.GaugeVec

	errorsTotal *prometheus.CounterVec

	profilingActive prometheus.Gauge

	// watcher metrics
	watcherPollsTotal    prometheus.Counter
	watcherSwapsTotal    prometheus.Counter
	watcherErrorsTotal   *prometheus.CounterVec
	bundleLoadDuration   prometheus.Histogram
	watcherLastSuccessTs prometheus.Gauge
	watcherStale         prometheus.Gauge
}

// New returns a fresh registry + standard collectors + HTTP metrics
// safe labels only (method, route, code) to avoid path/cardinality explosions
func New() *ServerMetrics {
	reg := prometheus.NewRegistry()
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	m := &ServerMetrics{
		inflight: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "http_inflight_requests",
			Help: "Current number of in-flight HTTP requests",
		}),
		reqTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total HTTP requests by method, route, and status",
		}, []string{"method", "route", "status"}),
		reqDur: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "Request latency by method and route",
			Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
		}, []string{"method", "route"}),
		respBytes: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "http_response_size_bytes",
			Help:    "Response size by method and route",
			Buckets: []float64{256, 1024, 4096, 16384, 65536, 262144, 1048576, 4194304, 16777216, 52428800},
		}, []string{"method", "route"}),
		httpPanicTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "http_panic_total",
			Help: "Total number of recovered httpserver panics",
		}),
		buildInfo: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "build_info",
			Help: "Build metadata (value is always 1)",
		}, []string{"app", "component", "version", "commit", "commit_date", "build_id", "build_date", "vcs_dirty", "go_version"}),
		ratelimitDeniedTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "http_requests_rate_limited_total",
			Help: "Total requests rejected by rate limiter",
		}),
		ratelimitCapacityTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "http_requests_rate_limited_capacity_total",
			Help: "Total number of times rate limiter capacity reached",
		}),
		contentSource: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "content_source_info",
			Help: "Current content source (label carries value, gauge is always 1)",
		}, []string{"source"}),
		contentLoadedTimestamp: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "content_loaded_timestamp_seconds",
			Help: "Unix timestamp of when the current content bundle was loaded",
		}),
		contentBundleInfo: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "content_bundle_info",
			Help: "Currently active content bundle (label carries identity, value is always 1)",
		}, []string{"sha256"}),
		errorsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "http_errors_total",
			Help: "Total 5xx HTTP server errors by method and route (SLI)",
		}, []string{"method", "route"}),
		profilingActive: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "profiling_active",
			Help: "Whether continuous profiling is active (1) or disabled/failed (0)",
		}),
		watcherPollsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "content_watcher_polls_total",
			Help: "Total number of watcher poll cycles",
		}),
		watcherSwapsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "content_watcher_swaps_total",
			Help: "Total number of successful content bundle swaps",
		}),
		watcherErrorsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "content_watcher_errors_total",
			Help: "Total watcher errors by type",
		}, []string{"type"}),
		bundleLoadDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "content_bundle_load_duration_seconds",
			Help:    "Time to download, verify, and extract a content bundle",
			Buckets: []float64{0.5, 1, 2.5, 5, 10, 30, 60},
		}),
		watcherLastSuccessTs: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "content_watcher_last_success_timestamp_seconds",
			Help: "Unix timestamp of the last successful SSM poll",
		}),
		watcherStale: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "content_watcher_stale",
			Help: "Whether the content watcher is stale (1) or healthy (0)",
		}),
	}
	reg.MustRegister(
		m.inflight,
		m.reqTotal,
		m.reqDur,
		m.respBytes,
		m.httpPanicTotal,
		m.buildInfo,
		m.ratelimitDeniedTotal,
		m.ratelimitCapacityTotal,
		m.contentSource,
		m.contentLoadedTimestamp,
		m.contentBundleInfo,
		m.errorsTotal,
		m.profilingActive,
		m.watcherPollsTotal,
		m.watcherSwapsTotal,
		m.watcherErrorsTotal,
		m.bundleLoadDuration,
		m.watcherLastSuccessTs,
		m.watcherStale,
	)

	m.handler = promhttp.HandlerFor(reg, promhttp.HandlerOpts{
		EnableOpenMetrics: true,
	})
	m.reg = reg
	return m
}

func (m *ServerMetrics) IncHttpPanic() {
	m.httpPanicTotal.Inc()
}

func (m *ServerMetrics) Handler() http.Handler {
	return m.handler
}

// set once at startup.
func (m *ServerMetrics) SetBuildInfoFromVersion(app, component string, vi *version.Info) {
	dirty := "unknown"
	if vi.VCSDirty != nil {
		dirty = strconv.FormatBool(*vi.VCSDirty)
	}
	m.buildInfo.With(prometheus.Labels{
		"app":         app,
		"component":   component,
		"version":     vi.Version,
		"commit":      vi.Commit,
		"commit_date": vi.CommitDate,
		"build_id":    vi.BuildId,
		"build_date":  vi.BuildDate,
		"go_version":  vi.GoVersion,
		"vcs_dirty":   dirty,
	}).Set(1)
}

func (m *ServerMetrics) IncRateLimitDenied() {
	m.ratelimitDeniedTotal.Inc()
}

func (m *ServerMetrics) IncRateLimitCapacity() {
	m.ratelimitCapacityTotal.Inc()
}

func (m *ServerMetrics) SetContentSource(source string) {
	m.contentSource.Reset() // clear previous label value
	m.contentSource.WithLabelValues(source).Set(1)
}

func (m *ServerMetrics) SetContentLoadedTimestamp(t time.Time) {
	m.contentLoadedTimestamp.Set(float64(t.Unix()))
}

func (m *ServerMetrics) SetContentBundle(sha256 string) {
	m.contentBundleInfo.Reset()
	m.contentBundleInfo.WithLabelValues(sha256).Set(1)
}

func (m *ServerMetrics) SetProfilingActive(active bool) {
	if active {
		m.profilingActive.Set(1)
	} else {
		m.profilingActive.Set(0)
	}
}

func (m *ServerMetrics) IncWatcherPolls() {
	m.watcherPollsTotal.Inc()
}

func (m *ServerMetrics) IncWatcherSwaps() {
	m.watcherSwapsTotal.Inc()
}

func (m *ServerMetrics) IncWatcherError(errType string) {
	m.watcherErrorsTotal.WithLabelValues(errType).Inc()
}

func (m *ServerMetrics) ObserveBundleLoadDuration(seconds float64) {
	m.bundleLoadDuration.Observe(seconds)
}

func (m *ServerMetrics) SetWatcherLastSuccess(unixSeconds float64) {
	m.watcherLastSuccessTs.Set(unixSeconds)
}

func (m *ServerMetrics) SetWatcherStale(stale bool) {
	if stale {
		m.watcherStale.Set(1)
	} else {
		m.watcherStale.Set(0)
	}
}
