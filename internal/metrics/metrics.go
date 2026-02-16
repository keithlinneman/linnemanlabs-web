package metrics

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/keithlinneman/linnemanlabs-web/internal/version"
)

// ReqDBStatsFromContextFunc is injected at wiring-time in main() so the metrics package doesn't need to import postgres.
type ReqDBStatsFromContextFunc func(ctx context.Context) (count int64, errs int64, total time.Duration, ok bool)

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
	contentSource          *prometheus.GaugeVec
	contentLoadedTimestamp prometheus.Gauge
	contentBundleInfo      *prometheus.GaugeVec
	reqDBStats             ReqDBStatsFromContextFunc
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
			Buckets: prometheus.ExponentialBuckets(200, 2, 10),
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
	}
	//reg.MustRegister(m.inflight, m.reqTotal, m.reqDur, m.respBytes, m.httpPanicTotal, m.buildInfo)
	reg.MustRegister(
		m.inflight,
		m.reqTotal,
		m.reqDur,
		m.respBytes,
		m.httpPanicTotal,
		m.buildInfo,
		m.ratelimitDeniedTotal,
		m.contentSource,
		m.contentLoadedTimestamp,
		m.contentBundleInfo,
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
func (m *ServerMetrics) SetBuildInfoFromVersion(app, component string, vi version.Info) {
	dirty := "unknown"
	if vi.VCSDirty != nil {
		dirty = strconv.FormatBool(*vi.VCSDirty)
	}
	//m.BuildInfo.WithLabelValues(app, component, vi.Version, vi.Commit, vi.CommitDate, vi.BuildId, vi.BuildDate, dirty, vi.GoVersion).Set(1)
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
