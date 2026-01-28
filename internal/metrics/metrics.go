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
	reg                *prometheus.Registry
	handler            http.Handler
	inflight           prometheus.Gauge
	reqTotal           *prometheus.CounterVec
	appDbQueriesTotal  *prometheus.CounterVec
	appDbReqDur        *prometheus.HistogramVec
	appDbQueriesPerReq *prometheus.HistogramVec
	appDbTimeReqDur    *prometheus.HistogramVec
	reqDur             *prometheus.HistogramVec
	respBytes          *prometheus.HistogramVec
	httpPanicTotal     prometheus.Counter
	buildInfo          *prometheus.GaugeVec

	reqDBStats ReqDBStatsFromContextFunc
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
		appDbQueriesTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "app_db_queries_total",
			Help: "Total number of database queries by method route and outcome",
		}, []string{"method", "route", "outcome"}),
		appDbReqDur: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "app_db_query_duration_seconds",
			Help:    "Duration of database requests by method route and outcome",
			Buckets: prometheus.ExponentialBuckets(0.001, 1.6, 16), // 1ms .. ~1.15s
		}, []string{"method", "route", "outcome"}),
		appDbQueriesPerReq: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "app_db_queries_per_request",
			Help:    "Number of database queries per http reuest by method and route",
			Buckets: []float64{1, 2, 3, 4, 5, 7, 10, 15, 20, 30, 40, 50, 75, 100},
		}, []string{"method", "route"}),
		appDbTimeReqDur: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "app_db_time_per_request_seconds",
			Help:    "Total time spent on database calls per http request by method and route",
			Buckets: prometheus.ExponentialBuckets(0.002, 1.6, 18), // 2ms .. ~4.3s
		}, []string{"method", "route"}),
		buildInfo: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "build_info",
			Help: "Build metadata (value is always 1)",
		}, []string{"app", "component", "version", "commit", "commit_date", "build_id", "build_date", "vcs_dirty", "go_version"}),
	}
	//reg.MustRegister(m.inflight, m.reqTotal, m.reqDur, m.respBytes, m.httpPanicTotal, m.buildInfo)
	reg.MustRegister(
		m.inflight,
		m.reqTotal,
		m.reqDur,
		m.respBytes,
		m.httpPanicTotal,
		m.appDbQueriesTotal,
		m.appDbReqDur,
		m.appDbQueriesPerReq,
		m.appDbTimeReqDur,
		m.buildInfo,
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

func (m *ServerMetrics) SetReqDBStatsFromContext(fn ReqDBStatsFromContextFunc) {
	m.reqDBStats = fn
}

func (m *ServerMetrics) ObserveDBQuery(ctx context.Context, method, route, outcome string, dur time.Duration) {
	if method == "" {
		method = "UNKNOWN"
	}
	if route == "" {
		route = "unknown"
	}
	if outcome == "" {
		outcome = "unknown"
	}

	m.appDbQueriesTotal.WithLabelValues(method, route, outcome).Inc()

	sec := dur.Seconds()
	if ex := traceExemplar(ctx); ex != nil {
		if eo, ok := m.appDbReqDur.WithLabelValues(method, route, outcome).(prometheus.ExemplarObserver); ok {
			eo.ObserveWithExemplar(sec, ex)
			return
		}
	}
	m.appDbReqDur.WithLabelValues(method, route, outcome).Observe(sec)
}
