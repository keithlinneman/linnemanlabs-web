package metrics

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/otel/trace"
)

type statusWriter struct {
	http.ResponseWriter
	status int
	n      int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}
func (w *statusWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(p)
	w.n += n
	return n, err
}

// Middleware measures inflight, total, duration, and size (safe labels).
type ctxKey string

const routeKey ctxKey = "route"

func (m *ServerMetrics) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		if chi.RouteContext(r.Context()) == nil {
			rctx := chi.NewRouteContext()
			r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
		}

		m.inflight.Inc()
		defer m.inflight.Dec()

		sw := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r)

		// Normalize default status (handlers that never Write/WriteHeader).
		statusCode := sw.status
		if statusCode == 0 {
			statusCode = http.StatusOK
		}

		method := r.Method
		ctx := r.Context()

		// Get route pattern (prefer chi route pattern, fall back to URL path).
		route := ""
		if rc := chi.RouteContext(ctx); rc != nil {
			route = rc.RoutePattern()
		}
		if route == "" {
			if v := r.Context().Value(routeKey); v != nil {
				if s, ok := v.(string); ok && s != "" {
					route = s
				}
			}
		}
		if route == "" {
			route = r.URL.Path
		}

		status := strconv.Itoa(statusCode)
		m.reqTotal.WithLabelValues(method, route, status).Inc()

		lat := time.Since(start).Seconds()
		if ex := traceExemplar(ctx); ex != nil {
			if eo, ok := m.reqDur.WithLabelValues(method, route).(prometheus.ExemplarObserver); ok {
				eo.ObserveWithExemplar(lat, ex)
			} else {
				m.reqDur.WithLabelValues(method, route).Observe(lat)
			}
		} else {
			m.reqDur.WithLabelValues(method, route).Observe(lat)
		}

		m.respBytes.WithLabelValues(method, route).Observe(float64(sw.n))
	})
}

// if a sampled trace is present attach its trace_id as an exemplar
func traceExemplar(ctx context.Context) prometheus.Labels {
	sc := trace.SpanContextFromContext(ctx)
	if !sc.IsValid() || !sc.IsSampled() {
		return nil
	}
	return prometheus.Labels{"trace_id": sc.TraceID().String()}
}
