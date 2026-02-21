package metrics

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"go.opentelemetry.io/otel/trace"
)

// statusWriter

func TestStatusWriter_WriteHeader(t *testing.T) {
	rec := httptest.NewRecorder()
	sw := &statusWriter{ResponseWriter: rec}

	sw.WriteHeader(http.StatusNotFound)

	if sw.status != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", sw.status)
	}
	if rec.Code != http.StatusNotFound {
		t.Fatalf("underlying code = %d, want 404", rec.Code)
	}
}

func TestStatusWriter_Write_DefaultsTo200(t *testing.T) {
	rec := httptest.NewRecorder()
	sw := &statusWriter{ResponseWriter: rec}

	n, err := sw.Write([]byte("hello"))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != 5 {
		t.Fatalf("n = %d, want 5", n)
	}
	if sw.status != http.StatusOK {
		t.Fatalf("status = %d, want 200", sw.status)
	}
	if sw.n != 5 {
		t.Fatalf("bytes = %d, want 5", sw.n)
	}
}

func TestStatusWriter_Write_AccumulatesBytes(t *testing.T) {
	rec := httptest.NewRecorder()
	sw := &statusWriter{ResponseWriter: rec}

	sw.Write([]byte("aaa"))
	sw.Write([]byte("bbbbb"))

	if sw.n != 8 {
		t.Fatalf("bytes = %d, want 8", sw.n)
	}
}

func TestStatusWriter_WriteHeader_ThenWrite(t *testing.T) {
	rec := httptest.NewRecorder()
	sw := &statusWriter{ResponseWriter: rec}

	sw.WriteHeader(http.StatusCreated)
	sw.Write([]byte("body"))

	if sw.status != http.StatusCreated {
		t.Fatalf("status = %d, want 201", sw.status)
	}
	if sw.n != 4 {
		t.Fatalf("bytes = %d, want 4", sw.n)
	}
}

// Middleware - basic behavior

func TestMiddleware_IncrementsReqTotal(t *testing.T) {
	m := New()

	handler := m.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/test", http.NoBody)
	handler.ServeHTTP(rec, req)

	f := gatherMetric(t, m.reg, "http_requests_total")
	if f == nil {
		t.Fatal("http_requests_total not found")
	}

	var total float64
	for _, metric := range f.GetMetric() {
		total += metric.GetCounter().GetValue()
	}
	if total != 1 {
		t.Fatalf("http_requests_total = %f, want 1", total)
	}
}

func TestMiddleware_CorrectLabels(t *testing.T) {
	m := New()

	handler := m.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/missing", http.NoBody)
	handler.ServeHTTP(rec, req)

	f := gatherMetric(t, m.reg, "http_requests_total")
	if f == nil {
		t.Fatal("metric not found")
	}

	metric := f.GetMetric()[0]
	labels := make(map[string]string)
	for _, lp := range metric.GetLabel() {
		labels[lp.GetName()] = lp.GetValue()
	}

	if labels["method"] != http.MethodPost {
		t.Fatalf("method = %q, want POST", labels["method"])
	}
	if labels["status"] != "404" {
		t.Fatalf("status = %q, want 404", labels["status"])
	}
	if labels["route"] != "unmatched" {
		t.Fatalf("route = %q, want unmatched", labels["route"])
	}
}

func TestMiddleware_DefaultStatus200(t *testing.T) {
	m := New()

	handler := m.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handler that writes without calling WriteHeader
		w.Write([]byte("implicit 200"))
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	handler.ServeHTTP(rec, req)

	f := gatherMetric(t, m.reg, "http_requests_total")
	metric := f.GetMetric()[0]
	labels := make(map[string]string)
	for _, lp := range metric.GetLabel() {
		labels[lp.GetName()] = lp.GetValue()
	}

	if labels["status"] != "200" {
		t.Fatalf("status = %q, want 200", labels["status"])
	}
}

func TestMiddleware_NoWriteDefaultsTo200(t *testing.T) {
	m := New()

	// Handler that does nothing - never calls Write or WriteHeader
	handler := m.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	handler.ServeHTTP(rec, req)

	f := gatherMetric(t, m.reg, "http_requests_total")
	labels := make(map[string]string)
	for _, lp := range f.GetMetric()[0].GetLabel() {
		labels[lp.GetName()] = lp.GetValue()
	}

	if labels["status"] != "200" {
		t.Fatalf("status = %q, want 200 (handler wrote nothing)", labels["status"])
	}
}

// Middleware - inflight gauge

func TestMiddleware_InflightGauge(t *testing.T) {
	m := New()

	var inflightDuring float64
	handler := m.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Capture inflight count while handler is running
		f := gatherMetric(t, m.reg, "http_inflight_requests")
		if f != nil && len(f.GetMetric()) > 0 {
			inflightDuring = f.GetMetric()[0].GetGauge().GetValue()
		}
		w.WriteHeader(http.StatusOK)
	}))

	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", http.NoBody))

	if inflightDuring != 1 {
		t.Fatalf("inflight during request = %f, want 1", inflightDuring)
	}

	// After request completes, inflight should be back to 0
	f := gatherMetric(t, m.reg, "http_inflight_requests")
	if f != nil && len(f.GetMetric()) > 0 {
		after := f.GetMetric()[0].GetGauge().GetValue()
		if after != 0 {
			t.Fatalf("inflight after request = %f, want 0", after)
		}
	}
}

// Middleware - duration histogram

func TestMiddleware_RecordsDuration(t *testing.T) {
	m := New()

	handler := m.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/test", http.NoBody))

	count := histogramCount(t, m.reg, "http_request_duration_seconds")
	if count != 1 {
		t.Fatalf("duration histogram count = %d, want 1", count)
	}
}

// Middleware - response size histogram

func TestMiddleware_RecordsResponseSize(t *testing.T) {
	m := New()

	handler := m.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("hello world")) // 11 bytes
	}))

	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", http.NoBody))

	f := gatherMetric(t, m.reg, "http_response_size_bytes")
	if f == nil {
		t.Fatal("http_response_size_bytes not found")
	}
	h := f.GetMetric()[0].GetHistogram()
	if h.GetSampleCount() != 1 {
		t.Fatalf("response size count = %d, want 1", h.GetSampleCount())
	}
	if h.GetSampleSum() != 11 {
		t.Fatalf("response size sum = %f, want 11", h.GetSampleSum())
	}
}

// Middleware - chi route pattern

func TestMiddleware_ChiRoutePattern(t *testing.T) {
	m := New()

	r := chi.NewRouter()
	r.Use(m.Middleware)
	r.Get("/users/{id}", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/users/42", http.NoBody)
	r.ServeHTTP(rec, req)

	f := gatherMetric(t, m.reg, "http_requests_total")
	if f == nil {
		t.Fatal("metric not found")
	}

	labels := make(map[string]string)
	for _, lp := range f.GetMetric()[0].GetLabel() {
		labels[lp.GetName()] = lp.GetValue()
	}

	if labels["route"] != "/users/{id}" {
		t.Fatalf("route = %q, want /users/{id}", labels["route"])
	}
}

func TestMiddleware_FallsBackToUnmatched(t *testing.T) {
	m := New()

	// No chi router - middleware creates its own route context
	handler := m.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/custom/path", http.NoBody))

	f := gatherMetric(t, m.reg, "http_requests_total")
	labels := make(map[string]string)
	for _, lp := range f.GetMetric()[0].GetLabel() {
		labels[lp.GetName()] = lp.GetValue()
	}

	if labels["route"] != "unmatched" {
		t.Fatalf("route = %q, want unmatched", labels["route"])
	}
}

// Middleware - multiple requests accumulate

func TestMiddleware_MultipleRequests(t *testing.T) {
	m := New()

	handler := m.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))

	for i := 0; i < 10; i++ {
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/data", http.NoBody))
	}

	f := gatherMetric(t, m.reg, "http_requests_total")
	var total float64
	for _, metric := range f.GetMetric() {
		total += metric.GetCounter().GetValue()
	}
	if total != 10 {
		t.Fatalf("total requests = %f, want 10", total)
	}

	durCount := histogramCount(t, m.reg, "http_request_duration_seconds")
	if durCount != 10 {
		t.Fatalf("duration count = %d, want 10", durCount)
	}
}

func TestMiddleware_DifferentMethods(t *testing.T) {
	m := New()

	handler := m.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api", http.NoBody))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api", http.NoBody))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPut, "/api", http.NoBody))

	f := gatherMetric(t, m.reg, "http_requests_total")
	if len(f.GetMetric()) != 3 {
		t.Fatalf("expected 3 distinct method label combos, got %d", len(f.GetMetric()))
	}
}

// Middleware - creates chi route context when missing

func TestMiddleware_CreatesRouteContext(t *testing.T) {
	m := New()

	var hasRouteCtx bool
	handler := m.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hasRouteCtx = chi.RouteContext(r.Context()) != nil
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	handler.ServeHTTP(httptest.NewRecorder(), req)

	if !hasRouteCtx {
		t.Fatal("middleware should inject chi route context when missing")
	}
}

// traceExemplar

func TestTraceExemplar_ValidSampled(t *testing.T) {
	traceID, _ := trace.TraceIDFromHex("0102030405060708090a0b0c0d0e0f10")
	spanID, _ := trace.SpanIDFromHex("0102030405060708")
	sc := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    traceID,
		SpanID:     spanID,
		TraceFlags: trace.FlagsSampled,
	})
	ctx := trace.ContextWithSpanContext(context.Background(), sc)

	labels := traceExemplar(ctx)
	if labels == nil {
		t.Fatal("expected exemplar labels for sampled trace")
	}
	if labels["trace_id"] != "0102030405060708090a0b0c0d0e0f10" {
		t.Fatalf("trace_id = %q", labels["trace_id"])
	}
}

func TestTraceExemplar_NotSampled(t *testing.T) {
	traceID, _ := trace.TraceIDFromHex("0102030405060708090a0b0c0d0e0f10")
	spanID, _ := trace.SpanIDFromHex("0102030405060708")
	sc := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    traceID,
		SpanID:     spanID,
		TraceFlags: 0, // not sampled
	})
	ctx := trace.ContextWithSpanContext(context.Background(), sc)

	labels := traceExemplar(ctx)
	if labels != nil {
		t.Fatal("non-sampled trace should not produce exemplar")
	}
}

func TestTraceExemplar_NoTrace(t *testing.T) {
	labels := traceExemplar(context.Background())
	if labels != nil {
		t.Fatal("no trace context should return nil")
	}
}

func TestTraceExemplar_InvalidSpanContext(t *testing.T) {
	// Zero span context
	sc := trace.SpanContext{}
	ctx := trace.ContextWithSpanContext(context.Background(), sc)

	labels := traceExemplar(ctx)
	if labels != nil {
		t.Fatal("invalid span context should return nil")
	}
}

// Middleware - handler output not corrupted

func TestMiddleware_ResponsePassthrough(t *testing.T) {
	m := New()

	handler := m.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Custom", "test")
		w.WriteHeader(http.StatusTeapot)
		w.Write([]byte("teapot"))
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", http.NoBody))

	if rec.Code != http.StatusTeapot {
		t.Fatalf("status = %d, want 418", rec.Code)
	}
	if rec.Header().Get("X-Custom") != "test" {
		t.Fatal("custom header not passed through")
	}
	if !strings.Contains(rec.Body.String(), "teapot") {
		t.Fatalf("body = %q", rec.Body.String())
	}
}

func TestMiddleware_DistinctStatusCodes(t *testing.T) {
	m := New()

	codes := []int{200, 201, 204, 400, 404, 500}
	for _, code := range codes {
		c := code
		handler := m.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(c)
		}))
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", http.NoBody))
	}

	f := gatherMetric(t, m.reg, "http_requests_total")
	if len(f.GetMetric()) != len(codes) {
		t.Fatalf("expected %d status label combos, got %d", len(codes), len(f.GetMetric()))
	}
}
