package health

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// HealthzHandler

func TestHealthzHandler_Healthy(t *testing.T) {
	h := HealthzHandler(Fixed(true, ""))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/healthz", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "ok") {
		t.Fatalf("body = %q, want 'ok'", rec.Body.String())
	}
}

func TestHealthzHandler_Unhealthy(t *testing.T) {
	h := HealthzHandler(Fixed(false, "database down"))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/healthz", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "database down") {
		t.Fatalf("body = %q, want reason in response", rec.Body.String())
	}
}

func TestHealthzHandler_NilProbe(t *testing.T) {
	h := HealthzHandler(nil)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/healthz", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (nil probe = healthy)", rec.Code)
	}
}

func TestHealthzHandler_DynamicProbe(t *testing.T) {
	healthy := true
	probe := CheckFunc(func(ctx context.Context) error {
		if !healthy {
			return fmt.Errorf("flipped unhealthy")
		}
		return nil
	})

	h := HealthzHandler(probe)

	// Initially healthy
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("initially: status = %d, want 200", rec.Code)
	}

	// Flip to unhealthy
	healthy = false
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/healthz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("after flip: status = %d, want 503", rec.Code)
	}
}

func TestHealthzHandler_PassesRequestContext(t *testing.T) {
	type ctxKey string
	var gotCtx context.Context

	probe := CheckFunc(func(ctx context.Context) error {
		gotCtx = ctx
		return nil
	})

	h := HealthzHandler(probe)
	ctx := context.WithValue(context.Background(), ctxKey("test"), "value")
	req := httptest.NewRequest("GET", "/healthz", nil).WithContext(ctx)
	h.ServeHTTP(httptest.NewRecorder(), req)

	if gotCtx.Value(ctxKey("test")) != "value" {
		t.Fatal("request context not passed to probe")
	}
}

// ReadyzHandler

func TestReadyzHandler_Ready(t *testing.T) {
	h := ReadyzHandler(Fixed(true, ""))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/readyz", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "ready") {
		t.Fatalf("body = %q, want 'ready'", rec.Body.String())
	}
}

func TestReadyzHandler_NotReady(t *testing.T) {
	h := ReadyzHandler(Fixed(false, "content: no active snapshot"))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/readyz", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "content: no active snapshot") {
		t.Fatalf("body = %q, want reason in response", rec.Body.String())
	}
}

func TestReadyzHandler_NilProbe(t *testing.T) {
	h := ReadyzHandler(nil)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/readyz", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (nil probe = ready)", rec.Code)
	}
}

// Handler is http.HandlerFunc

func TestHealthzHandler_IsHandlerFunc(t *testing.T) {
	var _ = HealthzHandler(nil)
}

func TestReadyzHandler_IsHandlerFunc(t *testing.T) {
	var _ = ReadyzHandler(nil)
}
