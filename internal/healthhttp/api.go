package healthhttp

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"
)

// Checker defines the health interface
type Checker interface {
	Healthy(ctx context.Context) bool
	Ready(ctx context.Context) bool
}

// API implements httpserver.RouteRegistrar for health endpoints
type API struct {
	Checker Checker
}

// NewAPI constructs a health API
func NewAPI(checker Checker) *API {
	return &API{
		Checker: checker,
	}
}

// RegisterRoutes attaches /-/ping, /-/healthy, /-/ready to the main chi router
func (api *API) RegisterRoutes(r chi.Router) {
	// simple liveness check
	r.Method(http.MethodGet, "/-/ping",
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("pong\n"))
		}),
	)

	// is app healthy?
	r.Method(http.MethodGet, "/-/healthy",
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			if api.Checker != nil && !api.Checker.Healthy(ctx) {
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte("unhealthy\n"))
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok\n"))
		}),
	)

	// can we serve traffic?
	r.Method(http.MethodGet, "/-/ready",
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			if api.Checker != nil && !api.Checker.Ready(ctx) {
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte("not ready\n"))
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ready\n"))
		}),
	)
}
