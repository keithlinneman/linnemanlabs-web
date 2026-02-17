package httpserver

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/keithlinneman/linnemanlabs-web/internal/health"
	"github.com/keithlinneman/linnemanlabs-web/internal/httpmw"
	"github.com/keithlinneman/linnemanlabs-web/internal/log"
)

type Options struct {
	Logger          log.Logger
	Port            int
	UseRecoverMW    bool
	OnPanic         func() // Optional callback for when panics are recovered, e.g. to trigger alerts or increment prometheus counters, etc.
	FallbackHandler http.Handler
	APIRoutes       func(chi.Router) // Provenance API routes
	SiteHandler     http.Handler     // Main site handler
	MetricsMW       func(http.Handler) http.Handler
	RateLimitMW     func(http.Handler) http.Handler
	Health          health.Probe
	Readiness       health.Probe
	ContentInfo     httpmw.ContentInfo // For X-Content-Bundle-Version and X-Content-Hash headers
}
