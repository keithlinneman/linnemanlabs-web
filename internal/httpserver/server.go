package httpserver

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/keithlinneman/linnemanlabs-web/internal/health"
	"github.com/keithlinneman/linnemanlabs-web/internal/httpmw"
	"github.com/keithlinneman/linnemanlabs-web/internal/xerrors"
)

// NewHandler builds an HTTP handler with routes + middleware
// main() owns *http.Server so it can do graceful shutdown
func NewHandler(opts *Options) http.Handler {
	// chi router
	r := chi.NewRouter()

	// Compress text responses (HTML/CSS/JS/JSON/SVG)
	r.Use(middleware.Compress(5,
		"text/html",
		"text/css",
		"application/javascript",
		"text/javascript",
		"application/json",
		"image/svg+xml",
		"image/x-icon",
	))

	// Annotate logger and tracer with http.route from chi route pattern if trace is recording
	r.Use(httpmw.AnnotateHTTPRoute)

	// Access log middleware
	r.Use(httpmw.AccessLog())

	r.Use(httpmw.MaxBody(1024)) // 1KB - nobody should be sending bodies to our static site to begin with

	// Register health routes at /-/healthy and /-/ready if probes provided
	if opts.Health != nil {
		r.Get("/-/healthy", health.HealthzHandler(opts.Health))
	}
	if opts.Readiness != nil {
		r.Get("/-/ready", health.ReadyzHandler(opts.Readiness))
	}

	if opts.APIRoutes != nil {
		opts.APIRoutes(r)
	}

	// Catch-all 404 handler if provided, otherwise chi default
	if opts.SiteHandler != nil {
		r.NotFound(opts.SiteHandler.ServeHTTP)
		r.MethodNotAllowed(opts.SiteHandler.ServeHTTP)
	}

	// Middleware (outermost first in wrapping order)
	var h http.Handler = r

	// Request-scoped logging (inner so it sees trace_id, etc)
	h = httpmw.WithLogger(opts.Logger)(h)

	// Metrics middleware for prometheus instrumentation
	if opts.MetricsMW != nil {
		h = opts.MetricsMW(h)
	}

	// add trace-id headers to any requests with a recording trace
	h = httpmw.TraceResponseHeaders("X-Trace-Id", "X-Span-Id")(h)

	// Add content version/hash headers
	if opts.ContentInfo != nil {
		h = httpmw.ContentHeaders(opts.ContentInfo)(h)
	}

	// Decide which requests get traced
	shouldTrace := func(p string) bool {
		// dont trace favicon/robots.txt
		if p == "/favicon.ico" || p == "/favicon.svg" || p == "/robots.txt" {
			return false
		}
		// dont trace health checks (may re-visit in the future to sample at a really low rate)
		if p == "/-/healthy" || p == "/-/ready" {
			return false
		}

		// dont trace static asset extensions
		ext := strings.ToLower(path.Ext(p))
		switch ext {
		case ".css", ".js", ".png", ".jpg", ".jpeg", ".webp", ".svg", ".ico", ".woff", ".woff2", ".map":
			return false
		}

		return true
	}

	h = otelhttp.NewHandler(
		h,
		"http.server",
		otelhttp.WithFilter(func(r *http.Request) bool {
			return shouldTrace(r.URL.Path)
		}),
		otelhttp.WithSpanNameFormatter(func(_ string, r *http.Request) string {
			// AnnotateHTTPRoute will rename the span later to the final route pattern
			return r.Method + " " + r.URL.Path
		}),
		// WithPublicEndpointFn is the replacement for WithPublicEndpoint()
		otelhttp.WithPublicEndpointFn(func(r *http.Request) bool { return true }),
	)

	// Rate limiting (after client IP mw so it uses resolved IP)
	if opts.RateLimitMW != nil {
		h = opts.RateLimitMW(h)
	}

	// Client IP resolution (must be before rate limiter and logging in middleware chain)
	h = httpmw.ClientIPWithOptions(opts.ClientIPOpts)(h)

	// Request ID (outer so everything downstream sees it)
	h = httpmw.RequestID("X-Request-Id")(h)

	// Recovery middleware to log panics and serve 500 response
	if opts.UseRecoverMW {
		h = httpmw.Recover(opts.Logger, opts.OnPanic)(h)
	}

	// Security headers outermost to ensure they are served on every response
	h = httpmw.SecurityHeaders(h)

	return h
}

// Server timeout defaults, shared with opshttp.
const (
	DefaultReadHeaderTimeout = 5 * time.Second
	DefaultReadTimeout       = 10 * time.Second
	DefaultWriteTimeout      = 10 * time.Second
	DefaultIdleTimeout       = 60 * time.Second
	DefaultMaxHeaderBytes    = 1 << 20 // 1 MB
)

func NewServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: DefaultReadHeaderTimeout,
		ReadTimeout:       DefaultReadTimeout,
		WriteTimeout:      DefaultWriteTimeout,
		IdleTimeout:       DefaultIdleTimeout,
		MaxHeaderBytes:    DefaultMaxHeaderBytes,
	}
}

// Start public HTTP server
// Returns stop(ctx) for graceful shutdown
func Start(ctx context.Context, opts *Options) (func(context.Context) error, error) {
	port := opts.Port
	if port == 0 {
		port = 8080
	}
	addr := fmt.Sprintf(":%d", port)

	handler := NewHandler(opts)
	srv := NewServer(addr, handler)

	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp4", addr)

	if err != nil {
		return nil, xerrors.EnsureTrace(err)
	}

	go func() {
		opts.Logger.Info(ctx, "http server listening", "addr", addr)
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			opts.Logger.Error(ctx, err, "http server error")
		}
	}()

	var once sync.Once
	stop := func(sctx context.Context) (retErr error) {
		once.Do(func() {
			opts.Logger.Info(sctx, "http server shutting down")
			c, cancel := context.WithTimeout(sctx, 5*time.Second)
			defer cancel()
			retErr = srv.Shutdown(c)
		})
		return retErr
	}
	return stop, nil
}
