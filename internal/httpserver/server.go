package httpserver

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"path"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	//"github.com/keithlinneman/linnemanlabs-web/internal/log"
	"github.com/keithlinneman/linnemanlabs-web/internal/httpmw"
	//"github.com/keithlinneman/linnemanlabs-web/internal/metrics"
	"github.com/keithlinneman/linnemanlabs-web/internal/xerrors"
)

type RouteRegistrar interface {
	RegisterRoutes(r chi.Router)
}

// NewHandler builds an HTTP handler with routes + middleware
// main() owns *http.Server so it can do graceful shutdown
func NewHandler(opts Options, regs ...RouteRegistrar) http.Handler {
	// chi router
	r := chi.NewRouter()

	// Normalize /categories/ to /categories, etc
	// r.Use(middleware.StripSlashes)

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

	// Register routes from other packages
	for _, reg := range regs {
		if reg == nil {
			continue
		}
		// Handle interface wrapping a typed nil, e.g. (*httpapi.API)(nil)
		v := reflect.ValueOf(reg)
		if v.Kind() == reflect.Ptr && v.IsNil() {
			continue
		}
		reg.RegisterRoutes(r)
	}

	// Middleware (outermost first in wrapping order)
	var h http.Handler = r

	// Request-scoped logging (inner so it sees trace_id, principal, tenant, etc)
	h = httpmw.WithLogger(opts.Logger)(h)

	// Metrics middleware for prometheus instrumentation
	if opts.MetricsMW != nil {
		h = opts.MetricsMW(h)
	}

	// add trace-id headers to any requests with a recording trace
	h = httpmw.TraceResponseHeaders("X-Trace-Id", "X-Span-Id")(h)

	// Decide which requests get traced
	shouldTrace := func(p string) bool {
		// dont trace favicon/robots.txt
		if p == "/favicon.ico" || p == "/robots.txt" {
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

	/* moved into otelhttp.WithFilter to follow otel recommended practice
	// Otel middleware to add spans to requests
	otelWrapped := otelhttp.NewHandler(
		h,
		"http.server",
		otelhttp.WithSpanNameFormatter(func(_ string, r *http.Request) string {
			// AnnotateHTTPRoute will rename the span later to the final route pattern.
			return r.Method + " " + r.URL.Path
		}),
		// WithPublicEndpointFn is the replacement for WithPublicEndpoint()
		otelhttp.WithPublicEndpointFn(func(r *http.Request) bool { return true }),
	)

	// traced requests go through otelWrapped, others skip it
	base := h
	h = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if shouldTrace(r.URL.Path) {
			otelWrapped.ServeHTTP(w, r)
			return
		}
		base.ServeHTTP(w, r)
	})
	*/

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

	// Request ID (outer so everything downstream sees it)
	h = httpmw.RequestID("X-Request-Id")(h)

	// Recovery middleware to log panics and serve 500 response
	if opts.UseRecoverMW {
		h = httpmw.Recover(opts.Logger)(h)
	}

	// Security headers outermost to ensure they are served on every response
	h = httpmw.SecurityHeaders(h)

	return h
}

func NewServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
}

// Start public HTTP server
// Returns stop(ctx) for graceful shutdown
func Start(ctx context.Context, opts Options, regs ...RouteRegistrar) (func(context.Context) error, error) {
	port := opts.Port
	if port == 0 {
		port = 8080
	}
	addr := fmt.Sprintf(":%d", port)

	handler := NewHandler(opts, regs...)
	srv := NewServer(addr, handler)

	ln, err := net.Listen("tcp", addr)
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
