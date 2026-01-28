package opshttp

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/keithlinneman/linnemanlabs-web/internal/log"
	"github.com/keithlinneman/linnemanlabs-web/internal/xerrors"
)

// Start admin HTTP server with /metrics, /healthz, /readyz, pprof debug endpoints
// Returns stop(ctx) for graceful shutdown
func Start(ctx context.Context, L log.Logger, opts Options) (func(context.Context) error, error) {
	port := opts.Port
	if port == 0 {
		port = 9000
	}
	addr := fmt.Sprintf(":%d", port)

	mux := http.NewServeMux()

	// Health endpoints
	mux.Handle("/-/healthy", HealthzHandler(opts.Health))
	mux.Handle("/-/ready", ReadyzHandler(opts.Readiness))

	// Metrics
	if opts.Metrics != nil {
		mux.Handle("/metrics", opts.Metrics)
	}

	// pprof (or shadow with 404s)
	if opts.EnablePprof {
		RegisterPprof(mux)
	} else {
		mux.HandleFunc("/debug/pprof/", func(w http.ResponseWriter, r *http.Request) {
			http.NotFound(w, r)
		})
	}

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, xerrors.Wrapf(err, "could not listen for admin port on addr=%v", addr)
	}

	go func() {
		L.Info(ctx, "ops http server listening", "addr", addr)
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			L.Error(ctx, err, "ops http server error")
		}
	}()

	var once sync.Once
	stop := func(sctx context.Context) (retErr error) {
		once.Do(func() {
			L.Info(sctx, "ops http server shutting down")
			c, cancel := context.WithTimeout(sctx, 5*time.Second)
			defer cancel()
			retErr = srv.Shutdown(c)
		})
		return retErr
	}
	return stop, nil
}
