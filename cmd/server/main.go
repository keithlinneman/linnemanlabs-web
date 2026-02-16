package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/keithlinneman/linnemanlabs-web/internal/cfg"
	"github.com/keithlinneman/linnemanlabs-web/internal/content"
	"github.com/keithlinneman/linnemanlabs-web/internal/evidence"
	"github.com/keithlinneman/linnemanlabs-web/internal/healthhttp"
	"github.com/keithlinneman/linnemanlabs-web/internal/opshttp"
	"github.com/keithlinneman/linnemanlabs-web/internal/provenancehttp"
	"github.com/keithlinneman/linnemanlabs-web/internal/ratelimit"
	"github.com/keithlinneman/linnemanlabs-web/internal/sitehandler"
	"github.com/keithlinneman/linnemanlabs-web/internal/sitehttp"
	"github.com/keithlinneman/linnemanlabs-web/internal/webassets"

	"github.com/keithlinneman/linnemanlabs-web/internal/httpserver"
	"github.com/keithlinneman/linnemanlabs-web/internal/log"
	"github.com/keithlinneman/linnemanlabs-web/internal/metrics"
	"github.com/keithlinneman/linnemanlabs-web/internal/otelx"
	"github.com/keithlinneman/linnemanlabs-web/internal/probe"
	"github.com/keithlinneman/linnemanlabs-web/internal/prof"
	v "github.com/keithlinneman/linnemanlabs-web/internal/version"
	// "github.com/keithlinneman/linnemanlabs-web/internal/xerrors"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var conf cfg.App
	var showVersion bool

	// Parse config from flags and env
	cfg.Register(flag.CommandLine, &conf)
	flag.BoolVar(&showVersion, "V", false, "Print version+build information and exit")
	flag.Parse()

	if showVersion {
		vi := v.Get()
		fmt.Printf(
			"%s %s (commit=%s, commit_date=%s, build_id=%s, build_date=%s, go=%s, dirty=%v)\n",
			vi.AppName, vi.Version, vi.Commit, vi.CommitDate, vi.BuildId, vi.BuildDate, vi.GoVersion,
			vi.VCSDirty != nil && *vi.VCSDirty,
		)
		os.Exit(0)
	}

	// Fill in config from environment variables with prefix LMLABS_ and validate
	cfg.FillFromEnv(flag.CommandLine, "LMLABS_", func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, format+"\n", args...)
	})

	// validate config
	if err := cfg.Validate(conf); err != nil {
		fmt.Fprintln(os.Stderr, "config error:", err)
		os.Exit(1)
	}

	// Setup logging
	lvl, err := log.ParseLevel(conf.LogLevel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid log level %s: %v\n", conf.LogLevel, err)
		os.Exit(1)
	}
	lg, err := log.New(log.Options{
		App:               v.AppName,
		Version:           v.Version,
		Commit:            v.Commit,
		BuildId:           v.BuildId,
		Level:             lvl,
		JsonFormat:        conf.LogJSON,
		MaxErrorLinks:     conf.MaxErrorLinks,
		IncludeErrorLinks: conf.IncludeErrorLinks,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "logger init error:", err)
		os.Exit(1)
	}
	// defer lg.Sync()
	L := lg.With("component", "server")
	ctx = log.WithContext(ctx, L)

	// Get build/version info
	vi := v.Get()
	L.Info(ctx, "initializing application",
		"version", vi.Version,
		"commit", vi.Commit,
		"commit_date", vi.CommitDate,
		"build_id", vi.BuildId,
		"build_date", vi.BuildDate,
		"go_version", vi.GoVersion,
		"vcs_dirty", vi.VCSDirty,
		"http_port", conf.HTTPPort,
		"admin_port", conf.AdminPort,
		"enable_pprof", conf.EnablePprof,
		"enable_pyroscope", conf.EnablePyroscope,
		"enable_tracing", conf.EnableTracing,
		"enable_content_updates", conf.EnableContentUpdates,
		"otlp_endpoint", conf.OTLPEndpoint,
		"pyro_server", conf.PyroServer,
		"pyro_tenant", conf.PyroTenantID,
		"trace_sample", conf.TraceSample,
		"include_error_links", conf.IncludeErrorLinks,
		"max_error_links", conf.MaxErrorLinks,
		"content_ssm_param", conf.ContentSSMParam,
		"content_s3_bucket", conf.ContentS3Bucket,
		"content_s3_prefix", conf.ContentS3Prefix,
	)

	// Setup pyroscope profiling
	stopProf, err := prof.Start(ctx, prof.Options{
		Enabled:       conf.EnablePyroscope,
		AppName:       v.AppName,
		AuthToken:     "",
		ServerAddress: conf.PyroServer,
		TenantID:      conf.PyroTenantID,
		Tags: map[string]string{
			"app":       v.AppName,
			"component": "server",
			"version":   vi.Version,
			"commit":    vi.Commit,
			"build_id":  vi.BuildId,
			"source":    "go-agent",
		},
	})
	if err != nil {
		L.Error(ctx, err, "pyroscope start failed", "pyro_server", conf.PyroServer)
	}
	defer func() { stopProf() }()

	// Setup otel for tracing
	// Insecure is true because we are only writing to a collector on localhost
	shutdownOTEL, err := otelx.Init(ctx, otelx.Options{
		Enabled:   conf.EnableTracing,
		Endpoint:  conf.OTLPEndpoint,
		Insecure:  true,
		Sample:    conf.TraceSample,
		Service:   v.AppName,
		Component: "server",
		Version:   vi.Version,
	})
	if err != nil {
		L.Error(ctx, err, "otel init failed")
	}
	defer func() { _ = shutdownOTEL(context.Background()) }()

	// Setup metrics / admin listener
	var m *metrics.ServerMetrics = metrics.New()
	m.SetBuildInfoFromVersion(v.AppName, "server", vi)

	// setup toggle for server shutdown
	var gate probe.ShutdownGate
	readiness := probe.Multi(
		gate.Probe(),
		probe.Func(func(ctx context.Context) error {
			// do db checks, etc here
			// nil = ok, err = reason
			return nil
		}),
	)

	// start admin/ops listener to serve metrics, health checks, pprof and any future admin APIs
	// sg restricts inbound to internal monitoring infrastructure
	// we reject connections from public ips and requests with x-forwarded set in middleware
	// to prevent accidental exposure if sg is misconfigured or load balancer ever sends traffic there
	opsHTTPStop, err := opshttp.Start(ctx, L, opshttp.Options{
		Port:         conf.AdminPort,
		Metrics:      m.Handler(),
		EnablePprof:  conf.EnablePprof,
		Health:       probe.Static(true, ""),
		Readiness:    readiness,
		UseRecoverMW: true,
		OnPanic:      m.IncHttpPanic,
	})
	if err != nil {
		L.Error(ctx, err, "failed to start ops http listener")
		os.Exit(1)
	}
	defer func() { _ = opsHTTPStop(context.Background()) }()

	// create application health/readiness checks
	checker := healthhttp.StaticChecker{}
	healthAPI := healthhttp.NewAPI(checker)

	// setup content manager that will manage what content we serve
	/*
		contentMgr := content.NewManager(content.Options{
			Logger:     L,
			FallbackFS: fallbackFS,
			SeedFS:     seedFS,
			HaveSeed:   haveSeed,
		})
	*/

	// initialize http content
	// setup maintenance fallback fs
	fallbackFS := webassets.FallbackFS()

	// setup seed fs to serve initial content to pass to content manger
	seedFS, haveSeed := webassets.SeedSiteFS()

	// setup content manager that will manage what content we serve
	contentMgr := content.NewManager()

	// load initial seed content if available
	if haveSeed {
		contentMgr.Set(content.Snapshot{
			FS: seedFS,
			Meta: content.Meta{
				Source:  content.SourceSeed,
				Version: "initial-seed",
			},
		})
		L.Info(ctx, "loaded initial seed site content into content manager")
	} else {
		L.Info(ctx, "no seed site content available to load into content manager")
	}

	// setup content bundle loader
	loader, err := content.NewLoader(ctx, content.LoaderOptions{
		Logger:   L,
		SSMParam: conf.ContentSSMParam,
		S3Bucket: conf.ContentS3Bucket,
		S3Prefix: conf.ContentS3Prefix,
	})
	if err != nil {
		L.Error(ctx, err, "failed to create content loader")
	} else {
		if err := loader.LoadIntoManager(ctx, contentMgr); err != nil {
			L.Error(ctx, err, "failed to load content bundle, falling back to seed")
		} else {
			L.Info(ctx, "loaded content bundle from S3",
				"content_version", contentMgr.ContentVersion(),
				"content_hash", contentMgr.ContentHash(),
			)
		}
	}

	// setup evidence loading (fetch build attestations from S3 at startup)
	var evidenceStore *evidence.Store
	if vi.HasProvenance() {
		evidenceStore = evidence.NewStore()
		evidenceLoader, err := evidence.NewLoader(ctx, evidence.LoaderOptions{
			Logger:    L,
			Bucket:    vi.EvidenceBucket,
			Prefix:    vi.EvidencePrefix,
			ReleaseID: vi.ReleaseId,
		})
		if err != nil {
			L.Warn(ctx, "failed to create evidence loader", "error", err)
		} else {
			bundle, err := evidenceLoader.Load(ctx)
			if err != nil {
				L.Warn(ctx, "failed to load evidence, continuing without", "error", err)
			} else {
				bundle = evidence.FilterBundleByPlatform(bundle, evidence.RuntimePlatform())
				evidenceStore.Set(bundle)
				L.Info(ctx, "loaded build evidence",
					"platform", evidence.RuntimePlatform(),
					"summary", bundle.LoadSummary(),
					"categories", bundle.Summary(),
					"inventory_hash", bundle.InventoryHash[:12],
				)
			}
		}
	} else {
		L.Info(ctx, "no build provenance (local build), skipping evidence fetch")
	}
	// setup provenance API
	provenanceAPI := provenancehttp.NewAPI(contentMgr, evidenceStore, L)

	// setup site handler that serves site content
	siteHandler, err := sitehandler.New(sitehandler.Options{
		Logger:     L,
		Content:    contentMgr,
		FallbackFS: fallbackFS,
	})
	if err != nil {
		L.Error(ctx, err, "failed to create site handler")
		os.Exit(1)
	}

	// register site handler routes
	siteRoutes := sitehttp.New(siteHandler)

	// Setup rate limiter middleware for site handler
	limiter := ratelimit.New(ctx,
		// increment prometheus counter on each denied request
		ratelimit.WithOnDenied(func(ip string) {
			m.IncRateLimitDenied()
		}),
		// only log the first time an ip is denied each time it is cleaned from the bucket
		ratelimit.WithOnFirstDenied(func(ip string) {
			L.Warn(ctx, "rate limit triggered", "ip", ip)
		}),
	)

	// start site http server
	siteHTTPStop, err := httpserver.Start(
		ctx,
		httpserver.Options{
			Port:         conf.HTTPPort,
			Health:       probe.Static(true, ""),
			Readiness:    readiness,
			UseRecoverMW: true,
			OnPanic:      m.IncHttpPanic,
			MetricsMW:    m.Middleware,
			RateLimitMW:  limiter.Middleware,
			Logger:       L,
			ContentInfo:  contentMgr, // Pass content manager for headers
		},
		healthAPI,
		provenanceAPI, // Register provenance API routes
		siteRoutes,
	)

	if err != nil {
		L.Error(ctx, err, "failed to start site http listener port")
		os.Exit(1)
	}
	defer func() { _ = siteHTTPStop(context.Background()) }()

	// notify systemd that we started successfully if started under systemd
	if err := notifySystemd(); err != nil {
		// log and dont exit, worst case systemd will kill the process after timeout
		L.Warn(ctx, "failed to notify systemd of readiness", "error", err)
	}

	// block until signal so we dont exit
	sigCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// wait for ctrl+c / sigterm
	<-sigCtx.Done()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	L.Info(context.Background(), "shutdown signal received")

	// fail health checks to drain connections
	gate.Set("draining")
	// sleep for 60s to allow in-flight requests to finish and for load balancer to detect unhealthy and stop sending new requests
	L.Info(context.Background(), "shutdown gate closed")

	// will make sleep time tunable in the future
	L.Info(context.Background(), "sleeping 60s for in-flight and load balancer health checks to drain")
	forceCh := make(chan os.Signal, 1)
	signal.Notify(forceCh, os.Interrupt, syscall.SIGTERM)
	select {
	case <-time.After(60 * time.Second):
		L.Info(context.Background(), "drain period complete")
	case <-forceCh:
		L.Warn(context.Background(), "second signal received, skipping drain")
	}
	signal.Stop(forceCh)

	if err := siteHTTPStop(shutdownCtx); err != nil {
		L.Error(context.Background(), err, "app http server shutdown")
	}

	if err := opsHTTPStop(shutdownCtx); err != nil {
		L.Error(context.Background(), err, "ops http server shutdown")
	}

	if err := shutdownOTEL(shutdownCtx); err != nil {
		L.Error(context.Background(), err, "otel shutdown")
	}

	stopProf()

	L.Info(context.Background(), "shutdown complete")
	os.Exit(0)
}

func notifySystemd() error {
	// systemd will set NOTIFY_SOCKET to a unix socket path if we were started under systemd with type=notify
	addr := os.Getenv("NOTIFY_SOCKET")
	if addr == "" {
		return fmt.Errorf("NOTIFY_SOCKET not set, skipping systemd notify")
	}
	conn, err := net.Dial("unixgram", addr)
	if err != nil {
		return fmt.Errorf("systemd notify failed: dial failed: %w", err)
	}
	conn.Write([]byte("READY=1"))
	if err := conn.Close(); err != nil {
		return fmt.Errorf("systemd notify failed: close failed: %w", err)
	}
	return nil
}
