package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/keithlinneman/linnemanlabs-web/internal/cfg"
	"github.com/keithlinneman/linnemanlabs-web/internal/content"
	"github.com/keithlinneman/linnemanlabs-web/internal/evidence"
	"github.com/keithlinneman/linnemanlabs-web/internal/healthhttp"
	"github.com/keithlinneman/linnemanlabs-web/internal/opshttp"
	"github.com/keithlinneman/linnemanlabs-web/internal/provenancehttp"
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

	// Handle cmd line flags
	var (
		flagLogJSON bool
		setLogJSON  bool

		flagLogLevel string
		setLogLevel  bool

		flagHTTPPort int
		setHTTPPort  bool

		flagAdminPort int
		setAdminPort  bool

		flagEnablePprof bool
		setEnablePprof  bool

		flagEnablePyroscope bool
		setEnablePyroscope  bool

		flagEnableTracing bool
		setEnableTracing  bool

		flagEnableContentUpdates bool
		setEnableContentUpdates  bool

		flagTraceSample float64
		setTraceSample  bool

		flagPyroServer string
		setPyroServer  bool

		flagPyroTenantID string
		setPyroTenantID  bool

		flagOTLPEndpoint string
		setOTLPEndpoint  bool

		flagStacktraceLevel string
		setStacktraceLevel  bool

		flagIncludeErrorLinks bool
		setIncludeErrorLinks  bool

		flagMaxErrorLinks int
		setMaxErrorLinks  bool

		flagContentSSMParam string
		setContentSSMParam  bool

		flagContentS3Bucket string
		setContentS3Bucket  bool

		flagContentS3Prefix string
		setContentS3Prefix  bool

		flagShowVersion bool
	)
	flag.Func("log-level", "debug|info|warn|error", func(s string) error {
		flagLogLevel, setLogLevel = s, true
		return nil
	})
	flag.Func("admin-port", "listen TCP port (1..65535)", func(s string) error {
		n, err := strconv.Atoi(s)
		if err != nil {
			return err
		}
		flagAdminPort, setAdminPort = n, true
		return nil
	})
	flag.Func("http-port", "listen TCP port (1..65535)", func(s string) error {
		n, err := strconv.Atoi(s)
		if err != nil {
			return err
		}
		flagHTTPPort, setHTTPPort = n, true
		return nil
	})
	flag.Func("trace-sample", "trace sampling ratio (0..1)", func(s string) error {
		n, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return err
		}
		flagTraceSample, setTraceSample = n, true
		return nil
	})
	flag.Func("stacktrace-level", "debug|info|warn|error", func(s string) error {
		flagStacktraceLevel, setStacktraceLevel = s, true
		return nil
	})
	flag.Func("pyro-server", "pyroscope server url to push to", func(s string) error {
		flagPyroServer, setPyroServer = s, true
		return nil
	})
	flag.Func("pyro-tenant", "tenant (x-scope-orgid) to use for pyro-server", func(s string) error {
		flagPyroTenantID, setPyroTenantID = s, true
		return nil
	})
	flag.Func("otlp-endpoint", "OTLP endpoint to push to (gRPC) (host:port)", func(s string) error {
		flagOTLPEndpoint, setOTLPEndpoint = s, true
		return nil
	})
	flag.Func("max-error-links", "max error chain depth (1..64)", func(s string) error {
		n, err := strconv.Atoi(s)
		if err != nil {
			return err
		}
		flagMaxErrorLinks, setMaxErrorLinks = n, true
		return nil
	})
	flag.Func("content-ssm-param", "ssm parameter name to get content bundle hash from", func(s string) error {
		flagContentSSMParam, setContentSSMParam = s, true
		return nil
	})
	flag.Func("content-s3-bucket", "s3 bucket name to get content bundle from", func(s string) error {
		flagContentS3Bucket, setContentS3Bucket = s, true
		return nil
	})
	flag.Func("content-s3-prefix", "s3 prefix (key) to get content bundle from", func(s string) error {
		flagContentS3Prefix, setContentS3Prefix = s, true
		return nil
	})
	flag.BoolVar(&flagIncludeErrorLinks, "include-error-links", true, "Include error links in log messages")
	flag.BoolVar(&flagLogJSON, "log-json", true, "JSON logs (true) or logfmt (false)")
	flag.BoolVar(&flagEnablePprof, "enable-pprof", true, "Enable Pprof profiling (on admin port only)")
	flag.BoolVar(&flagEnableTracing, "enable-tracing", false, "Enable OTLP tracing and push to otlp-endpoint")
	flag.BoolVar(&flagEnablePyroscope, "enable-pyroscope", false, "Enable pushing Pyroscope data to server set in -pyro-server")
	flag.BoolVar(&flagEnableContentUpdates, "enable-content-updates", true, "Enable refreshing content bundles from S3/SSM")
	flag.BoolVar(&flagShowVersion, "V", false, "Print version+build information and exit")
	flag.Parse()
	if flagShowVersion {
		vi := v.Get()
		fmt.Printf(
			"linnemanlabs web %s (commit=%s, commit_date=%s, build_id=%s, build_date=%s, go=%s, dirty=%v)\n",
			vi.Version, vi.Commit, vi.CommitDate, vi.BuildId, vi.BuildDate, vi.GoVersion,
			vi.VCSDirty != nil && *vi.VCSDirty,
		)
		os.Exit(0)
	}
	flag.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "include-error-links":
			setIncludeErrorLinks = true
		case "log-json":
			setLogJSON = true
		case "enable-pprof":
			setEnablePprof = true
		case "enable-pyroscope":
			setEnablePyroscope = true
		case "enable-tracing":
			setEnableTracing = true
		case "enable-content-updates":
			setEnableContentUpdates = true
		}
	})

	// Setup configuration
	conf := cfg.Defaults()
	conf = cfg.FromEnv(conf, "LMLABS_")
	conf = cfg.Apply(conf, cfg.Overrides{
		LogJSON:              ptrIf(setLogJSON, flagLogJSON),
		LogLevel:             ptrIf(setLogLevel, flagLogLevel),
		HTTPPort:             ptrIf(setHTTPPort, flagHTTPPort),
		AdminPort:            ptrIf(setAdminPort, flagAdminPort),
		EnablePprof:          ptrIf(setEnablePprof, flagEnablePprof),
		EnablePyroscope:      ptrIf(setEnablePyroscope, flagEnablePyroscope),
		EnableTracing:        ptrIf(setEnableTracing, flagEnableTracing),
		EnableContentUpdates: ptrIf(setEnableContentUpdates, flagEnableContentUpdates),
		PyroServer:           ptrIf(setPyroServer, flagPyroServer),
		PyroTenantID:         ptrIf(setPyroTenantID, flagPyroTenantID),
		OTLPEndpoint:         ptrIf(setOTLPEndpoint, flagOTLPEndpoint),
		TraceSample:          ptrIf(setTraceSample, flagTraceSample),
		StacktraceLevel:      ptrIf(setStacktraceLevel, flagStacktraceLevel),
		IncludeErrorLinks:    ptrIf(setIncludeErrorLinks, flagIncludeErrorLinks),
		MaxErrorLinks:        ptrIf(setMaxErrorLinks, flagMaxErrorLinks),
		ContentSSMParam:      ptrIf(setContentSSMParam, flagContentSSMParam),
		ContentS3Bucket:      ptrIf(setContentS3Bucket, flagContentS3Bucket),
		ContentS3Prefix:      ptrIf(setContentS3Prefix, flagContentS3Prefix),
	})
	if err := cfg.Validate(conf); err != nil {
		fmt.Fprintln(os.Stderr, "config error: ", err)
		os.Exit(1)
	}

	// Setup logging
	lvl, err := log.ParseLevel(conf.LogLevel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid log level %s: %v\n", conf.LogLevel, err)
		os.Exit(1)
	}
	lg, err := log.New(log.Options{
		App:               "linnemanlabs",
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
	L := lg.With("component", "web")
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
		AppName:       "linnemanlabs.web",
		AuthToken:     "",
		ServerAddress: conf.PyroServer,
		TenantID:      conf.PyroTenantID,
		Tags: map[string]string{
			"app":       "linnemanlabs",
			"component": "web",
			"env":       "prod",
			"region":    "us-east-2",
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
	shutdownOTEL, err := otelx.Init(ctx, otelx.Options{
		Enabled:   conf.EnableTracing,
		Endpoint:  conf.OTLPEndpoint,
		Insecure:  true,
		Sample:    conf.TraceSample,
		Service:   "linnemanlabs",
		Component: "web",
		Version:   vi.Version,
	})
	if err != nil {
		L.Error(ctx, err, "otel init failed")
	}
	defer func() { _ = shutdownOTEL(context.Background()) }()

	// Setup metrics / admin listener
	var m *metrics.ServerMetrics = metrics.New()
	m.SetBuildInfoFromVersion("linnemanlabs", "web", vi)

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

	// start ops http server
	opsHTTPStop, err := opshttp.Start(ctx, L, opshttp.Options{
		Port:         conf.AdminPort,
		Metrics:      m.Handler(),
		EnablePprof:  conf.EnablePprof,
		Health:       probe.Static(true, ""),
		Readiness:    readiness,
		UseRecoverMW: true,
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
				evidenceStore.Set(bundle)
				L.Info(ctx, "loaded build evidence",
					"release_id", vi.ReleaseId,
					"artifact_count", len(bundle.Artifacts),
					"artifact_names", bundle.Names(),
				)
			}
		}
	} else {
		L.Info(ctx, "no build provenance (local build), skipping evidence fetch")
	}

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

	// setup provenance API
	provenanceAPI := provenancehttp.NewAPI(contentMgr, evidenceStore, L)

	// start site http server
	siteHTTPStop, err := httpserver.Start(
		ctx,
		httpserver.Options{
			Port:         conf.HTTPPort,
			Health:       probe.Static(true, ""),
			Readiness:    readiness,
			UseRecoverMW: true,
			MetricsMW:    m.Middleware,
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

	// notify systemd that we started successfully
	addr := os.Getenv("NOTIFY_SOCKET")
	if addr == "" {
		L.Info(ctx, "NOTIFY_SOCKET not set, skipping systemd notify")
		return
	}
	conn, err := net.Dial("unixgram", addr)
	if err != nil {
		L.Warn(ctx, "systemd notify failed: dial failed: %w", "notify_socket", addr, err)
		return
	}
	conn.Write([]byte("READY=1"))
	conn.Close()
	L.Info(ctx, "sent systemd READY notification")

	// block until signal so we dont exit
	sigCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// wait for ctrl+c / sigterm
	<-sigCtx.Done()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	L.Info(context.Background(), "shutdown signal received")

	// fail health checks to drain connections
	// we may want to have a force/clean mechanism to allow this to be set for 30s before actually shutting downy to allow load balancers to notice and drain connections
	gate.Set("draining")

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

func ptrIf[T any](changed bool, v T) *T {
	if changed {
		return &v
	}
	return nil
}
