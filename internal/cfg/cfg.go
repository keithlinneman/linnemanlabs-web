package cfg

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"

	"github.com/keithlinneman/linnemanlabs-web/internal/log"
)

type App struct {
	LogJSON               bool
	LogLevel              string
	HTTPPort              int
	AdminPort             int
	EnablePprof           bool
	EnablePyroscope       bool
	EnableTracing         bool
	EnableContentUpdates  bool
	PyroServer            string
	PyroTenantID          string
	OTLPEndpoint          string
	TraceSample           float64
	StacktraceLevel       string
	IncludeErrorLinks     bool
	MaxErrorLinks         int
	ContentSSMParam       string
	ContentS3Bucket       string
	ContentS3Prefix       string
	EvidenceSigningKeyARN string
	ContentSigningKeyARN  string
}

// Register binds all config fields to the given FlagSet with defaults inline
func Register(fs *flag.FlagSet, c *App) {
	fs.BoolVar(&c.LogJSON, "log-json", true, "JSON logs (true) or logfmt (false)")
	fs.StringVar(&c.LogLevel, "log-level", "info", "debug|info|warn|error")
	fs.IntVar(&c.HTTPPort, "http-port", 8080, "listen TCP port (1..65535)")
	fs.IntVar(&c.AdminPort, "admin-port", 9000, "admin listen TCP port (1..65535)")
	fs.BoolVar(&c.EnablePprof, "enable-pprof", true, "Enable pprof profiling (on admin port only)")
	fs.BoolVar(&c.EnableTracing, "enable-tracing", false, "Enable OTLP tracing and push to otlp-endpoint")
	fs.BoolVar(&c.EnablePyroscope, "enable-pyroscope", false, "Enable pushing Pyroscope data to server set in -pyro-server")
	fs.BoolVar(&c.EnableContentUpdates, "enable-content-updates", true, "Enable refreshing content bundles from S3/SSM")
	fs.BoolVar(&c.IncludeErrorLinks, "include-error-links", true, "Include error links in log messages")
	fs.IntVar(&c.MaxErrorLinks, "max-error-links", 5, "max error chain depth (1..64)")
	fs.Float64Var(&c.TraceSample, "trace-sample", 0.0, "trace sampling ratio (0..1)")
	fs.StringVar(&c.StacktraceLevel, "stacktrace-level", "error", "debug|info|warn|error")
	fs.StringVar(&c.PyroServer, "pyro-server", "", "pyroscope server url to push to")
	fs.StringVar(&c.PyroTenantID, "pyro-tenant", "", "tenant (x-scope-orgid) to use for pyro-server")
	fs.StringVar(&c.OTLPEndpoint, "otlp-endpoint", "", "OTLP endpoint to push to (gRPC) (host:port)")
	fs.StringVar(&c.ContentSSMParam, "content-ssm-param", "/app/linnemanlabs-web/server/content/stable/release/id", "ssm parameter name to get content bundle hash from")
	fs.StringVar(&c.ContentS3Bucket, "content-s3-bucket", "phxi-build-prod-use2-deployment-artifacts", "s3 bucket name to get content bundle from")
	fs.StringVar(&c.ContentS3Prefix, "content-s3-prefix", "apps/linnemanlabs-web/server/content/bundles", "s3 prefix (key) to get content bundle from")
	fs.StringVar(&c.ContentSigningKeyARN, "content-signing-key-arn", "", "KMS key ARN for content bundle signature verification")
	fs.StringVar(&c.EvidenceSigningKeyARN, "evidence-signing-key-arn", "", "KMS key ARN for evidence signature verification")
}

// FillFromEnv sets any flag not explicitly passed on the CLI from
// environment variables. Flag "foo-bar" maps to PREFIX_FOO_BAR.
// Precedence: cli flag > env var > default.
func FillFromEnv(fs *flag.FlagSet, prefix string, logf func(string, ...any)) {
	explicit := make(map[string]bool)
	fs.Visit(func(f *flag.Flag) { explicit[f.Name] = true })

	fs.VisitAll(func(f *flag.Flag) {
		key := prefix + strings.ReplaceAll(strings.ToUpper(f.Name), "-", "_")
		envVal, envSet := os.LookupEnv(key)
		if !envSet {
			return
		}
		if explicit[f.Name] {
			if logf != nil {
				logf("flag -%s: cli value %q overrides env %s=%q", f.Name, f.Value.String(), key, envVal)
			}
			return
		}
		prev := f.Value.String()
		if err := fs.Set(f.Name, envVal); err != nil {
			fs.Set(f.Name, prev)
			if logf != nil {
				logf("flag -%s: ignoring invalid env %s=%q: %v", f.Name, key, envVal, err)
			}
		}
	})
}

// Validate checks that config values are within expected ranges and formats.
// Returns an error describing all invalid fields, or nil if all valid.
func Validate(c App, hasProvenance bool) error {
	var errs []error

	// Ports
	if c.HTTPPort < 1 || c.HTTPPort > 65535 {
		errs = append(errs, fmt.Errorf("invalid HTTP_PORT %d (must be 1..65535)", c.HTTPPort))
	}
	if c.AdminPort < 1 || c.AdminPort > 65535 {
		errs = append(errs, fmt.Errorf("invalid ADMIN_PORT %d (must be 1..65535)", c.AdminPort))
	}
	if c.AdminPort == c.HTTPPort {
		errs = append(errs, fmt.Errorf("ADMIN_PORT and HTTP_PORT must differ (both %d)", c.HTTPPort))
	}

	// Log levels
	if _, err := log.ParseLevel(c.LogLevel); err != nil {
		errs = append(errs, fmt.Errorf("invalid LOG_LEVEL %q: %w", c.LogLevel, err))
	}
	if c.StacktraceLevel != "" {
		if _, err := log.ParseLevel(c.StacktraceLevel); err != nil {
			errs = append(errs, fmt.Errorf("invalid STACKTRACE_LEVEL %q: %w", c.StacktraceLevel, err))
		}
	}

	// Tracing sample
	if c.TraceSample < 0 || c.TraceSample > 1 {
		errs = append(errs, fmt.Errorf("invalid TRACE_SAMPLE %.3f (must be 0..1)", c.TraceSample))
	}

	// Pyroscope (URL and scheme)
	if c.EnablePyroscope {
		if c.PyroServer == "" {
			errs = append(errs, fmt.Errorf("PYRO_SERVER required when ENABLE_PYROSCOPE=true"))
		} else if u, err := url.Parse(c.PyroServer); err != nil || u.Scheme == "" || u.Host == "" {
			errs = append(errs, fmt.Errorf("PYRO_SERVER must be a URL (got %q)", c.PyroServer))
		}
	}

	// Pyroscope tenant
	if c.EnablePyroscope {
		if c.PyroTenantID == "" {
			errs = append(errs, fmt.Errorf("PYRO_TENANT required when ENABLE_PYROSCOPE=true"))
		}
	}

	// OTLP tracing (grpc exporter wants host:port, no scheme)
	if c.EnableTracing {
		if c.OTLPEndpoint == "" {
			errs = append(errs, fmt.Errorf("OTLP_ENDPOINT required when ENABLE_TRACING=true"))
		} else if _, _, err := net.SplitHostPort(c.OTLPEndpoint); err != nil {
			errs = append(errs, fmt.Errorf("OTLP_ENDPOINT must be host:port (got %q): %v", c.OTLPEndpoint, err))
		}
	}

	// Error link limits
	if c.IncludeErrorLinks {
		if c.MaxErrorLinks < 1 || c.MaxErrorLinks > 64 {
			errs = append(errs, fmt.Errorf("MAX_ERROR_LINKS must be 1..64 (got %d)", c.MaxErrorLinks))
		}
	}

	if c.EnableContentUpdates {
		// Content config
		if c.ContentSSMParam == "" {
			errs = append(errs, fmt.Errorf("CONTENT_SSM_PARAM is required"))
		}
		if c.ContentS3Bucket == "" {
			errs = append(errs, fmt.Errorf("CONTENT_S3_BUCKET is required"))
		}
		if c.ContentS3Prefix == "" {
			errs = append(errs, fmt.Errorf("CONTENT_S3_PREFIX is required"))
		}
		if c.ContentSigningKeyARN == "" {
			errs = append(errs, fmt.Errorf("CONTENT_SIGNING_KEY_ARN is required when ENABLE_CONTENT_UPDATES=true"))
		}
	}

	// Fail-closed: when provenance is compiled in, both signing keys are mandatory.
	// Dev builds without ldflags never reach this path - HasProvenance() is false
	// and the content watcher doesn't start, so there's nothing to verify.
	if hasProvenance {
		if c.EvidenceSigningKeyARN == "" {
			return fmt.Errorf("release build requires evidence-signing-key-arn")
		}
		if c.ContentSigningKeyARN == "" {
			return fmt.Errorf("release build requires content-signing-key-arn")
		}
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}
