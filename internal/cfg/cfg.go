package cfg

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"

	"linnemanlabs/internal/log"
)

type App struct {
	LogJSON           bool
	LogLevel          string
	HTTPPort          int
	AdminPort         int
	EnablePprof       bool
	EnablePyroscope   bool
	EnableTracing     bool
	PyroServer        string
	PyroTenantID      string
	OTLPEndpoint      string
	TraceSample       float64
	StacktraceLevel   string
	IncludeErrorLinks bool
	MaxErrorLinks     int
}

func Defaults() App {
	return App{
		LogJSON:           true,
		LogLevel:          "info",
		HTTPPort:          8080,
		AdminPort:         9000,
		EnablePprof:       true,
		EnablePyroscope:   false,
		EnableTracing:     false,
		OTLPEndpoint:      "",
		TraceSample:       0.1,
		PyroServer:        "",
		PyroTenantID:      "",
		StacktraceLevel:   "error",
		IncludeErrorLinks: true,
		MaxErrorLinks:     8,
	}
}

func FromEnv(base App, prefix string) App {
	if v := os.Getenv(prefix + "LOG_JSON"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			base.LogJSON = b
		}
	}
	if v := os.Getenv(prefix + "ENABLE_PPROF"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			base.EnablePprof = b
		}
	}
	if v := os.Getenv(prefix + "ENABLE_PYROSCOPE"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			base.EnablePyroscope = b
		}
	}
	if v := os.Getenv(prefix + "ENABLE_TRACING"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			base.EnableTracing = b
		}
	}
	if v := os.Getenv(prefix + "PYRO_SERVER"); v != "" {
		base.PyroServer = v
	}
	if v := os.Getenv(prefix + "PYRO_TENANT"); v != "" {
		base.PyroTenantID = v
	}
	if v := os.Getenv(prefix + "OTLP_ENDPOINT"); v != "" {
		base.OTLPEndpoint = v
	}
	if v := os.Getenv(prefix + "LOG_LEVEL"); v != "" {
		base.LogLevel = v
	}
	if v := os.Getenv(prefix + "ADMIN_PORT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			base.AdminPort = n
		}
	}
	if v := os.Getenv(prefix + "HTTP_PORT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			base.HTTPPort = n
		}
	}
	if v := os.Getenv(prefix + "TRACE_SAMPLE"); v != "" {
		if n, err := strconv.ParseFloat(v, 64); err == nil {
			base.TraceSample = n
		}
	}
	if v := os.Getenv(prefix + "STACKTRACE_LEVEL"); v != "" {
		base.StacktraceLevel = v
	}
	if v := os.Getenv(prefix + "INCLUDE_ERROR_LINKS"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			base.IncludeErrorLinks = b
		}
	}
	if v := os.Getenv(prefix + "MAX_ERROR_LINKS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			base.MaxErrorLinks = n
		}
	}
	return base
}

type Overrides struct {
	LogJSON           *bool
	LogLevel          *string
	StacktraceLevel   *string
	HTTPPort          *int
	AdminPort         *int
	EnablePprof       *bool
	EnablePyroscope   *bool
	EnableTracing     *bool
	PyroServer        *string
	PyroTenantID      *string
	OTLPEndpoint      *string
	TraceSample       *float64
	IncludeErrorLinks *bool
	MaxErrorLinks     *int
}

func Apply(base App, o Overrides) App {
	if o.LogJSON != nil {
		base.LogJSON = *o.LogJSON
	}
	if o.LogLevel != nil {
		base.LogLevel = *o.LogLevel
	}
	if o.AdminPort != nil {
		base.AdminPort = *o.AdminPort
	}
	if o.EnablePprof != nil {
		base.EnablePprof = *o.EnablePprof
	}
	if o.EnablePyroscope != nil {
		base.EnablePyroscope = *o.EnablePyroscope
	}
	if o.EnableTracing != nil {
		base.EnableTracing = *o.EnableTracing
	}
	if o.OTLPEndpoint != nil {
		base.OTLPEndpoint = *o.OTLPEndpoint
	}
	if o.PyroServer != nil {
		base.PyroServer = *o.PyroServer
	}
	if o.PyroTenantID != nil {
		base.PyroTenantID = *o.PyroTenantID
	}
	if o.HTTPPort != nil {
		base.HTTPPort = *o.HTTPPort
	}
	if o.TraceSample != nil {
		base.TraceSample = *o.TraceSample
	}
	if o.StacktraceLevel != nil {
		base.StacktraceLevel = *o.StacktraceLevel
	}
	if o.IncludeErrorLinks != nil {
		base.IncludeErrorLinks = *o.IncludeErrorLinks
	}
	if o.MaxErrorLinks != nil {
		base.MaxErrorLinks = *o.MaxErrorLinks
	}
	return base
}

func Validate(c App) error {
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

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}
