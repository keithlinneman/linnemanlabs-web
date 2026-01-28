package cfg

import (
	"os"
	"strings"
	"testing"
)

func bptr(v bool) *bool       { return &v }
func sptr(v string) *string   { return &v }
func iptr(v int) *int         { return &v }
func fptr(v float64) *float64 { return &v }

func wantErrContains(t *testing.T, err error, sub string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error containing %q, got <nil>", sub)
	}
	if !strings.Contains(err.Error(), sub) {
		t.Fatalf("error %q does not contain %q", err.Error(), sub)
	}
}

func TestDefaults(t *testing.T) {
	c := Defaults()
	if !c.LogJSON || c.LogLevel != "info" || c.HTTPPort != 8080 || c.AdminPort != 9000 {
		t.Fatalf("unexpected defaults: %+v", c)
	}
	if !c.EnablePprof || c.EnablePyroscope || c.EnableTracing {
		t.Fatalf("unexpected defaults pprof/pyro/tracing: %+v", c)
	}
	if c.TraceSample != 0.1 || c.StacktraceLevel != "error" || !c.IncludeErrorLinks || c.MaxErrorLinks != 8 {
		t.Fatalf("unexpected defaults trace/stack/errorlinks: %+v", c)
	}
}

func TestFromEnv_WithPrefix(t *testing.T) {
	pfx := "APP_"
	t.Setenv(pfx+"LOG_JSON", "false")
	t.Setenv(pfx+"ENABLE_PPROF", "false")
	t.Setenv(pfx+"ENABLE_PYROSCOPE", "true")
	t.Setenv(pfx+"ENABLE_TRACING", "true")
	t.Setenv(pfx+"PYRO_SERVER", "https://pyro:4040")
	t.Setenv(pfx+"OTLP_ENDPOINT", "otel:4317")
	t.Setenv(pfx+"LOG_LEVEL", "debug")
	t.Setenv(pfx+"ADMIN_PORT", "9100")
	t.Setenv(pfx+"HTTP_PORT", "8088")
	t.Setenv(pfx+"TRACE_SAMPLE", "0.25")
	t.Setenv(pfx+"STACKTRACE_LEVEL", "warn")
	t.Setenv(pfx+"INCLUDE_ERROR_LINKS", "false")
	t.Setenv(pfx+"MAX_ERROR_LINKS", "16")

	c := FromEnv(Defaults(), pfx)

	if c.LogJSON != false ||
		c.EnablePprof != false ||
		c.EnablePyroscope != true ||
		c.EnableTracing != true ||
		c.PyroServer != "https://pyro:4040" ||
		c.OTLPEndpoint != "otel:4317" ||
		c.LogLevel != "debug" ||
		c.AdminPort != 9100 ||
		c.HTTPPort != 8088 ||
		c.TraceSample != 0.25 ||
		c.StacktraceLevel != "warn" ||
		c.IncludeErrorLinks != false ||
		c.MaxErrorLinks != 16 {
		t.Fatalf("FromEnv parse mismatch: %+v", c)
	}
}

func TestApply_AllOverrides(t *testing.T) {
	base := Defaults()
	ov := Overrides{
		LogJSON:           bptr(false),
		LogLevel:          sptr("debug"),
		StacktraceLevel:   sptr("warn"),
		HTTPPort:          iptr(8088),
		AdminPort:         iptr(9300),
		EnablePprof:       bptr(false),
		EnablePyroscope:   bptr(true),
		EnableTracing:     bptr(true),
		PyroServer:        sptr("https://pyro:4040"),
		OTLPEndpoint:      sptr("otel:4317"),
		TraceSample:       fptr(0.33),
		IncludeErrorLinks: bptr(false),
		MaxErrorLinks:     iptr(12),
	}
	out := Apply(base, ov)

	if out.LogJSON != false ||
		out.LogLevel != "debug" ||
		out.StacktraceLevel != "warn" ||
		out.HTTPPort != 8088 ||
		out.AdminPort != 9300 ||
		out.EnablePprof != false ||
		out.EnablePyroscope != true ||
		out.EnableTracing != true ||
		out.PyroServer != "https://pyro:4040" ||
		out.OTLPEndpoint != "otel:4317" ||
		out.TraceSample != 0.33 ||
		out.IncludeErrorLinks != false ||
		out.MaxErrorLinks != 12 {
		t.Fatalf("Apply overrides mismatch: %+v", out)
	}
}

func TestValidate_OK(t *testing.T) {
	c := Defaults()
	c.EnablePyroscope = true
	c.PyroServer = "https://pyro:4040"
	c.EnableTracing = true
	c.OTLPEndpoint = "otel:4317"
	c.TraceSample = 0.2
	if err := Validate(c); err != nil {
		t.Fatalf("Validate() unexpected error: %v", err)
	}
}

func TestValidate_InvalidCombined(t *testing.T) {
	c := Defaults()
	c.HTTPPort = 0
	c.AdminPort = 70000
	c.LogLevel = "nope"
	c.StacktraceLevel = "alsonope"
	c.TraceSample = 2.0
	c.EnablePyroscope = true
	c.PyroServer = "not-a-url"
	c.EnableTracing = true
	c.OTLPEndpoint = "otel"
	c.IncludeErrorLinks = true
	c.MaxErrorLinks = 0

	err := Validate(c)
	if err == nil {
		t.Fatalf("Validate() expected errors, got <nil>")
	}

	wantErrContains(t, err, "invalid HTTP_PORT")
	wantErrContains(t, err, "invalid ADMIN_PORT")
	wantErrContains(t, err, "invalid LOG_LEVEL")
	wantErrContains(t, err, "invalid STACKTRACE_LEVEL")
	wantErrContains(t, err, "invalid TRACE_SAMPLE")
	wantErrContains(t, err, "PYRO_SERVER must be a URL")
	wantErrContains(t, err, "OTLP_ENDPOINT must be host:port")
	wantErrContains(t, err, "MAX_ERROR_LINKS")
}

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
