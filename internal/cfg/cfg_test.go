package cfg

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"testing"
)

func wantErrContains(t *testing.T, err error, sub string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error containing %q, got <nil>", sub)
	}
	if !strings.Contains(err.Error(), sub) {
		t.Fatalf("error %q does not contain %q", err.Error(), sub)
	}
}

// newTestConfig registers flags on a fresh FlagSet, parses the given args,
// and returns the resulting App. This isolates each test from flag.CommandLine.
func newTestConfig(t *testing.T, args []string) App {
	t.Helper()
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	var c App
	Register(fs, &c)
	if err := fs.Parse(args); err != nil {
		t.Fatalf("flag parse: %v", err)
	}
	return c
}

func TestRegister_Defaults(t *testing.T) {
	c := newTestConfig(t, nil)

	if !c.LogJSON {
		t.Error("LogJSON: want true")
	}
	if c.LogLevel != "info" {
		t.Errorf("LogLevel: want %q, got %q", "info", c.LogLevel)
	}
	if c.HTTPPort != 8080 {
		t.Errorf("HTTPPort: want 8080, got %d", c.HTTPPort)
	}
	if c.AdminPort != 9000 {
		t.Errorf("AdminPort: want 9000, got %d", c.AdminPort)
	}
	if !c.EnablePprof {
		t.Error("EnablePprof: want true")
	}
	if c.EnablePyroscope {
		t.Error("EnablePyroscope: want false")
	}
	if c.EnableTracing {
		t.Error("EnableTracing: want false")
	}
	if !c.EnableContentUpdates {
		t.Error("EnableContentUpdates: want true")
	}
	if !c.IncludeErrorLinks {
		t.Error("IncludeErrorLinks: want true")
	}
	if c.StacktraceLevel != "error" {
		t.Errorf("StacktraceLevel: want %q, got %q", "error", c.StacktraceLevel)
	}
	if c.DrainSeconds != 60 {
		t.Errorf("DrainSeconds: want 60, got %d", c.DrainSeconds)
	}
	if c.ShutdownBudgetSeconds != 30 {
		t.Errorf("ShutdownBudgetSeconds: want 30, got %d", c.ShutdownBudgetSeconds)
	}
}

func TestRegister_CLIOverrides(t *testing.T) {
	c := newTestConfig(t, []string{
		"-log-json=false",
		"-log-level=debug",
		"-http-port=9090",
		"-admin-port=9100",
		"-enable-pprof=false",
		"-enable-pyroscope=true",
		"-enable-tracing=true",
		"-trace-sample=0.5",
		"-stacktrace-level=warn",
		"-include-error-links=false",
		"-max-error-links=16",
		"-pyro-server=https://pyro:4040",
		"-pyro-tenant=test-tenant",
		"-otlp-endpoint=otel:4317",
		"-content-ssm-param=/custom/param",
		"-content-s3-bucket=my-bucket",
		"-content-s3-prefix=my/prefix",
		"-drain-seconds=120",
		"-shutdown-budget-seconds=45",
	})

	if c.LogJSON != false {
		t.Error("LogJSON: want false")
	}
	if c.LogLevel != "debug" {
		t.Errorf("LogLevel: want %q, got %q", "debug", c.LogLevel)
	}
	if c.HTTPPort != 9090 {
		t.Errorf("HTTPPort: want 9090, got %d", c.HTTPPort)
	}
	if c.AdminPort != 9100 {
		t.Errorf("AdminPort: want 9100, got %d", c.AdminPort)
	}
	if c.EnablePprof != false {
		t.Error("EnablePprof: want false")
	}
	if c.EnablePyroscope != true {
		t.Error("EnablePyroscope: want true")
	}
	if c.EnableTracing != true {
		t.Error("EnableTracing: want true")
	}
	if c.TraceSample != 0.5 {
		t.Errorf("TraceSample: want 0.5, got %f", c.TraceSample)
	}
	if c.StacktraceLevel != "warn" {
		t.Errorf("StacktraceLevel: want %q, got %q", "warn", c.StacktraceLevel)
	}
	if c.IncludeErrorLinks != false {
		t.Error("IncludeErrorLinks: want false")
	}
	if c.MaxErrorLinks != 16 {
		t.Errorf("MaxErrorLinks: want 16, got %d", c.MaxErrorLinks)
	}
	if c.PyroServer != "https://pyro:4040" {
		t.Errorf("PyroServer: want %q, got %q", "https://pyro:4040", c.PyroServer)
	}
	if c.PyroTenantID != "test-tenant" {
		t.Errorf("PyroTenantID: want %q, got %q", "test-tenant", c.PyroTenantID)
	}
	if c.OTLPEndpoint != "otel:4317" {
		t.Errorf("OTLPEndpoint: want %q, got %q", "otel:4317", c.OTLPEndpoint)
	}
	if c.ContentSSMParam != "/custom/param" {
		t.Errorf("ContentSSMParam: want %q, got %q", "/custom/param", c.ContentSSMParam)
	}
	if c.ContentS3Bucket != "my-bucket" {
		t.Errorf("ContentS3Bucket: want %q, got %q", "my-bucket", c.ContentS3Bucket)
	}
	if c.ContentS3Prefix != "my/prefix" {
		t.Errorf("ContentS3Prefix: want %q, got %q", "my/prefix", c.ContentS3Prefix)
	}
	if c.DrainSeconds != 120 {
		t.Errorf("DrainSeconds: want 120, got %d", c.DrainSeconds)
	}
	if c.ShutdownBudgetSeconds != 45 {
		t.Errorf("ShutdownBudgetSeconds: want 45, got %d", c.ShutdownBudgetSeconds)
	}
}

func TestFillFromEnv(t *testing.T) {
	pfx := "TESTCFG_"
	t.Setenv(pfx+"LOG_JSON", "false")
	t.Setenv(pfx+"LOG_LEVEL", "debug")
	t.Setenv(pfx+"HTTP_PORT", "8088")
	t.Setenv(pfx+"ADMIN_PORT", "9100")
	t.Setenv(pfx+"ENABLE_PPROF", "false")
	t.Setenv(pfx+"ENABLE_PYROSCOPE", "true")
	t.Setenv(pfx+"ENABLE_TRACING", "true")
	t.Setenv(pfx+"TRACE_SAMPLE", "0.25")
	t.Setenv(pfx+"STACKTRACE_LEVEL", "warn")
	t.Setenv(pfx+"INCLUDE_ERROR_LINKS", "false")
	t.Setenv(pfx+"MAX_ERROR_LINKS", "12")
	t.Setenv(pfx+"PYRO_SERVER", "https://pyro:4040")
	t.Setenv(pfx+"OTLP_ENDPOINT", "otel:4317")

	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	var c App
	Register(fs, &c)
	if err := fs.Parse(nil); err != nil {
		t.Fatalf("flag parse: %v", err)
	}
	FillFromEnv(fs, pfx, nil)

	if c.LogJSON != false {
		t.Error("LogJSON: want false from env")
	}
	if c.LogLevel != "debug" {
		t.Errorf("LogLevel: want %q, got %q", "debug", c.LogLevel)
	}
	if c.HTTPPort != 8088 {
		t.Errorf("HTTPPort: want 8088, got %d", c.HTTPPort)
	}
	if c.AdminPort != 9100 {
		t.Errorf("AdminPort: want 9100, got %d", c.AdminPort)
	}
	if c.EnablePprof != false {
		t.Error("EnablePprof: want false from env")
	}
	if c.EnablePyroscope != true {
		t.Error("EnablePyroscope: want true from env")
	}
	if c.EnableTracing != true {
		t.Error("EnableTracing: want true from env")
	}
	if c.TraceSample != 0.25 {
		t.Errorf("TraceSample: want 0.25, got %f", c.TraceSample)
	}
	if c.StacktraceLevel != "warn" {
		t.Errorf("StacktraceLevel: want %q, got %q", "warn", c.StacktraceLevel)
	}
	if c.IncludeErrorLinks != false {
		t.Error("IncludeErrorLinks: want false from env")
	}
	if c.MaxErrorLinks != 12 {
		t.Errorf("MaxErrorLinks: want 12, got %d", c.MaxErrorLinks)
	}
	if c.PyroServer != "https://pyro:4040" {
		t.Errorf("PyroServer: want %q, got %q", "https://pyro:4040", c.PyroServer)
	}
	if c.OTLPEndpoint != "otel:4317" {
		t.Errorf("OTLPEndpoint: want %q, got %q", "otel:4317", c.OTLPEndpoint)
	}
}

func TestFillFromEnv_CLITakesPrecedence(t *testing.T) {
	pfx := "TESTCFG2_"
	t.Setenv(pfx+"HTTP_PORT", "7777")
	t.Setenv(pfx+"LOG_LEVEL", "warn")
	t.Setenv(pfx+"ENABLE_PPROF", "false")

	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	var c App
	Register(fs, &c)
	if err := fs.Parse([]string{"-http-port=9090", "-log-level=debug", "-enable-pprof=true"}); err != nil {
		t.Fatalf("flag parse: %v", err)
	}

	var overrideMessages []string
	FillFromEnv(fs, pfx, func(format string, args ...any) {
		overrideMessages = append(overrideMessages, fmt.Sprintf(format, args...))
	})

	// CLI wins
	if c.HTTPPort != 9090 {
		t.Errorf("HTTPPort: want 9090 (cli), got %d", c.HTTPPort)
	}
	if c.LogLevel != "debug" {
		t.Errorf("LogLevel: want %q (cli), got %q", "debug", c.LogLevel)
	}
	if c.EnablePprof != true {
		t.Error("EnablePprof: want true (cli)")
	}

	// Should have logged override messages for all three
	if len(overrideMessages) != 3 {
		t.Errorf("expected 3 override messages, got %d: %v", len(overrideMessages), overrideMessages)
	}
	for _, msg := range overrideMessages {
		if !strings.Contains(msg, "overrides env") {
			t.Errorf("unexpected override message format: %s", msg)
		}
	}
}

func TestFillFromEnv_InvalidEnvIgnored(t *testing.T) {
	pfx := "TESTCFG3_"
	t.Setenv(pfx+"HTTP_PORT", "not-a-number")

	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	var c App
	Register(fs, &c)
	if err := fs.Parse(nil); err != nil {
		t.Fatalf("flag parse: %v", err)
	}

	var logMessages []string
	FillFromEnv(fs, pfx, func(format string, args ...any) {
		logMessages = append(logMessages, fmt.Sprintf(format, args...))
	})

	// Should keep default, not crash
	if c.HTTPPort != 8080 {
		t.Errorf("HTTPPort: want 8080 (default), got %d", c.HTTPPort)
	}
	// Should have logged the error
	if len(logMessages) != 1 {
		t.Fatalf("expected 1 log message, got %d: %v", len(logMessages), logMessages)
	}
	if !strings.Contains(logMessages[0], "ignoring invalid env") {
		t.Errorf("unexpected log message: %s", logMessages[0])
	}
}

func TestValidate_OK(t *testing.T) {
	c := newTestConfig(t, []string{
		"-enable-pyroscope=true",
		"-pyro-server=https://pyro:4040",
		"-pyro-tenant=test-tenant",
		"-enable-tracing=true",
		"-otlp-endpoint=otel:4317",
		"-trace-sample=0.2",
		"-content-signing-key-arn=arn:aws:kms:us-east-2:000000000000:key/content-key",
	})
	if err := Validate(c, false); err != nil {
		t.Fatalf("Validate() unexpected error: %v", err)
	}
}

func TestValidate_InvalidCombined(t *testing.T) {
	c := newTestConfig(t, []string{
		"-http-port=0",
		"-admin-port=70000",
		"-log-level=nope",
		"-stacktrace-level=alsonope",
		"-trace-sample=2.0",
		"-enable-pyroscope=true",
		"-pyro-server=not-a-url",
		"-enable-tracing=true",
		"-otlp-endpoint=otel",
		"-include-error-links=true",
		"-max-error-links=0",
	})

	err := Validate(c, false)
	if err == nil {
		t.Fatal("Validate() expected errors, got <nil>")
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

// validConfig returns an App with all fields set to valid, non-default values
// suitable for testing individual validation rules in isolation.
func validConfig() App {
	return App{
		LogJSON:               true,
		LogLevel:              "info",
		HTTPPort:              8080,
		AdminPort:             9000,
		EnablePprof:           true,
		StacktraceLevel:       "error",
		IncludeErrorLinks:     true,
		MaxErrorLinks:         5,
		TraceSample:           0.1,
		EvidenceSigningKeyARN: "arn:aws:kms:us-east-2:000000000000:key/evidence-key",
		ContentSigningKeyARN:  "arn:aws:kms:us-east-2:000000000000:key/content-key",
		DrainSeconds:          60,
		ShutdownBudgetSeconds: 30,
	}
}

func TestValidate_ContentUpdatesRequireSigningKey(t *testing.T) {
	c := validConfig()
	c.EnableContentUpdates = true
	c.ContentSSMParam = "/app/param"
	c.ContentS3Bucket = "my-bucket"
	c.ContentS3Prefix = "my/prefix"
	c.ContentSigningKeyARN = ""

	wantErrContains(t, Validate(c, false), "CONTENT_SIGNING_KEY_ARN is required when ENABLE_CONTENT_UPDATES=true")

	// Setting the key should clear the error
	c.ContentSigningKeyARN = "arn:aws:kms:us-east-2:000000000000:key/content-key"
	if err := Validate(c, false); err != nil {
		t.Fatalf("unexpected error with signing key set: %v", err)
	}
}

func TestValidate_ProvenanceRequiresBothKeys(t *testing.T) {
	t.Run("both missing", func(t *testing.T) {
		c := validConfig()
		c.EvidenceSigningKeyARN = ""
		c.ContentSigningKeyARN = ""
		wantErrContains(t, Validate(c, true), "evidence-signing-key-arn")
	})

	t.Run("evidence missing", func(t *testing.T) {
		c := validConfig()
		c.EvidenceSigningKeyARN = ""
		wantErrContains(t, Validate(c, true), "evidence-signing-key-arn")
	})

	t.Run("content missing", func(t *testing.T) {
		c := validConfig()
		c.ContentSigningKeyARN = ""
		wantErrContains(t, Validate(c, true), "content-signing-key-arn")
	})

	t.Run("both present", func(t *testing.T) {
		c := validConfig()
		if err := Validate(c, true); err != nil {
			t.Fatalf("unexpected error with both keys: %v", err)
		}
	})
}

func TestValidate_DrainSeconds_Invalid(t *testing.T) {
	c := validConfig()
	c.DrainSeconds = 0
	wantErrContains(t, Validate(c, false), "invalid DRAIN_SECONDS")

	c.DrainSeconds = -5
	wantErrContains(t, Validate(c, false), "invalid DRAIN_SECONDS")
}

func TestValidate_ShutdownBudgetSeconds_Invalid(t *testing.T) {
	c := validConfig()
	c.ShutdownBudgetSeconds = 0
	wantErrContains(t, Validate(c, false), "invalid SHUTDOWN_BUDGET_SECONDS")

	c.ShutdownBudgetSeconds = -1
	wantErrContains(t, Validate(c, false), "invalid SHUTDOWN_BUDGET_SECONDS")
}

func TestValidate_NoProvenanceSkipsKeyCheck(t *testing.T) {
	c := validConfig()
	c.EvidenceSigningKeyARN = ""
	c.ContentSigningKeyARN = ""
	if err := Validate(c, false); err != nil {
		t.Fatalf("unexpected error without provenance: %v", err)
	}
}
