package opshttp

import (
	"net/http"

	"github.com/keithlinneman/linnemanlabs-web/internal/health"
)

type Options struct {
	Port         int
	Metrics      http.Handler
	EnablePprof  bool
	Health       health.Probe
	Readiness    health.Probe
	UseRecoverMW bool
	OnPanic      func() // Optional callback for when panics are recovered, e.g. to trigger alerts or increment prometheus counters, etc.
}
