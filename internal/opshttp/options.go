package opshttp

import (
	"net/http"

	"github.com/keithlinneman/linnemanlabs-web/internal/probe"
)

type Options struct {
	Port         int
	Metrics      http.Handler
	EnablePprof  bool
	Health       probe.Probe
	Readiness    probe.Probe
	UseRecoverMW bool
}
