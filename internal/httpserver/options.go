package httpserver

import (
	"net/http"

	"linnemanlabs/internal/log"
	"linnemanlabs/internal/probe"
)

type Options struct {
	Logger       log.Logger
	Port         int
	UseRecoverMW bool
	MetricsMW    func(http.Handler) http.Handler
	Health       probe.Probe
	Readiness    probe.Probe
}
