package httpserver

import (
	"net/http"

	"github.com/keithlinneman/linnemanlabs-web/internal/httpmw"
	"github.com/keithlinneman/linnemanlabs-web/internal/log"
	"github.com/keithlinneman/linnemanlabs-web/internal/probe"
)

type Options struct {
	Logger       log.Logger
	Port         int
	UseRecoverMW bool
	MetricsMW    func(http.Handler) http.Handler
	Health       probe.Probe
	Readiness    probe.Probe
	ContentInfo  httpmw.ContentInfo // For X-Content-Bundle-Version and X-Content-Hash headers
}
