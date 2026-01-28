package opshttp

import (
	"net/http"

	"github.com/keithlinneman/linnemanlabs-web/internal/probe"
)

// HealthzHandler: 200 OK when probe passes, 503 otherwise (with reason)
func HealthzHandler(p probe.Probe) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if p != nil {
			if err := p.Check(r.Context()); err != nil {
				http.Error(w, err.Error()+"\n", http.StatusServiceUnavailable)
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	}
}

// ReadyzHandler: 200 OK when probe passes, 503 otherwise (with reason)
func ReadyzHandler(p probe.Probe) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if p != nil {
			if err := p.Check(r.Context()); err != nil {
				http.Error(w, err.Error()+"\n", http.StatusServiceUnavailable)
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready\n"))
	}
}
