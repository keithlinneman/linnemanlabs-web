package sitehttp

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

type Routes struct {
	Site http.Handler
}

func New(site http.Handler) *Routes {
	return &Routes{Site: site}
}

// todo revisit understanding this
// RegisterRoutes should be passed LAST so it becomes the final fallback.
func (rt *Routes) RegisterRoutes(r chi.Router) {
	// Use NotFound rather than a wildcard route so we don't interfere with
	// health/control routes registered by other registrars.
	r.NotFound(rt.Site.ServeHTTP)
	r.MethodNotAllowed(rt.Site.ServeHTTP)
}
