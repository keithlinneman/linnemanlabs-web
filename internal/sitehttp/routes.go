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

// RegisterRoutes final fallback for all unmatched routes
func (rt *Routes) RegisterRoutes(r chi.Router) {
	r.NotFound(rt.Site.ServeHTTP)
	r.MethodNotAllowed(rt.Site.ServeHTTP)
}
