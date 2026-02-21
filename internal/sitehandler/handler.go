package sitehandler

import (
	"io/fs"
	"net/http"
)

type Handler struct {
	opts Options
}

func New(opts *Options) (*Handler, error) {
	opts.setDefaults()
	if err := opts.validate(); err != nil {
		return nil, err
	}
	return &Handler{opts: *opts}, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// hardening: only allow GET/HEAD
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusMethodNotAllowed)
		// we keep counter metrics already which will alert us to issues without the overhead and security risk/sanitizing work of logging these
		// we should disable traces for these as well but that is part of a future update as otel doesnt expose a simple solution
		return
	}

	// get active content snapshot
	snap, ok := h.opts.Content.Get()

	// serve maintenance page if no active content snapshot
	if !ok {
		h.serveMaintenance(w, r)
		return
	}

	// resolve request -> file
	file, redirectTo, found := resolvePath(r.URL.Path, snap.FS)
	// handle redirects if returned by resolver
	if redirectTo != "" {
		// use 308 redirect to keep method even though we only use GET/HEAD
		http.Redirect(w, r, redirectTo, http.StatusPermanentRedirect)
		return
	}
	// handle not found
	if !found {
		h.serveNotFound(w, r, snap.FS)
		return
	}

	// apply cache-control policy (basic version based on file extension for now, will expand to cache posts and not homepage/tags/categories/etc)
	if cc := cacheControlForFile(file, &h.opts); cc != "" {
		w.Header().Set("Cache-Control", cc)
	}

	// serve the actual file from the active content FS
	http.ServeFileFS(w, r, snap.FS, file)
}

func (h *Handler) serveMaintenance(w http.ResponseWriter, r *http.Request) {
	// Maintenance should never be cached.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Retry-After", "60")

	serveFileWithStatus(w, r, http.StatusServiceUnavailable, h.opts.FallbackFS, h.opts.MaintenanceFile)
}

func (h *Handler) serveNotFound(w http.ResponseWriter, r *http.Request, siteFS fs.FS) {
	// avoid caching 404 responses
	w.Header().Set("Cache-Control", "no-store")

	// prefer themed 404 from the active snapshot
	if existsFile(siteFS, h.opts.Site404File) {
		serveFileWithStatus(w, r, http.StatusNotFound, siteFS, h.opts.Site404File)
		return
	}

	// fall back to embedded 404 if present
	if existsFile(h.opts.FallbackFS, h.opts.Fallback404File) {
		serveFileWithStatus(w, r, http.StatusNotFound, h.opts.FallbackFS, h.opts.Fallback404File)
		return
	}

	// last resort: plain text
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte("404 page not found"))
}

// we want to serve a file but force an HTTP status code (404/503)
// but http.ServeFileFS writes a status code on its own so wrapping
// ResponseWriter and overriding the first WriteHeader call here
type statusOverrideWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (w *statusOverrideWriter) WriteHeader(code int) {
	if w.wroteHeader {
		w.ResponseWriter.WriteHeader(code)
		return
	}
	w.wroteHeader = true
	w.ResponseWriter.WriteHeader(w.status)
}

func serveFileWithStatus(w http.ResponseWriter, r *http.Request, status int, fsys fs.FS, name string) {
	sw := &statusOverrideWriter{ResponseWriter: w, status: status}
	http.ServeFileFS(sw, r, fsys, name)
}
