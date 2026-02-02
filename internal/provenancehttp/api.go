package provenancehttp

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/keithlinneman/linnemanlabs-web/internal/content"
	"github.com/keithlinneman/linnemanlabs-web/internal/log"
)

// SnapshotProvider defines the interface for getting content snapshots
type SnapshotProvider interface {
	Get() (*content.Snapshot, bool)
}

// API implements the provenance API endpoints
type API struct {
	content SnapshotProvider
	logger  log.Logger
}

// NewAPI creates a new provenance API handler
func NewAPI(content SnapshotProvider, logger log.Logger) *API {
	if logger == nil {
		logger = log.Nop()
	}
	return &API{
		content: content,
		logger:  logger,
	}
}

// RegisterRoutes attaches provenance endpoints to the router
func (api *API) RegisterRoutes(r chi.Router) {
	r.Get("/api/provenance/content", api.HandleContentProvenance)
	r.Get("/api/provenance/content/summary", api.HandleContentSummary)
}

// ContentProvenanceResponse is the full provenance response
type ContentProvenanceResponse struct {
	// Bundle provenance from provenance.json
	Bundle *content.Provenance `json:"bundle,omitempty"`

	// Runtime information
	Runtime RuntimeInfo `json:"runtime"`

	// Error if provenance is unavailable
	Error string `json:"error,omitempty"`
}

// RuntimeInfo contains server-side runtime information
type RuntimeInfo struct {
	LoadedAt   time.Time      `json:"loaded_at"`
	ServerTime time.Time      `json:"server_time"`
	Source     content.Source `json:"source"`
	Hash       string         `json:"hash,omitempty"`
	Version    string         `json:"version,omitempty"`
}

// ContentSummaryResponse is a lightweight summary for the UI
type ContentSummaryResponse struct {
	Version     string    `json:"version"`
	ContentHash string    `json:"content_hash"`
	CommitShort string    `json:"commit_short"`
	CreatedAt   time.Time `json:"created_at"`
	TotalFiles  int       `json:"total_files"`
	TotalSize   int64     `json:"total_size"`
	Source      string    `json:"source"`
	LoadedAt    time.Time `json:"loaded_at"`
}

// HandleContentProvenance serves the full provenance data
func (api *API) HandleContentProvenance(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	snap, ok := api.content.Get()
	if !ok {
		api.writeJSON(ctx, w, http.StatusServiceUnavailable, ContentProvenanceResponse{
			Runtime: RuntimeInfo{
				ServerTime: time.Now().UTC().Truncate(time.Second),
			},
			Error: "no content loaded",
		})
		return
	}

	resp := ContentProvenanceResponse{
		Bundle: snap.Provenance,
		Runtime: RuntimeInfo{
			LoadedAt:   snap.LoadedAt.Truncate(time.Second),
			ServerTime: time.Now().UTC().Truncate(time.Second),
			Source:     snap.Meta.Source,
			Hash:       snap.Meta.SHA256,
			Version:    snap.Meta.Version,
		},
	}

	if snap.Provenance == nil {
		resp.Error = "provenance data not available for this bundle"
	}

	api.logger.Debug(ctx, "served content provenance",
		"version", snap.Meta.Version,
		"hash", snap.Meta.SHA256,
	)

	api.writeJSON(ctx, w, http.StatusOK, resp)
}

// HandleContentSummary serves a lightweight summary for UI display
func (api *API) HandleContentSummary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	snap, ok := api.content.Get()
	if !ok {
		http.Error(w, `{"error":"no content loaded"}`, http.StatusServiceUnavailable)
		return
	}

	resp := ContentSummaryResponse{
		Source:   string(snap.Meta.Source),
		LoadedAt: snap.LoadedAt.Truncate(time.Second),
	}

	// Fill in from provenance if available
	if p := snap.Provenance; p != nil {
		resp.Version = p.Version
		resp.ContentHash = p.ContentHash
		resp.CommitShort = p.Source.CommitShort
		resp.CreatedAt = p.CreatedAt
		resp.TotalFiles = p.Summary.TotalFiles
		resp.TotalSize = p.Summary.TotalSize
	} else {
		// Fall back to meta if no provenance
		resp.Version = snap.Meta.Version
		resp.ContentHash = snap.Meta.SHA256
	}

	api.logger.Debug(ctx, "served content summary",
		"version", resp.Version,
	)

	api.writeJSON(ctx, w, http.StatusOK, resp)
}

func (api *API) writeJSON(ctx context.Context, w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		api.logger.Warn(ctx, "failed to encode JSON response", "error", err)
	}
}
