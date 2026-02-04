package provenancehttp

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/keithlinneman/linnemanlabs-web/internal/content"
	"github.com/keithlinneman/linnemanlabs-web/internal/evidence"
	"github.com/keithlinneman/linnemanlabs-web/internal/log"
	v "github.com/keithlinneman/linnemanlabs-web/internal/version"
)

// SnapshotProvider defines the interface for getting content snapshots
type SnapshotProvider interface {
	Get() (*content.Snapshot, bool)
}

// API implements the provenance API endpoints
type API struct {
	content  SnapshotProvider
	evidence *evidence.Store
	logger   log.Logger
}

// NewAPI creates a new provenance API handler.
// evidenceStore can be nil (local builds with no evidence)
func NewAPI(content SnapshotProvider, evidenceStore *evidence.Store, logger log.Logger) *API {
	if logger == nil {
		logger = log.Nop()
	}
	return &API{
		content:  content,
		evidence: evidenceStore,
		logger:   logger,
	}
}

// RegisterRoutes attaches provenance endpoints to the router
func (api *API) RegisterRoutes(r chi.Router) {
	r.Get("/api/provenance/app", api.HandleAppProvenance)
	r.Get("/api/provenance/content", api.HandleContentProvenance)
	r.Get("/api/provenance/content/summary", api.HandleContentSummary)
	r.Get("/api/provenance/evidence", api.HandleEvidence)
	r.Get("/api/provenance/evidence/*", api.HandleEvidenceArtifact)
}

// AppProvenanceResponse wraps build info with evidence availability
type AppProvenanceResponse struct {
	Build    v.Info           `json:"build"`
	Evidence *EvidenceSummary `json:"evidence,omitempty"`
}

// EvidenceSummary is the lightweight evidence hint on the app provenance response
type EvidenceSummary struct {
	Available     bool     `json:"available"`
	ReleaseID     string   `json:"release_id,omitempty"`
	ArtifactCount int      `json:"artifact_count"`
	ArtifactNames []string `json:"artifact_names,omitempty"`
}

// ContentProvenanceResponse is the full provenance response
type ContentProvenanceResponse struct {
	Bundle  *content.Provenance `json:"bundle,omitempty"`
	Runtime RuntimeInfo         `json:"runtime"`
	Error   string              `json:"error,omitempty"`
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

// EvidenceManifestResponse is the list of available evidence artifacts
type EvidenceManifestResponse struct {
	ReleaseID     string             `json:"release_id"`
	Available     bool               `json:"available"`
	ArtifactCount int                `json:"artifact_count"`
	FetchedAt     time.Time          `json:"fetched_at,omitempty"`
	Artifacts     []EvidenceArtifact `json:"artifacts,omitempty"`
	Error         string             `json:"error,omitempty"`
}

// EvidenceArtifact is the manifest entry for a single evidence artifact
type EvidenceArtifact struct {
	Name        string    `json:"name"`
	Size        int64     `json:"size"`
	ContentType string    `json:"content_type,omitempty"`
	FetchedAt   time.Time `json:"fetched_at"`
	URL         string    `json:"url"`
}

// HandleAppProvenance serves application build provenance, enriched with evidence availability
func (api *API) HandleAppProvenance(w http.ResponseWriter, r *http.Request) {
	resp := AppProvenanceResponse{
		Build: v.Get(),
	}

	// attach evidence summary if we have any
	if api.evidence != nil {
		if bundle, ok := api.evidence.Get(); ok {
			resp.Evidence = &EvidenceSummary{
				Available:     len(bundle.Artifacts) > 0,
				ReleaseID:     bundle.ReleaseID,
				ArtifactCount: len(bundle.Artifacts),
				ArtifactNames: bundle.Names(),
			}
		}
	}

	api.writeJSON(r.Context(), w, http.StatusOK, resp)
}

// HandleContentProvenance serves the full content provenance data
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

	// fill in from provenance if available
	if p := snap.Provenance; p != nil {
		resp.Version = p.Version
		resp.ContentHash = p.ContentHash
		resp.CommitShort = p.Source.CommitShort
		resp.CreatedAt = p.CreatedAt
		resp.TotalFiles = p.Summary.TotalFiles
		resp.TotalSize = p.Summary.TotalSize
	} else {
		// fall back to meta if no provenance
		resp.Version = snap.Meta.Version
		resp.ContentHash = snap.Meta.SHA256
	}

	api.logger.Debug(ctx, "served content summary",
		"version", resp.Version,
	)

	api.writeJSON(ctx, w, http.StatusOK, resp)
}

// HandleEvidence serves the evidence manifest (list of all loaded attestation artifacts)
func (api *API) HandleEvidence(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if api.evidence == nil {
		api.writeJSON(ctx, w, http.StatusOK, EvidenceManifestResponse{
			Available: false,
			Error:     "no evidence available (local build)",
		})
		return
	}

	bundle, ok := api.evidence.Get()
	if !ok {
		api.writeJSON(ctx, w, http.StatusOK, EvidenceManifestResponse{
			Available: false,
			Error:     "evidence not loaded",
		})
		return
	}

	artifacts := make([]EvidenceArtifact, len(bundle.Artifacts))
	for i, a := range bundle.Artifacts {
		artifacts[i] = EvidenceArtifact{
			Name:        a.Name,
			Size:        a.Size,
			ContentType: a.ContentType,
			FetchedAt:   a.FetchedAt,
			URL:         "/api/provenance/evidence/" + a.Name,
		}
	}

	api.writeJSON(ctx, w, http.StatusOK, EvidenceManifestResponse{
		ReleaseID:     bundle.ReleaseID,
		Available:     len(bundle.Artifacts) > 0,
		ArtifactCount: len(bundle.Artifacts),
		FetchedAt:     bundle.FetchedAt,
		Artifacts:     artifacts,
	})
}

// HandleEvidenceArtifact serves a single raw evidence artifact by name
// Evidence is currently immutable so we cache it aggressively
// Soon evidence will probably be updated regularly and this will all be re-wrote
func (api *API) HandleEvidenceArtifact(w http.ResponseWriter, r *http.Request) {
	// extract artifact name from the wildcard path
	// chi wildcard gives us everything after /api/provenance/evidence/
	name := strings.TrimPrefix(r.URL.Path, "/api/provenance/evidence/")
	name = strings.TrimPrefix(name, "/")

	if name == "" {
		http.Error(w, `{"error":"artifact name required"}`, http.StatusBadRequest)
		return
	}

	if api.evidence == nil {
		http.Error(w, `{"error":"no evidence available"}`, http.StatusNotFound)
		return
	}

	art, ok := api.evidence.Artifact(name)
	if !ok {
		http.Error(w, `{"error":"artifact not found"}`, http.StatusNotFound)
		return
	}

	// evidence for a release is permanent so cache aggressively
	w.Header().Set("Cache-Control", "public, max-age=86400, immutable")

	ct := art.ContentType
	if ct == "" {
		ct = "application/json; charset=utf-8"
	}
	w.Header().Set("Content-Type", ct)
	w.WriteHeader(http.StatusOK)
	_, err := w.Write(art.RawJSON)
	if err != nil {
		api.logger.Warn(r.Context(), "failed to write evidence artifact",
			"artifact", name,
			"size", art.Size,
			"error", err,
		)
	}
}

func (api *API) writeJSON(ctx context.Context, w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		api.logger.Warn(ctx, "failed to encode JSON response", "error", err)
	}
}
