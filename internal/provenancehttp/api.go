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

// NewAPI creates a new provenance API handler
// evidenceStore may be nil for local builds without provenance
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
	// App build provenance (full)
	r.Get("/api/provenance/app", api.HandleAppProvenance)

	// App build summary (frontend-optimized)
	r.Get("/api/provenance/app/summary", api.HandleAppSummary)

	// Content bundle provenance
	r.Get("/api/provenance/content", api.HandleContentProvenance)
	r.Get("/api/provenance/content/summary", api.HandleContentSummary)

	// Build evidence
	r.Get("/api/provenance/evidence", api.HandleEvidenceManifest)
	r.Get("/api/provenance/evidence/release.json", api.HandleReleaseJSON)
	r.Get("/api/provenance/evidence/inventory.json", api.HandleInventoryJSON)
	r.Get("/api/provenance/evidence/files/*", api.HandleEvidenceFile)
}

// AppProvenanceResponse wraps build info with evidence summary
type AppProvenanceResponse struct {
	Build    v.Info           `json:"build"`
	Evidence *EvidenceSummary `json:"evidence,omitempty"`
}

// EvidenceSummary is the lightweight evidence indicator on the app provenance response
type EvidenceSummary struct {
	Available  bool           `json:"available"`
	ReleaseID  string         `json:"release_id,omitempty"`
	Version    string         `json:"version,omitempty"`
	FileCount  int            `json:"file_count"`
	Categories map[string]int `json:"categories,omitempty"`
	FetchedAt  time.Time      `json:"fetched_at,omitempty"`
}

// ContentProvenanceResponse is the full content provenance response
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

// EvidenceManifestResponse is the browsable manifest of all available evidence
type EvidenceManifestResponse struct {
	Available bool   `json:"available"`
	Error     string `json:"error,omitempty"`

	ReleaseID string    `json:"release_id,omitempty"`
	Version   string    `json:"version,omitempty"`
	Component string    `json:"component,omitempty"`
	Track     string    `json:"track,omitempty"`
	CreatedAt time.Time `json:"created_at,omitempty"`
	FetchedAt time.Time `json:"fetched_at,omitempty"`

	Source  *evidence.ReleaseSource  `json:"source,omitempty"`
	Builder *evidence.ReleaseBuilder `json:"builder,omitempty"`

	// Evidence counts by "scope.category.kind"
	Categories map[string]int `json:"categories,omitempty"`

	// Full file index for browsing
	Files []*evidence.EvidenceFileRef `json:"files,omitempty"`

	// Links to raw manifests
	Links map[string]string `json:"_links,omitempty"`
}

// AppSummaryResponse is the lightweight app build summary for frontend consumption
// All data is projected from the build system's release.json
type AppSummaryResponse struct {
	HasEvidence bool   `json:"has_evidence"`
	Error       string `json:"error,omitempty"`

	Version   string    `json:"version,omitempty"`
	BuildID   string    `json:"build_id,omitempty"`
	Track     string    `json:"track,omitempty"`
	CreatedAt time.Time `json:"created_at,omitempty"`
	FetchedAt time.Time `json:"fetched_at,omitempty"`

	Source  *AppSummarySource  `json:"source,omitempty"`
	Builder *AppSummaryBuilder `json:"builder,omitempty"`

	Vulnerabilities *AppSummaryVulns      `json:"vulnerabilities,omitempty"`
	SBOM            *AppSummarySBOM       `json:"sbom,omitempty"`
	Licenses        *AppSummaryLicenses   `json:"licenses,omitempty"`
	Signing         *AppSummarySigning    `json:"signing,omitempty"`
	SLSA            *AppSummarySLSA       `json:"slsa,omitempty"`
	Evidence        *AppSummaryEvidence   `json:"evidence,omitempty"`
	Components      []AppSummaryComponent `json:"components,omitempty"`

	// Links to detailed endpoints for drill-down
	Links map[string]string `json:"_links,omitempty"`
}

type AppSummarySource struct {
	Repository  string    `json:"repository"`
	Commit      string    `json:"commit"`
	CommitShort string    `json:"commit_short"`
	CommitDate  time.Time `json:"commit_date"`
	Branch      string    `json:"branch,omitempty"`
	Tag         string    `json:"tag,omitempty"`
	Dirty       bool      `json:"dirty"`
}

type AppSummaryBuilder struct {
	Repository  string `json:"repository"`
	CommitShort string `json:"commit_short"`
	Dirty       bool   `json:"dirty"`
}

type AppSummaryVulns struct {
	Counts        evidence.VulnCounts `json:"counts"`
	Total         int                 `json:"total"`
	WorstSeverity string              `json:"worst_severity"`
	GateThreshold string              `json:"gate_threshold"`
	GateResult    string              `json:"gate_result"`
	ScannersUsed  []string            `json:"scanners_used"`
	ScannedAt     string              `json:"scanned_at"`
}

type AppSummarySBOM struct {
	Generators           []string `json:"generators"`
	FormatsProduced      []string `json:"formats_produced"`
	SourcePackageCount   int      `json:"source_package_count"`
	ArtifactPackageCount int      `json:"artifact_package_count"`
}

type AppSummaryLicenses struct {
	Compliant           bool     `json:"compliant"`
	UniqueLicenses      []string `json:"unique_licenses"`
	DeniedFound         []string `json:"denied_found"`
	WithoutLicenseCount int      `json:"without_license_count"`
}

type AppSummarySigning struct {
	Method            string `json:"method"`
	ArtifactsAttested bool   `json:"artifacts_attested"`
	IndexAttested     bool   `json:"index_attested"`
	InventorySigned   bool   `json:"inventory_signed"`
	ReleaseSigned     bool   `json:"release_signed"`
}

type AppSummarySLSA struct {
	ProvenanceGenerated bool   `json:"provenance_generated"`
	Level               int    `json:"level,omitempty"`
	Note                string `json:"note,omitempty"`
}

type AppSummaryEvidence struct {
	FileCount    int                            `json:"file_count"`
	Categories   map[string]int                 `json:"categories,omitempty"`
	Completeness *evidence.EvidenceCompleteness `json:"completeness,omitempty"`
}

type AppSummaryComponent struct {
	OS   string `json:"os"`
	Arch string `json:"arch"`

	Binary *AppSummaryBinary `json:"binary,omitempty"`
	OCI    *AppSummaryOCI    `json:"oci,omitempty"`
}

type AppSummaryBinary struct {
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type AppSummaryOCI struct {
	Repository string `json:"repository"`
	Tag        string `json:"tag"`
	Digest     string `json:"digest"`
	PushedAt   string `json:"pushed_at,omitempty"`
}

// HandleAppProvenance serves application build provenance with evidence summary
func (api *API) HandleAppProvenance(w http.ResponseWriter, r *http.Request) {
	resp := AppProvenanceResponse{
		Build: v.Get(),
	}

	if api.evidence != nil {
		if bundle, ok := api.evidence.Get(); ok {
			resp.Evidence = &EvidenceSummary{
				Available:  len(bundle.Files) > 0,
				ReleaseID:  bundle.Release.ReleaseID,
				Version:    bundle.Release.Version,
				FileCount:  len(bundle.Files),
				Categories: bundle.Summary(),
				FetchedAt:  bundle.FetchedAt,
			}
		}
	}

	api.writeJSON(r.Context(), w, http.StatusOK, resp)
}

// HandleAppSummary serves the lightweight app build summary for frontend consumption
// This is a pure projection of release.json data
func (api *API) HandleAppSummary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if api.evidence == nil {
		api.writeJSON(ctx, w, http.StatusOK, AppSummaryResponse{
			HasEvidence: false,
			Error:       "evidence not configured (local build)",
			Links:       appSummaryLinks(),
		})
		return
	}

	bundle, ok := api.evidence.Get()
	if !ok {
		api.writeJSON(ctx, w, http.StatusOK, AppSummaryResponse{
			HasEvidence: false,
			Error:       "no evidence loaded",
			Links:       appSummaryLinks(),
		})
		return
	}

	rel := bundle.Release
	resp := AppSummaryResponse{
		HasEvidence: true,
		Version:     rel.Version,
		BuildID:     rel.BuildID,
		Track:       rel.Track,
		CreatedAt:   rel.CreatedAt,
		FetchedAt:   bundle.FetchedAt,
		Links:       appSummaryLinks(),
	}

	// Source
	resp.Source = buildAppSummarySource(&rel.Source)

	// Builder
	resp.Builder = &AppSummaryBuilder{
		Repository:  rel.Builder.Repo,
		CommitShort: rel.Builder.CommitShort,
		Dirty:       rel.Builder.Dirty,
	}

	// Project summary block (all from build system)
	if s := rel.Summary; s != nil {
		if v := s.Vulnerabilities; v != nil {
			resp.Vulnerabilities = &AppSummaryVulns{
				Counts:        v.Counts,
				Total:         v.Total,
				WorstSeverity: v.WorstSeverity,
				GateThreshold: v.GateThreshold,
				GateResult:    v.GateResult,
				ScannersUsed:  v.ScannersUsed,
				ScannedAt:     v.ScannedAt,
			}
		}

		if sb := s.SBOM; sb != nil {
			resp.SBOM = &AppSummarySBOM{
				Generators:           sb.Generators,
				FormatsProduced:      sb.FormatsProduced,
				SourcePackageCount:   sb.SourcePackageCount,
				ArtifactPackageCount: sb.ArtifactPackageCount,
			}
		}

		if l := s.Licenses; l != nil {
			resp.Licenses = &AppSummaryLicenses{
				Compliant:           l.Compliant,
				UniqueLicenses:      l.UniqueLicenses,
				DeniedFound:         l.DeniedFound,
				WithoutLicenseCount: l.WithoutLicenseCount,
			}
		}

		if sg := s.Signing; sg != nil {
			resp.Signing = &AppSummarySigning{
				Method:            sg.Method,
				ArtifactsAttested: sg.ArtifactsAttested,
				IndexAttested:     sg.IndexAttested,
				InventorySigned:   sg.InventorySigned,
				ReleaseSigned:     sg.ReleaseSigned,
			}
		}

		if sl := s.SLSA; sl != nil {
			resp.SLSA = &AppSummarySLSA{
				ProvenanceGenerated: sl.ProvenanceGenerated,
				Level:               sl.Level,
				Note:                sl.Note,
			}
		}

		resp.Evidence = &AppSummaryEvidence{
			FileCount:    len(bundle.Files),
			Categories:   bundle.Summary(),
			Completeness: s.EvidenceComplete,
		}
	} else {
		// No summary block in release.json, still report evidence file counts
		resp.Evidence = &AppSummaryEvidence{
			FileCount:  len(bundle.Files),
			Categories: bundle.Summary(),
		}
	}

	// Components: merge per-platform artifacts with OCI info
	resp.Components = buildAppSummaryComponents(rel)

	api.logger.Debug(ctx, "served app summary",
		"version", resp.Version,
		"has_evidence", resp.HasEvidence,
	)

	api.writeJSON(ctx, w, http.StatusOK, resp)
}

// buildAppSummarySource projects ReleaseSource into the frontend-friendly shape.
// handles the tag-build case where branch/ref may be "unknown".
func buildAppSummarySource(src *evidence.ReleaseSource) *AppSummarySource {
	if src == nil {
		return nil
	}

	out := &AppSummarySource{
		Repository:  src.Repo,
		Commit:      src.Commit,
		CommitShort: src.CommitShort,
		CommitDate:  src.CommitDate,
		Dirty:       src.Dirty,
	}

	// for tag builds, branch is often empty/unknown — use base_tag as the meaningful ref
	if src.BaseTag != "" {
		out.Tag = src.BaseTag
	}

	// only include branch if it's actually meaningful
	branch := src.ResolvedBranch
	if branch != "" && branch != "unknown" {
		out.Branch = branch
	}

	return out
}

// buildAppSummaryComponents merges the per-platform artifacts with OCI info
// OCI is shared across all platforms (it's a multi-arch index), so we attach
// it to each component for frontend convenience.
func buildAppSummaryComponents(rel *evidence.ReleaseManifest) []AppSummaryComponent {
	if len(rel.Artifacts) == 0 {
		return nil
	}

	// Build shared OCI reference (same index for all platforms)
	var sharedOCI *AppSummaryOCI
	if rel.OCI.Repository != "" {
		sharedOCI = &AppSummaryOCI{
			Repository: rel.OCI.Repository,
			Tag:        rel.OCI.Tag,
			Digest:     rel.OCI.Digest,
			PushedAt:   rel.OCI.PushedAt,
		}
	}

	out := make([]AppSummaryComponent, 0, len(rel.Artifacts))
	for _, a := range rel.Artifacts {
		c := AppSummaryComponent{
			OS:   a.OS,
			Arch: a.Arch,
			Binary: &AppSummaryBinary{
				SHA256: a.Binary.SHA256,
				Size:   a.Binary.Size,
			},
			OCI: sharedOCI,
		}
		out = append(out, c)
	}
	return out
}

func appSummaryLinks() map[string]string {
	return map[string]string{
		"full":      "/api/provenance/app",
		"evidence":  "/api/provenance/evidence",
		"release":   "/api/provenance/evidence/release.json",
		"inventory": "/api/provenance/evidence/inventory.json",
		"content":   "/api/provenance/content/summary",
	}
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

	if p := snap.Provenance; p != nil {
		resp.Version = p.Version
		resp.ContentHash = p.ContentHash
		resp.CommitShort = p.Source.CommitShort
		resp.CreatedAt = p.CreatedAt
		resp.TotalFiles = p.Summary.TotalFiles
		resp.TotalSize = p.Summary.TotalSize
	} else {
		resp.Version = snap.Meta.Version
		resp.ContentHash = snap.Meta.SHA256
	}

	api.writeJSON(ctx, w, http.StatusOK, resp)
}

// HandleEvidenceManifest serves the browsable evidence manifest
func (api *API) HandleEvidenceManifest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if api.evidence == nil {
		api.writeJSON(ctx, w, http.StatusOK, EvidenceManifestResponse{
			Available: false,
			Error:     "evidence not configured (local build)",
		})
		return
	}

	bundle, ok := api.evidence.Get()
	if !ok {
		api.writeJSON(ctx, w, http.StatusOK, EvidenceManifestResponse{
			Available: false,
			Error:     "no evidence loaded",
		})
		return
	}

	// collect all file refs
	files := make([]*evidence.EvidenceFileRef, 0, len(bundle.FileIndex))
	for _, ref := range bundle.FileIndex {
		files = append(files, ref)
	}

	resp := EvidenceManifestResponse{
		Available:  true,
		ReleaseID:  bundle.Release.ReleaseID,
		Version:    bundle.Release.Version,
		Component:  bundle.Release.Component,
		Track:      bundle.Release.Track,
		CreatedAt:  bundle.Release.CreatedAt,
		FetchedAt:  bundle.FetchedAt,
		Source:     &bundle.Release.Source,
		Builder:    &bundle.Release.Builder,
		Categories: bundle.Summary(),
		Files:      files,
		Links: map[string]string{
			"release":   "/api/provenance/evidence/release.json",
			"inventory": "/api/provenance/evidence/inventory.json",
		},
	}

	api.logger.Debug(ctx, "served evidence manifest",
		"release_id", bundle.Release.ReleaseID,
		"file_count", len(files),
	)

	api.writeJSON(ctx, w, http.StatusOK, resp)
}

// HandleReleaseJSON serves the raw release.json
func (api *API) HandleReleaseJSON(w http.ResponseWriter, r *http.Request) {
	if api.evidence == nil {
		http.Error(w, `{"error":"evidence not configured"}`, http.StatusNotFound)
		return
	}

	bundle, ok := api.evidence.Get()
	if !ok || bundle.ReleaseRaw == nil {
		http.Error(w, `{"error":"no evidence loaded"}`, http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	// immutable for a given release (for now at least, will do re-scans etc soon)
	w.Header().Set("Cache-Control", "public, max-age=86400, immutable")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(bundle.ReleaseRaw)
}

// HandleInventoryJSON serves the raw inventory.json
func (api *API) HandleInventoryJSON(w http.ResponseWriter, r *http.Request) {
	if api.evidence == nil {
		http.Error(w, `{"error":"evidence not configured"}`, http.StatusNotFound)
		return
	}

	bundle, ok := api.evidence.Get()
	if !ok || bundle.InventoryRaw == nil {
		http.Error(w, `{"error":"no evidence loaded"}`, http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=86400, immutable")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(bundle.InventoryRaw)
}

// HandleEvidenceFile serves an individual evidence file by its inventory path (served from memory)
func (api *API) HandleEvidenceFile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// chi wildcard gives us everything after /files/
	filePath := chi.URLParam(r, "*")
	if filePath == "" {
		http.Error(w, `{"error":"file path required"}`, http.StatusBadRequest)
		return
	}

	// basic path sanitization
	if strings.Contains(filePath, "..") || strings.HasPrefix(filePath, "/") {
		http.Error(w, `{"error":"invalid path"}`, http.StatusBadRequest)
		return
	}

	if api.evidence == nil {
		http.Error(w, `{"error":"evidence not configured"}`, http.StatusNotFound)
		return
	}

	file, ok := api.evidence.File(filePath)
	if !ok {
		// distinguish "path not in manifest" from "known but failed to load"
		if _, inIndex := api.evidence.FileRef(filePath); inIndex {
			http.Error(w, `{"error":"evidence file known but not loaded (fetch failed at startup)"}`,
				http.StatusServiceUnavailable)
		} else {
			http.Error(w, `{"error":"file not found in inventory"}`, http.StatusNotFound)
		}
		return
	}

	api.logger.Debug(ctx, "served evidence file",
		"path", filePath,
		"size", len(file.Data),
		"category", file.Ref.Category,
		"kind", file.Ref.Kind,
	)

	// content type: in-toto for attestations, json for everything else
	contentType := "application/json; charset=utf-8"
	if file.Ref.Kind == "attestation" {
		contentType = "application/vnd.in-toto+json"
	}

	w.Header().Set("Content-Type", contentType)
	// evidence is immutable and hash-addressed via inventory (will do periodic re-scans soon)
	w.Header().Set("Cache-Control", "public, max-age=86400, immutable")
	w.WriteHeader(http.StatusOK)
	_, err := w.Write(file.Data)
	if err != nil {
		api.logger.Warn(ctx, "failed to write evidence file response",
			"path", filePath,
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
