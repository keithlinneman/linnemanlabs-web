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
	"github.com/keithlinneman/linnemanlabs-web/internal/pathutil"
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

// AppProvenanceResponse is the comprehensive app provenance endpoint.
// Returns everything: build info, full release manifest, parsed policy,
// attestation details, and complete evidence file index.
// The summary endpoint abbreviates from this.
type AppProvenanceResponse struct {
	Build v.Info `json:"build"`

	// Full release manifest from the build system (nil for local builds)
	Release *evidence.ReleaseManifest `json:"release,omitempty"`

	// Parsed policy from release.json (extracted from raw JSON for convenience)
	Policy *evidence.ReleasePolicy `json:"policy,omitempty"`

	// Attestation details derived from the evidence file index
	Attestations *AppProvenanceAttestations `json:"attestations,omitempty"`

	// Evidence loading status and complete file index
	Evidence *AppProvenanceEvidence `json:"evidence,omitempty"`

	// Enriched license data with per-license counts (derived from evidence files)
	Licenses *AppProvenanceLicenses `json:"licenses,omitempty"`

	// Full package list with license status evaluated against build policy
	Packages []evidence.PackageInfo `json:"packages,omitempty"`

	// When evidence was loaded
	FetchedAt time.Time `json:"fetched_at,omitempty"`

	// Links to related endpoints
	Links map[string]string `json:"_links"`
}

// AppProvenanceAttestations is the attestation detail on the full endpoint
// richer than the summary - includes per-file references
type AppProvenanceAttestations struct {
	Total    int `json:"total"`
	Source   int `json:"source"`
	Artifact int `json:"artifact"`

	SBOMAttested    bool `json:"sbom_attested"`
	ScanAttested    bool `json:"scan_attested"`
	LicenseAttested bool `json:"license_attested"`

	// Full list of attestation files with metadata
	Files []*evidence.EvidenceFileRef `json:"files,omitempty"`
}

// AppProvenanceEvidence is the full evidence status on the comprehensive endpoint
type AppProvenanceEvidence struct {
	Available     bool                        `json:"available"`
	FileCount     int                         `json:"file_count"`
	Categories    map[string]int              `json:"categories,omitempty"`
	InventoryHash string                      `json:"inventory_hash,omitempty"`
	Files         []*evidence.EvidenceFileRef `json:"files,omitempty"`
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

// AppSummaryResponse is the app build summary for frontend consumption
// includes build context, policy, attestation counts, per-scanner vuln breakdowns
type AppSummaryResponse struct {
	HasEvidence bool   `json:"has_evidence"`
	Error       string `json:"error,omitempty"`

	// Release identity
	Version   string    `json:"version,omitempty"`
	ReleaseID string    `json:"release_id,omitempty"`
	BuildID   string    `json:"build_id,omitempty"`
	Track     string    `json:"track,omitempty"`
	CreatedAt time.Time `json:"created_at,omitempty"`
	FetchedAt time.Time `json:"fetched_at,omitempty"`

	// build context - who/how/where (from binary ldflags)
	BuildActor      string `json:"build_actor,omitempty"`
	BuildSystem     string `json:"build_system,omitempty"`
	BuildRunURL     string `json:"build_run_url,omitempty"`
	BuilderIdentity string `json:"builder_identity,omitempty"`
	GoVersion       string `json:"go_version,omitempty"`

	Source  *AppSummarySource  `json:"source,omitempty"`
	Builder *AppSummaryBuilder `json:"builder,omitempty"`

	Vulnerabilities  *AppSummaryVulns            `json:"vulnerabilities,omitempty"`
	SBOM             *AppSummarySBOM             `json:"sbom,omitempty"`
	Licenses         *AppSummaryLicenses         `json:"licenses,omitempty"`
	Signing          *AppSummarySigning          `json:"signing,omitempty"`
	SLSA             *AppSummarySLSA             `json:"slsa,omitempty"`
	Policy           *AppSummaryPolicy           `json:"policy,omitempty"`
	PolicyCompliance *AppSummaryPolicyCompliance `json:"policy_compliance,omitempty"`
	Attestations     *AppSummaryAttestations     `json:"attestations,omitempty"`
	Evidence         *AppSummaryEvidence         `json:"evidence,omitempty"`
	Components       []AppSummaryComponent       `json:"components,omitempty"`

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
	Repository  string    `json:"repository"`
	Branch      string    `json:"branch,omitempty"`
	Commit      string    `json:"commit"`
	CommitShort string    `json:"commit_short"`
	CommitDate  time.Time `json:"commit_date"`
	Dirty       bool      `json:"dirty"`
}

type AppSummaryVulns struct {
	Counts        evidence.VulnCounts `json:"counts"`
	Total         int                 `json:"total"`
	WorstSeverity string              `json:"worst_severity"`
	GateThreshold string              `json:"gate_threshold"`
	GateResult    string              `json:"gate_result"`
	ScannersUsed  []string            `json:"scanners_used"`
	ScannedAt     string              `json:"scanned_at"`

	// per-scanner raw breakdown
	ByScanner map[string]json.RawMessage `json:"by_scanner,omitempty"`

	// what was scanned (source+artifacts) and how results were reconciled
	Scope         string `json:"scope,omitempty"`
	Deduplication string `json:"deduplication,omitempty"`
}

type AppSummarySBOM struct {
	Generators           []string `json:"generators"`
	FormatsProduced      []string `json:"formats_produced"`
	SourcePackageCount   int      `json:"source_package_count"`
	ArtifactPackageCount int      `json:"artifact_package_count"`
	GeneratedAt          string   `json:"generated_at,omitempty"`
}

type AppSummaryLicenses struct {
	Compliant           bool     `json:"compliant"`
	UniqueLicenses      []string `json:"unique_licenses"`
	DeniedFound         []string `json:"denied_found"`
	WithoutLicenseCount int      `json:"without_license_count"`
}

type AppSummarySigning struct {
	Method                 string `json:"method"`
	KeyRef                 string `json:"key_ref,omitempty"`
	ArtifactsAttested      bool   `json:"artifacts_attested"`
	IndexAttested          bool   `json:"index_attested"`
	InventorySigned        bool   `json:"inventory_signed"`
	ReleaseSigned          bool   `json:"release_signed"`
	ReleaseSigstoreBundled bool   `json:"release_sigstore_bundled"`
}

type AppSummarySLSA struct {
	ProvenanceGenerated bool   `json:"provenance_generated"`
	Level               int    `json:"level,omitempty"`
	BuilderID           string `json:"builder_id,omitempty"`
	BuildType           string `json:"build_type,omitempty"`
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
	Repository   string `json:"repository"`
	Tag          string `json:"tag"`
	Digest       string `json:"digest"`
	DigestRef    string `json:"digest_ref,omitempty"`
	MediaType    string `json:"media_type,omitempty"`
	ArtifactType string `json:"artifact_type,omitempty"`
	PushedAt     string `json:"pushed_at,omitempty"`
}

// AppSummaryPolicy is the structured build policy that was enforced
type AppSummaryPolicy struct {
	Enforcement   string                   `json:"enforcement"`
	Signing       AppSummaryPolicySigning  `json:"signing"`
	Evidence      AppSummaryPolicyEvidence `json:"evidence"`
	Vulnerability AppSummaryPolicyVuln     `json:"vulnerability"`
	License       AppSummaryPolicyLicense  `json:"license"`
}

type AppSummaryPolicySigning struct {
	RequireInventorySignature bool `json:"require_inventory_signature"`
	RequireSubjectSignatures  bool `json:"require_subject_signatures"`
}

type AppSummaryPolicyEvidence struct {
	SBOMRequired         bool `json:"sbom_required"`
	ScanRequired         bool `json:"scan_required"`
	LicenseRequired      bool `json:"license_required"`
	ProvenanceRequired   bool `json:"provenance_required"`
	AttestationsRequired bool `json:"attestations_required"`
}

type AppSummaryPolicyVuln struct {
	BlockOn    []string `json:"block_on,omitempty"` // ["critical", "high"]
	AllowIfVEX bool     `json:"allow_if_vex"`
}

type AppSummaryPolicyLicense struct {
	Denied       []string `json:"denied,omitempty"`  // SPDX deny patterns
	Allowed      []string `json:"allowed,omitempty"` // SPDX explicit allowlist
	AllowUnknown bool     `json:"allow_unknown"`
}

// AppSummaryAttestations summarizes what attestations exist in the evidence bundle
// Counts are derived from the inventory file index at load time
type AppSummaryAttestations struct {
	Total int `json:"total"`

	// per-scope counts
	SourceAttestations   int `json:"source_attestations"`
	ArtifactAttestations int `json:"artifact_attestations"`

	// whats attested (derived from evidence file classification)
	SBOMAttested    bool `json:"sbom_attested"`
	ScanAttested    bool `json:"scan_attested"`
	LicenseAttested bool `json:"license_attested"`
}

// AppProvenanceLicenses is the enriched license section on the full endpoint.
// Combines the summary from release.json with license_counts derived from
// the actual license report evidence files.
type AppProvenanceLicenses struct {
	Compliant           bool           `json:"compliant"`
	UniqueLicenses      []string       `json:"unique_licenses"`
	LicenseCounts       map[string]int `json:"license_counts,omitempty"`
	DeniedFound         []string       `json:"denied_found"`
	WithoutLicenseCount int            `json:"without_license_count"`
}

// HandleAppProvenance serves the comprehensive app provenance: build info + full release
// manifest + parsed policy + attestation details + complete evidence file index
// This is the "give me everything" endpoint - the summary abbreviates from this
func (api *API) HandleAppProvenance(w http.ResponseWriter, r *http.Request) {
	resp := AppProvenanceResponse{
		Build: v.Get(),
		Links: map[string]string{
			"summary":   "/api/provenance/app/summary",
			"evidence":  "/api/provenance/evidence",
			"release":   "/api/provenance/evidence/release.json",
			"inventory": "/api/provenance/evidence/inventory.json",
			"content":   "/api/provenance/content",
		},
	}

	if api.evidence == nil {
		api.writeJSON(r.Context(), w, http.StatusOK, resp)
		return
	}

	bundle, ok := api.evidence.Get()
	if !ok {
		api.writeJSON(r.Context(), w, http.StatusOK, resp)
		return
	}

	resp.Release = bundle.Release
	resp.FetchedAt = bundle.FetchedAt

	// Parse policy from raw JSON into structured form
	if bundle.Release != nil {
		pol, err := evidence.ParsePolicy(bundle.Release.Policy)
		if err != nil {
			api.logger.Warn(r.Context(), "parse policy", "error", err)
		}
		if pol != nil {
			resp.Policy = pol
		}
	}

	// Build attestation details from file index
	ac := bundle.Attestations()
	if ac.Total > 0 {
		attestationFiles := make([]*evidence.EvidenceFileRef, 0, ac.Total)
		for _, ref := range bundle.FileIndex {
			if ref.Kind == "attestation" {
				attestationFiles = append(attestationFiles, ref)
			}
		}

		resp.Attestations = &AppProvenanceAttestations{
			Total:           ac.Total,
			Source:          ac.Source,
			Artifact:        ac.Artifact,
			SBOMAttested:    ac.SBOMAttested,
			ScanAttested:    ac.ScanAttested,
			LicenseAttested: ac.LicenseAttested,
			Files:           attestationFiles,
		}
	}

	// Full evidence file index
	allFiles := make([]*evidence.EvidenceFileRef, 0, len(bundle.FileIndex))
	for _, ref := range bundle.FileIndex {
		allFiles = append(allFiles, ref)
	}

	resp.Evidence = &AppProvenanceEvidence{
		Available:     len(bundle.Files) > 0,
		FileCount:     len(bundle.Files),
		Categories:    bundle.Summary(),
		InventoryHash: bundle.InventoryHash,
		Files:         allFiles,
	}

	// License packages and enriched license summary from evidence files
	licenses, packages := buildLicenseData(bundle, resp.Policy)
	if licenses != nil {
		resp.Licenses = licenses
	}
	if len(packages) > 0 {
		resp.Packages = packages
	}

	api.writeJSON(r.Context(), w, http.StatusOK, resp)
}

// HandleAppSummary serves the lightweight app build summary for frontend consumption
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
	bi := v.Get()

	resp := AppSummaryResponse{
		HasEvidence: true,
		Version:     rel.Version,
		ReleaseID:   rel.ReleaseID,
		BuildID:     rel.BuildID,
		Track:       rel.Track,
		CreatedAt:   rel.CreatedAt,
		FetchedAt:   bundle.FetchedAt,
		Links:       appSummaryLinks(),

		// build context - who/how/where (from compile-time ldflags)
		BuildActor:      bi.BuildActor,
		BuildSystem:     bi.BuildSystem,
		BuildRunURL:     bi.BuildRunURL,
		BuilderIdentity: bi.BuilderIdentity,
		GoVersion:       bi.GoVersion,
	}

	// source
	resp.Source = buildAppSummarySource(&rel.Source)

	// builder
	resp.Builder = &AppSummaryBuilder{
		Repository:  rel.Builder.Repo,
		Branch:      rel.Builder.Branch,
		Commit:      rel.Builder.Commit,
		CommitShort: rel.Builder.CommitShort,
		CommitDate:  rel.Builder.CommitDate,
		Dirty:       rel.Builder.Dirty,
	}

	// project summary block
	if s := rel.Summary; s != nil {
		if sv := s.Vulnerabilities; sv != nil {
			resp.Vulnerabilities = &AppSummaryVulns{
				Counts:        sv.Counts,
				Total:         sv.Total,
				WorstSeverity: sv.WorstSeverity,
				GateThreshold: sv.GateThreshold,
				GateResult:    sv.GateResult,
				ScannersUsed:  sv.ScannersUsed,
				ScannedAt:     sv.ScannedAt,
				ByScanner:     sv.ByScanner,
				Scope:         sv.Scope,
				Deduplication: sv.Deduplication,
			}
		}

		if sb := s.SBOM; sb != nil {
			resp.SBOM = &AppSummarySBOM{
				Generators:           sb.Generators,
				FormatsProduced:      sb.FormatsProduced,
				SourcePackageCount:   sb.SourcePackageCount,
				ArtifactPackageCount: sb.ArtifactPackageCount,
				GeneratedAt:          sb.GeneratedAt,
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
				KeyRef:            sg.KeyRef,
				ArtifactsAttested: sg.ArtifactsAttested,
				IndexAttested:     sg.IndexAttested,
				InventorySigned:   sg.InventorySigned,
				ReleaseSigned:     sg.ReleaseSigned,
			}
		}

		// sigstore bundle proves release.json is signed - build-system cant sign and then include the fact its signed in the same release.json
		if resp.Signing != nil && bundle.HasReleaseSigstoreBundle() {
			resp.Signing.ReleaseSigned = true
		}

		if sl := s.SLSA; sl != nil {
			resp.SLSA = &AppSummarySLSA{
				ProvenanceGenerated: sl.ProvenanceGenerated,
				Level:               sl.Level,
				BuilderID:           sl.BuilderID,
				BuildType:           sl.BuildType,
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

	// parse policy from raw json in the release manifest
	pol, err := evidence.ParsePolicy(rel.Policy)
	if err != nil {
		api.logger.Warn(ctx, "parse policy", "error", err)
	}
	if pol != nil {
		resp.Policy = &AppSummaryPolicy{
			Enforcement: pol.Enforcement,
			Signing: AppSummaryPolicySigning{
				RequireInventorySignature: pol.Signing.RequireInventorySignature,
				RequireSubjectSignatures:  pol.Signing.RequireSubjectSignatures,
			},
			Evidence: AppSummaryPolicyEvidence{
				SBOMRequired:         pol.Evidence.SBOMRequired,
				ScanRequired:         pol.Evidence.ScanRequired,
				LicenseRequired:      pol.Evidence.LicenseRequired,
				ProvenanceRequired:   pol.Evidence.ProvenanceRequired,
				AttestationsRequired: pol.Evidence.AttestationsRequired,
			},
			Vulnerability: AppSummaryPolicyVuln{
				BlockOn:    pol.Vulnerability.BlockOn,
				AllowIfVEX: pol.Vulnerability.AllowIfVEX,
			},
			License: AppSummaryPolicyLicense{
				Denied:       pol.License.Denied,
				Allowed:      pol.License.Allowed,
				AllowUnknown: pol.License.AllowUnknown,
			},
		}

		// build compliance evaluation
		compliance := &AppSummaryPolicyCompliance{
			Enforcement: pol.Enforcement,

			SigningRequired:  pol.Signing.RequireSubjectSignatures,
			SigningSatisfied: resp.Signing != nil && resp.Signing.ReleaseSigned && resp.Signing.ArtifactsAttested,

			SBOMRequired:  pol.Evidence.SBOMRequired,
			SBOMSatisfied: resp.SBOM != nil && resp.SBOM.SourcePackageCount > 0,

			ScanRequired:  pol.Evidence.ScanRequired,
			ScanSatisfied: resp.Vulnerabilities != nil && len(resp.Vulnerabilities.ScannersUsed) > 0,

			LicenseRequired:  pol.Evidence.LicenseRequired,
			LicenseSatisfied: resp.Licenses != nil,

			ProvenanceRequired:  pol.Evidence.ProvenanceRequired,
			ProvenanceSatisfied: resp.HasEvidence,

			VulnGating:       pol.Vulnerability.BlockOn,
			LicenseGating:    pol.Evidence.LicenseRequired,
			LicenseCompliant: resp.Licenses != nil && resp.Licenses.Compliant,
		}

		if resp.Vulnerabilities != nil {
			compliance.VulnGateResult = resp.Vulnerabilities.GateResult
		}

		if bundle.HasReleaseSigstoreBundle() {
			compliance.SigningSatisfied = true
		}

		resp.PolicyCompliance = compliance
	}

	// attestations derived from evidence file index, not release.json
	ac := bundle.Attestations()
	if ac.Total > 0 {
		resp.Attestations = &AppSummaryAttestations{
			Total:                ac.Total,
			SourceAttestations:   ac.Source,
			ArtifactAttestations: ac.Artifact,
			SBOMAttested:         ac.SBOMAttested,
			ScanAttested:         ac.ScanAttested,
			LicenseAttested:      ac.LicenseAttested,
		}
	}

	if bundle.HasReleaseSigstoreBundle() {
		// either fold into attestations or add to signing
		resp.Signing.ReleaseSigstoreBundled = true
	}

	// components: merge per-platform artifacts with oci info
	resp.Components = buildAppSummaryComponents(rel)

	api.logger.Debug(ctx, "served app summary",
		"version", resp.Version,
		"has_evidence", resp.HasEvidence,
	)

	api.writeJSON(ctx, w, http.StatusOK, resp)
}

// buildAppSummarySource projects ReleaseSource into the frontend-friendly shape
// handles the tag-build case where branch/ref may be "unknown"
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

	// for tag builds, branch is often empty/unknown - use base_tag as the meaningful ref
	if src.BaseTag != "" {
		out.Tag = src.BaseTag
	}

	// only include branch if its actually meaningful
	branch := src.ResolvedBranch
	if branch != "" && branch != "unknown" {
		out.Branch = branch
	}

	return out
}

// buildAppSummaryComponents merges the per-platform artifacts with oci info
// oci is shared across all platforms (it's a multi-arch index), so we attach
// it to each component for frontend convenience
func buildAppSummaryComponents(rel *evidence.ReleaseManifest) []AppSummaryComponent {
	if len(rel.Artifacts) == 0 {
		return nil
	}

	// Build shared OCI reference (same index for all platforms)
	var sharedOCI *AppSummaryOCI
	if rel.OCI.Repository != "" {
		sharedOCI = &AppSummaryOCI{
			Repository:   rel.OCI.Repository,
			Tag:          rel.OCI.Tag,
			Digest:       rel.OCI.Digest,
			DigestRef:    rel.OCI.DigestRef,
			MediaType:    rel.OCI.MediaType,
			ArtifactType: rel.OCI.ArtifactType,
			PushedAt:     rel.OCI.PushedAt,
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

	// basic rejection of ambiguous/unsafe paths, return 404 and shared "not found" message to limit discovery about our handler filtering
	if strings.Contains(filePath, "\x00") || strings.Contains(filePath, "\\") || strings.Contains(filePath, "..") {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}
	if pathutil.HasDotSegments(filePath) {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
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
			http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		}
		return
	}

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
	api.logger.Debug(ctx, "served evidence file",
		"path", filePath,
		"size", len(file.Data),
		"category", file.Ref.Category,
		"kind", file.Ref.Kind,
	)
}

func (api *API) writeJSON(ctx context.Context, w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		api.logger.Warn(ctx, "failed to encode JSON response", "error", err)
	}
}

// buildLicenseData finds license report evidence files in the bundle, parses
// them, evaluates each package against the build policy, and returns the
// enriched license section + sorted package list for the full endpoint.
//
// Prefers source-scope reports over artifact-scope since source represents
// the direct dependency tree. Falls back to artifact if no source report exists.
func buildLicenseData(bundle *evidence.Bundle, policy *evidence.ReleasePolicy) (*AppProvenanceLicenses, []evidence.PackageInfo) {
	if bundle == nil {
		return nil, nil
	}

	// Find license report files - prefer source scope
	var reportData []byte
	for _, scope := range []string{"source", "artifact"} {
		refs := bundle.FileRefs(scope, "license")
		for _, ref := range refs {
			if ref.Kind != "report" {
				continue
			}
			f, ok := bundle.File(ref.Path)
			if !ok || f.Data == nil {
				continue
			}
			reportData = f.Data
			break
		}
		if reportData != nil {
			break
		}
	}

	if reportData == nil {
		return nil, nil
	}

	report, err := evidence.ParseLicenseReport(reportData)
	if err != nil || report == nil {
		return nil, nil
	}

	// Evaluate each package against policy
	eval := evidence.NewLicenseEvaluator(policy)
	packages, licenseCounts := evidence.BuildPackageList(report, eval)

	// Build the enriched licenses section
	licenses := &AppProvenanceLicenses{
		LicenseCounts: licenseCounts,
	}

	// Pull base data from release.json summary if available
	if bundle.Release != nil && bundle.Release.Summary != nil {
		if ls := bundle.Release.Summary.Licenses; ls != nil {
			licenses.Compliant = ls.Compliant
			licenses.UniqueLicenses = ls.UniqueLicenses
			licenses.DeniedFound = ls.DeniedFound
			licenses.WithoutLicenseCount = ls.WithoutLicenseCount
		}
	}

	return licenses, packages
}
