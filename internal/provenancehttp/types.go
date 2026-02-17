package provenancehttp

import (
	"encoding/json"
	"time"

	"github.com/keithlinneman/linnemanlabs-web/internal/content"
	"github.com/keithlinneman/linnemanlabs-web/internal/evidence"
	"github.com/keithlinneman/linnemanlabs-web/internal/log"
	v "github.com/keithlinneman/linnemanlabs-web/internal/version"
)

type AppSummaryPolicyCompliance struct {
	Enforcement string `json:"enforcement"`

	SigningRequired  bool `json:"signing_required"`
	SigningSatisfied bool `json:"signing_satisfied"`

	SBOMRequired  bool `json:"sbom_required"`
	SBOMSatisfied bool `json:"sbom_satisfied"`

	ScanRequired  bool `json:"scan_required"`
	ScanSatisfied bool `json:"scan_satisfied"`

	LicenseRequired  bool `json:"license_required"`
	LicenseSatisfied bool `json:"license_satisfied"`

	ProvenanceRequired  bool `json:"provenance_required"`
	ProvenanceSatisfied bool `json:"provenance_satisfied"`

	VulnGating     []string `json:"vuln_gating,omitempty"`
	VulnGateResult string   `json:"vuln_gate_result,omitempty"`

	LicenseGating    bool `json:"license_gating"`
	LicenseCompliant bool `json:"license_compliant"`
}

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
