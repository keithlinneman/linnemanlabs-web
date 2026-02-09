package evidence

import (
	"encoding/json"
	"time"
)

type ReleaseManifest struct {
	Schema    string    `json:"schema"`
	App       string    `json:"app"`
	Version   string    `json:"version"`
	BuildID   string    `json:"build_id"`
	ReleaseID string    `json:"release_id"`
	Track     string    `json:"track"`
	CreatedAt time.Time `json:"created_at"`
	Epoch     int64     `json:"epoch"`
	Component string    `json:"component"`

	Source  ReleaseSource  `json:"source"`
	Builder ReleaseBuilder `json:"builder"`

	Files        map[string]FileRef `json:"files"`
	Distribution Distribution       `json:"distribution"`
	OCI          ReleaseOCI         `json:"oci"`
	Artifacts    []ReleaseArtifact  `json:"artifacts"`

	// Parsed summary block from build system
	Summary *ReleaseSummary `json:"summary,omitempty"`

	// Policy is stored as raw JSON (nested structure with overrides)
	Policy json.RawMessage `json:"policy,omitempty"`
}

// ReleaseSource is the git source info from release.json
type ReleaseSource struct {
	Repo            string    `json:"repo"`
	ResolvedBranch  string    `json:"resolved_branch"`
	Ref             string    `json:"ref"`
	Detached        bool      `json:"detached"`
	Commit          string    `json:"commit"`
	CommitShort     string    `json:"commit_short"`
	CommitDate      time.Time `json:"commit_date"`
	BaseTag         string    `json:"base_tag,omitempty"`
	CommitsSinceTag *int      `json:"commits_since_tag,omitempty"`
	Dirty           bool      `json:"dirty"`
}

// ReleaseBuilder is the build system source info
type ReleaseBuilder struct {
	Repo        string    `json:"repo"`
	Branch      string    `json:"branch"`
	Commit      string    `json:"commit"`
	CommitShort string    `json:"commit_short"`
	CommitDate  time.Time `json:"commit_date"`
	Dirty       bool      `json:"dirty"`
}

// FileRef references a file within the release with integrity info
type FileRef struct {
	Path   string            `json:"path"`
	Hashes map[string]string `json:"hashes"`
	Size   int64             `json:"size"`
}

// Distribution describes where release artifacts are stored
type Distribution struct {
	Provider string            `json:"provider"`
	Bucket   string            `json:"bucket"`
	Region   string            `json:"region"`
	URI      string            `json:"uri"`
	Prefix   string            `json:"prefix"`
	Objects  map[string]string `json:"objects"`
}

// ReleaseOCI describes the OCI index for the release
type ReleaseOCI struct {
	Repository   string `json:"repository"`
	Tag          string `json:"tag"`
	TagRef       string `json:"tag_ref"`
	Digest       string `json:"digest"`
	DigestRef    string `json:"digest_ref"`
	MediaType    string `json:"mediaType"`
	ArtifactType string `json:"artifactType"`
	Size         int64  `json:"size"`
	PushedAt     string `json:"pushed_at"`
}

// ReleaseArtifact is a per-platform binary from release.json
type ReleaseArtifact struct {
	OS     string    `json:"os"`
	Arch   string    `json:"arch"`
	Binary BinaryRef `json:"binary"`
}

// BinaryRef references a binary with integrity info
type BinaryRef struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// ReleaseSummary is the top-level summary block from release.json
type ReleaseSummary struct {
	Schema      string `json:"schema"`
	GeneratedAt string `json:"generated_at"`

	Vulnerabilities  *VulnSummary          `json:"vulnerabilities,omitempty"`
	SBOM             *SBOMSummary          `json:"sbom,omitempty"`
	Licenses         *LicenseSummary       `json:"licenses,omitempty"`
	Signing          *SigningSummary       `json:"signing,omitempty"`
	SLSA             *SLSASummary          `json:"slsa,omitempty"`
	EvidenceComplete *EvidenceCompleteness `json:"evidence_completeness,omitempty"`
}

// VulnSummary is the deduplicated vulnerability overview
type VulnSummary struct {
	ScannersUsed  []string                   `json:"scanners_used"`
	ScannedAt     string                     `json:"scanned_at"`
	Findings      []VulnFinding              `json:"findings,omitempty"`
	Scope         string                     `json:"scope"`
	Deduplication string                     `json:"deduplication"`
	Counts        VulnCounts                 `json:"counts"`
	Total         int                        `json:"total"`
	ByScanner     map[string]json.RawMessage `json:"by_scanner,omitempty"`
	WorstSeverity string                     `json:"worst_severity"`
	GateThreshold string                     `json:"gate_threshold"`
	GateResult    string                     `json:"gate_result"`
}

// VulnCounts is the deduplicated severity breakdown
type VulnCounts struct {
	Critical   int `json:"critical"`
	High       int `json:"high"`
	Medium     int `json:"medium"`
	Low        int `json:"low"`
	Negligible int `json:"negligible"`
	Unknown    int `json:"unknown"`
}

// SBOMSummary is the SBOM generation overview
type SBOMSummary struct {
	Generators           []string `json:"generators"`
	FormatsProduced      []string `json:"formats_produced"`
	SourcePackageCount   int      `json:"source_package_count"`
	ArtifactPackageCount int      `json:"artifact_package_count"`
	GeneratedAt          string   `json:"generated_at"`
}

// LicenseSummary is the license compliance overview
type LicenseSummary struct {
	Compliant           bool     `json:"compliant"`
	UniqueLicenses      []string `json:"unique_licenses"`
	DeniedFound         []string `json:"denied_found"`
	WithoutLicenseCount int      `json:"without_license_count"`
}

// SigningSummary is the signing status overview
type SigningSummary struct {
	Method            string `json:"method"`
	KeyRef            string `json:"key_ref"`
	ArtifactsAttested bool   `json:"artifacts_attested"`
	IndexAttested     bool   `json:"index_attested"`
	InventorySigned   bool   `json:"inventory_signed"`
	ReleaseSigned     bool   `json:"release_signed"`
}

// SLSASummary is the SLSA provenance status (future use)
type SLSASummary struct {
	ProvenanceGenerated bool   `json:"provenance_generated"`
	Level               int    `json:"level,omitempty"`
	BuilderID           string `json:"builder_id,omitempty"`
	BuildType           string `json:"build_type,omitempty"`
	Note                string `json:"note,omitempty"`
}

// EvidenceCompleteness indicates which evidence categories were produced
type EvidenceCompleteness struct {
	SBOMSource           bool `json:"sbom_source"`
	SBOMArtifacts        bool `json:"sbom_artifacts"`
	ScanSource           bool `json:"scan_source"`
	ScanArtifacts        bool `json:"scan_artifacts"`
	LicenseSource        bool `json:"license_source"`
	LicenseArtifacts     bool `json:"license_artifacts"`
	AttestationsAttached bool `json:"attestations_attached"`
}

// full json is kept in ReleaseManifest.Policy for passthrough on the
// full endpoint and this parsed form is used for the summary endpoint
type ReleasePolicy struct {
	Enforcement   string              `json:"enforcement"` // "warn" or "block"
	Signing       PolicySigning       `json:"signing"`
	Evidence      PolicyEvidence      `json:"evidence"`
	Vulnerability PolicyVulnerability `json:"vulnerability"`
	License       PolicyLicense       `json:"license"`
}

// PolicySigning describes what must be cryptographically signed
type PolicySigning struct {
	RequireInventorySignature bool `json:"require_inventory_signature"`
	RequireSubjectSignatures  bool `json:"require_subject_signatures"`
}

// PolicyEvidence describes what evidence artifacts the policy mandates
type PolicyEvidence struct {
	SBOMRequired         bool `json:"sbom_required"`
	ScanRequired         bool `json:"scan_required"`
	LicenseRequired      bool `json:"license_required"`
	ProvenanceRequired   bool `json:"provenance_required"`
	AttestationsRequired bool `json:"attestations_required"`
}

// PolicyVulnerability describes vulnerability gating rules.
type PolicyVulnerability struct {
	BlockOn    []string `json:"block_on"` // ["critical", "high"]
	AllowIfVEX bool     `json:"allow_if_vex"`
}

// PolicyLicense describes license compliance rules
type PolicyLicense struct {
	Denied       []string `json:"denied"`
	Allowed      []string `json:"allowed"`
	AllowUnknown bool     `json:"allow_unknown"`
}

// policyRaw is the top-level policy block in release.json
type policyRaw struct {
	Defaults  policyDefaults  `json:"defaults"`
	Overrides json.RawMessage `json:"overrides,omitempty"`
}

type policyDefaults struct {
	Enforcement   string            `json:"enforcement"`
	Signing       PolicySigning     `json:"signing"`
	Evidence      policyEvidenceRaw `json:"evidence"`
	Vulnerability policyVulnRaw     `json:"vulnerability"`
	License       policyLicenseRaw  `json:"license"`
}

// evidence.sbom.required, evidence.scan.required, etc
type policyEvidenceRaw struct {
	SBOM       policyEvidenceEntry `json:"sbom"`
	Scan       policyEvidenceEntry `json:"scan"`
	License    policyEvidenceEntry `json:"license"`
	Provenance policyEvidenceEntry `json:"provenance"`
}

type policyEvidenceEntry struct {
	Required            bool `json:"required"`
	AttestationRequired bool `json:"attestation_required"`
}

// vulnerability.gating.default.block_on, etc
type policyVulnRaw struct {
	Gating struct {
		Default struct {
			BlockOn    []string `json:"block_on"`
			AllowIfVEX bool     `json:"allow_if_vex"`
		} `json:"default"`
	} `json:"gating"`
}

// license.deny.spdx_ids, license.allow.spdx_ids, etc
type policyLicenseRaw struct {
	Deny         []string `json:"deny"`
	DenyRegex    []string `json:"deny_regex,omitempty"`
	Allow        []string `json:"allow"`
	AllowUnknown bool     `json:"allow_unknown"`
}

type VulnFinding struct {
	ID               string   `json:"id"`
	Severity         string   `json:"severity"`
	Package          string   `json:"package"`
	InstalledVersion string   `json:"installed_version"`
	FixedVersion     string   `json:"fixed_version,omitempty"`
	Title            string   `json:"title,omitempty"`
	SourceURL        string   `json:"source_url,omitempty"`
	Scanners         []string `json:"scanners"`
}

// EvidenceFileRef is a flattened reference to any evidence file in the inventory
type EvidenceFileRef struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`

	// Classification for UI grouping and filtering
	Scope    string `json:"scope"`              // "source" or "artifact"
	Category string `json:"category"`           // "sbom", "scan", "license"
	Kind     string `json:"kind"`               // "report" or "attestation"
	Platform string `json:"platform,omitempty"` // "linux/arm64" or "linux/amd64"
}

// EvidenceFile is an evidence file that has been fetched and hash-verified
type EvidenceFile struct {
	Ref  *EvidenceFileRef
	Data []byte
}

// Bundle holds all evidence for a release eager loaded at startup
type Bundle struct {
	// parsed release.json
	Release *ReleaseManifest

	// sigstore bundle for release.json
	ReleaseSigstoreBundle []byte

	// raw bytes for serving as-is
	ReleaseRaw   []byte
	InventoryRaw []byte

	// verified hash of fetched inventory.json
	InventoryHash string

	// flat index: inventory path -> file reference
	FileIndex map[string]*EvidenceFileRef

	// fetched evidence files: inventory path -> verified bytes
	Files map[string]*EvidenceFile

	// where this bundle was loaded from
	Bucket        string
	ReleasePrefix string

	// when the bundle was loaded
	FetchedAt time.Time
}

// File looks up a fetched evidence file by its inventory path
func (b *Bundle) File(path string) (*EvidenceFile, bool) {
	if b == nil || b.Files == nil {
		return nil, false
	}
	f, ok := b.Files[path]
	return f, ok
}

// FileRef looks up a file reference by path (metadata only, no content)
func (b *Bundle) FileRef(path string) (*EvidenceFileRef, bool) {
	if b == nil || b.FileIndex == nil {
		return nil, false
	}
	ref, ok := b.FileIndex[path]
	return ref, ok
}

// FileRefs returns file references filtered by scope and/or category
// empty string means "any"
func (b *Bundle) FileRefs(scope, category string) []*EvidenceFileRef {
	if b == nil {
		return nil
	}
	out := make([]*EvidenceFileRef, 0, 16)
	for _, ref := range b.FileIndex {
		if scope != "" && ref.Scope != scope {
			continue
		}
		if category != "" && ref.Category != category {
			continue
		}
		out = append(out, ref)
	}
	return out
}

// Summary returns file counts keyed by "scope.category.kind"
func (b *Bundle) Summary() map[string]int {
	if b == nil || b.FileIndex == nil {
		return nil
	}
	counts := make(map[string]int, 8)
	for _, ref := range b.FileIndex {
		key := ref.Scope + "." + ref.Category + "." + ref.Kind
		counts[key]++
	}
	return counts
}

// AttestationCounts returns attestation statistics derived from the file index
type AttestationCounts struct {
	Total    int
	Source   int
	Artifact int

	SBOMAttested    bool
	ScanAttested    bool
	LicenseAttested bool
}

// Attestations counts attestation files in the index by scope and category
func (b *Bundle) Attestations() AttestationCounts {
	var c AttestationCounts
	if b == nil || b.FileIndex == nil {
		return c
	}
	for _, ref := range b.FileIndex {
		if ref.Kind != "attestation" {
			continue
		}
		c.Total++
		switch ref.Scope {
		case "source":
			c.Source++
		case "artifact":
			c.Artifact++
		}
		switch ref.Category {
		case "sbom":
			c.SBOMAttested = true
		case "scan":
			c.ScanAttested = true
		case "license":
			c.LicenseAttested = true
		}
	}
	return c
}

// ParsePolicy extracts a summary-friendly ReleasePolicy from the raw policy
func ParsePolicy(raw json.RawMessage) *ReleasePolicy {
	if len(raw) == 0 {
		return nil
	}

	var pr policyRaw
	if err := json.Unmarshal(raw, &pr); err != nil {
		return nil
	}

	d := pr.Defaults
	if d.Enforcement == "" {
		return nil
	}

	// any attestation_required flag set means attestations required overall
	attestationsRequired := d.Evidence.SBOM.AttestationRequired ||
		d.Evidence.Scan.AttestationRequired ||
		d.Evidence.License.AttestationRequired ||
		d.Evidence.Provenance.AttestationRequired

	return &ReleasePolicy{
		Enforcement: d.Enforcement,
		Signing:     d.Signing,
		Evidence: PolicyEvidence{
			SBOMRequired:         d.Evidence.SBOM.Required,
			ScanRequired:         d.Evidence.Scan.Required,
			LicenseRequired:      d.Evidence.License.Required,
			ProvenanceRequired:   d.Evidence.Provenance.Required,
			AttestationsRequired: attestationsRequired,
		},
		Vulnerability: PolicyVulnerability{
			BlockOn:    d.Vulnerability.Gating.Default.BlockOn,
			AllowIfVEX: d.Vulnerability.Gating.Default.AllowIfVEX,
		},
		License: PolicyLicense{
			Denied:       d.License.Deny,
			Allowed:      d.License.Allow,
			AllowUnknown: d.License.AllowUnknown,
		},
	}
}

// HasReleaseSigstoreBundle returns true if a sigstore bundle exists for release.json
func (b *Bundle) HasReleaseSigstoreBundle() bool {
	return b != nil && len(b.ReleaseSigstoreBundle) > 0
}
