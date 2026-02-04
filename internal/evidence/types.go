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

	// Policy is stored as raw JSON
	Policy json.RawMessage `json:"policy,omitempty"`
}

// ReleaseSource is the git source info from release.json
type ReleaseSource struct {
	Repo           string    `json:"repo"`
	ResolvedBranch string    `json:"resolved_branch"`
	Ref            string    `json:"ref"`
	Detached       bool      `json:"detached"`
	Commit         string    `json:"commit"`
	CommitShort    string    `json:"commit_short"`
	CommitDate     time.Time `json:"commit_date"`
	Dirty          bool      `json:"dirty"`
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
