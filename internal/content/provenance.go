package content

import (
	"encoding/json"
	"io/fs"
	"time"

	"github.com/keithlinneman/linnemanlabs-web/internal/xerrors"
)

// Provenance contains all the info from provenance.json manifest
type Provenance struct {
	Schema      string            `json:"schema"`
	Type        string            `json:"type"`
	Version     string            `json:"version"`
	ContentID   string            `json:"content_id"`
	ContentHash string            `json:"content_hash"`
	CreatedAt   time.Time         `json:"created_at"`
	Source      ProvenanceSource  `json:"source"`
	Build       ProvenanceBuild   `json:"build"`
	Summary     ProvenanceSummary `json:"summary"`
	Files       []ProvenanceFile  `json:"files"`
	Tooling     ProvenanceTooling `json:"tooling"`
}

// ProvenanceSource contains git repository information
type ProvenanceSource struct {
	Repository  string    `json:"repository"`
	Commit      string    `json:"commit"`
	CommitShort string    `json:"commit_short"`
	CommitDate  time.Time `json:"commit_date"`
	Branch      string    `json:"branch"`
	Dirty       bool      `json:"dirty"`
}

// ProvenanceBuild contains build environment information
type ProvenanceBuild struct {
	Host      string    `json:"host"`
	User      string    `json:"user"`
	Timestamp time.Time `json:"timestamp"`
}

// ProvenanceSummary contains aggregate statistics
type ProvenanceSummary struct {
	TotalFiles int            `json:"total_files"`
	TotalSize  int64          `json:"total_size"`
	FileTypes  map[string]int `json:"file_types"`
}

// ProvenanceFile represents a single file in the manifest
type ProvenanceFile struct {
	Path     string    `json:"path"`
	SHA256   string    `json:"sha256"`
	Size     int64     `json:"size"`
	Type     string    `json:"type"`
	Modified time.Time `json:"modified"`
}

// ProvenanceTooling contains tool version information
type ProvenanceTooling struct {
	Hugo        *ToolInfo `json:"hugo,omitempty"`
	TailwindCSS *ToolInfo `json:"tailwindcss,omitempty"`
	Tidy        *ToolInfo `json:"tidy,omitempty"`
	Git         *ToolInfo `json:"git,omitempty"`
	Bash        *ToolInfo `json:"bash,omitempty"`
}

// ToolInfo represents version and optional hash of a build tool
type ToolInfo struct {
	Version string `json:"version"`
	SHA256  string `json:"sha256,omitempty"`
}

// ProvenanceFilePath is the expected location of provenance.json in the bundle
const ProvenanceFilePath = "provenance.json"

// LoadProvenance reads and parses provenance.json from the given filesystem
func LoadProvenance(fsys fs.FS) (*Provenance, error) {
	data, err := fs.ReadFile(fsys, ProvenanceFilePath)
	if err != nil {
		return nil, xerrors.Wrapf(err, "read %s", ProvenanceFilePath)
	}

	var p Provenance
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, xerrors.Wrapf(err, "parse %s", ProvenanceFilePath)
	}

	return &p, nil
}

// ProvenanceResponse is the enriched response served at /api/provenance/content
// It includes runtime information in addition to the bundle provenance
type ProvenanceResponse struct {
	// Bundle provenance (from provenance.json)
	Bundle *Provenance `json:"bundle"`

	// Runtime information added by the server
	Runtime RuntimeInfo `json:"runtime"`
}

// RuntimeInfo contains server-side runtime information
type RuntimeInfo struct {
	LoadedAt   time.Time `json:"loaded_at"`
	ServerTime time.Time `json:"server_time"`
	Source     Source    `json:"source"`
}
