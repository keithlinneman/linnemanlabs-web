package content

import "time"

type Source string

const (
	SourceUnknown Source = "unknown"
	SourceSeed    Source = "seed"
	SourceDisk    Source = "disk"
	SourceTUF     Source = "tuf"
)

type Signature struct {
	Role  string `json:"role,omitempty"`
	KeyID string `json:"keyid,omitempty"`
}

type Meta struct {
	Version    string    `json:"version,omitempty"`
	SHA256     string    `json:"sha256,omitempty"`
	BuiltAt    time.Time `json:"built_at,omitempty"`
	VerifiedAt time.Time `json:"verified_at,omitempty"`
	Source     Source    `json:"source,omitempty"`

	Signatures []Signature `json:"signatures,omitempty"`
}
