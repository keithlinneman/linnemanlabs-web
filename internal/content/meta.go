package content

import "time"

type Source string

const (
	SourceUnknown Source = "unknown"
	SourceSeed    Source = "seed"
	SourceDisk    Source = "disk"
	SourceTUF     Source = "tuf"
	SourceS3      Source = "s3"
)

type Signature struct {
	Role  string `json:"role,omitempty"`
	KeyID string `json:"keyid,omitempty"`
}

type Meta struct {
	Version       string    `json:"version,omitempty"`
	Hash          string    `json:"hash,omitempty"`
	HashAlgorithm string    `json:"hash_algorithm,omitempty"`
	BuiltAt       time.Time `json:"built_at,omitempty"`
	VerifiedAt    time.Time `json:"verified_at,omitempty"`
	Source        Source    `json:"source,omitempty"`

	Signatures []Signature `json:"signatures,omitempty"`
}
