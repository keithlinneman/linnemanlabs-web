package content

import (
	"time"

	"github.com/keithlinneman/linnemanlabs-web/internal/cryptoutil"
)

type Source string

const (
	SourceUnknown Source = "unknown"
	SourceSeed    Source = "seed"
	SourceDisk    Source = "disk"
	SourceTUF     Source = "tuf"
	SourceS3      Source = "s3"
)

type Meta struct {
	Version       string    `json:"version,omitempty"`
	Hash          string    `json:"hash,omitempty"`
	HashAlgorithm string    `json:"hash_algorithm,omitempty"`
	BuiltAt       time.Time `json:"built_at,omitempty"`
	VerifiedAt    time.Time `json:"verified_at,omitempty"`
	Source        Source    `json:"source,omitempty"`

	// Signatures aggregates the keyless (Fulcio) + KMS signature evidence
	// extracted from the two sigstore bundles at load time. Either half may
	// be nil when its bundle was not loaded; both populated for verified
	// dual-signed releases.
	Signatures *cryptoutil.SignaturesInfo `json:"signatures,omitempty"`
}
