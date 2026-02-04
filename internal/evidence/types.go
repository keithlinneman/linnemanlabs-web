package evidence

import "time"

// Artifact represents a single attestation or evidence file
type Artifact struct {
	// Name is the filename relative to the release prefix (e.g. "sbom.spdx.json")
	Name string `json:"name"`

	// S3Key is the full S3 object key this was fetched from
	S3Key string `json:"s3_key,omitempty"`

	// RawJSON holds the raw file content; omitted from JSON manifest responses
	RawJSON []byte `json:"-"`

	// Size in bytes
	Size int64 `json:"size"`

	// ContentType from S3 object metadata, if available
	ContentType string `json:"content_type,omitempty"`

	// FetchedAt is when this artifact was downloaded
	FetchedAt time.Time `json:"fetched_at"`
}

// Bundle holds all evidence artifacts for a specific release
type Bundle struct {
	// ReleaseID this evidence belongs to
	ReleaseID string `json:"release_id"`

	// Bucket the evidence was fetched from
	Bucket string `json:"bucket"`

	// Prefix within the bucket (includes release ID)
	Prefix string `json:"prefix"`

	// Artifacts is the list of fetched evidence files
	Artifacts []Artifact `json:"artifacts"`

	// FetchedAt is when the bundle was loaded
	FetchedAt time.Time `json:"fetched_at"`

	// index for lookup by name
	byName map[string]*Artifact
}

// Artifact returns a specific artifact by name, or nil if not found
func (b *Bundle) Artifact(name string) *Artifact {
	if b == nil || b.byName == nil {
		return nil
	}
	return b.byName[name]
}

// Names returns all artifact names in the bundle
func (b *Bundle) Names() []string {
	if b == nil {
		return nil
	}
	names := make([]string, len(b.Artifacts))
	for i, a := range b.Artifacts {
		names[i] = a.Name
	}
	return names
}

// buildIndex populates the byName lookup map
func (b *Bundle) buildIndex() {
	b.byName = make(map[string]*Artifact, len(b.Artifacts))
	for i := range b.Artifacts {
		b.byName[b.Artifacts[i].Name] = &b.Artifacts[i]
	}
}
