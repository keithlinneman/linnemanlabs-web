package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// Constants

func TestLoaderConstants(t *testing.T) {
	// verify constants haven't drifted to unexpected values
	if MaxManifestSize != 2*1024*1024 {
		t.Fatalf("MaxManifestSize = %d, want 2MB", MaxManifestSize)
	}
	if MaxEvidenceFileSize != 5*1024*1024 {
		t.Fatalf("MaxEvidenceFileSize = %d, want 5MB", MaxEvidenceFileSize)
	}
	if MaxArtifacts != 150 {
		t.Fatalf("MaxArtifacts = %d, want 150", MaxArtifacts)
	}
	if fetchWorkers != 10 {
		t.Fatalf("fetchWorkers = %d, want 10", fetchWorkers)
	}
}

// NewLoader validation

func TestNewLoader_MissingBucket(t *testing.T) {
	_, err := NewLoader(t.Context(), LoaderOptions{
		ReleaseID: "rel-123",
	})
	if err == nil {
		t.Fatal("expected error for missing Bucket")
	}
}

func TestNewLoader_MissingReleaseID(t *testing.T) {
	_, err := NewLoader(t.Context(), LoaderOptions{
		Bucket: "my-bucket",
	})
	if err == nil {
		t.Fatal("expected error for missing ReleaseID")
	}
}

func TestNewLoader_BothMissing(t *testing.T) {
	_, err := NewLoader(t.Context(), LoaderOptions{})
	if err == nil {
		t.Fatal("expected error when both Bucket and ReleaseID missing")
	}
}

// NewLoader with valid params requires AWS config.
// Integration tests would cover the success path.

// releasePrefix

func TestLoader_releasePrefix_WithPrefix(t *testing.T) {
	l := &Loader{
		opts: LoaderOptions{
			Prefix:    "deploy-artifacts/evidence",
			ReleaseID: "rel-20260215-abc123",
		},
	}
	got := l.releasePrefix()
	want := "deploy-artifacts/evidence/rel-20260215-abc123/"
	if got != want {
		t.Fatalf("releasePrefix() = %q, want %q", got, want)
	}
}

func TestLoader_releasePrefix_WithoutPrefix(t *testing.T) {
	l := &Loader{
		opts: LoaderOptions{
			Prefix:    "",
			ReleaseID: "rel-20260215-abc123",
		},
	}
	got := l.releasePrefix()
	want := "rel-20260215-abc123/"
	if got != want {
		t.Fatalf("releasePrefix() = %q, want %q", got, want)
	}
}

func TestLoader_releasePrefix_TrailingSlashStripped(t *testing.T) {
	l := &Loader{
		opts: LoaderOptions{
			Prefix:    "evidence/",
			ReleaseID: "rel-1",
		},
	}
	got := l.releasePrefix()
	// should not produce "evidence//rel-1/"
	want := "evidence/rel-1/"
	if got != want {
		t.Fatalf("releasePrefix() = %q, want %q", got, want)
	}
}

func TestLoader_releasePrefix_NestedPrefix(t *testing.T) {
	l := &Loader{
		opts: LoaderOptions{
			Prefix:    "apps/web/evidence",
			ReleaseID: "rel-42",
		},
	}
	got := l.releasePrefix()
	want := "apps/web/evidence/rel-42/"
	if got != want {
		t.Fatalf("releasePrefix() = %q, want %q", got, want)
	}
}

// sha256hex

func TestSha256hex_KnownVector(t *testing.T) {
	input := []byte("hello world")
	got := sha256hex(input)

	h := sha256.Sum256(input)
	want := hex.EncodeToString(h[:])

	if got != want {
		t.Fatalf("sha256hex(\"hello world\") = %q, want %q", got, want)
	}

	// verify the actual hex value
	if got != "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9" {
		t.Fatalf("unexpected hash: %s", got)
	}
}

func TestSha256hex_Empty(t *testing.T) {
	got := sha256hex([]byte{})
	// SHA256 of empty input is well-known
	if got != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Fatalf("sha256hex(empty) = %q", got)
	}
}

func TestSha256hex_Deterministic(t *testing.T) {
	input := []byte("determinism check")
	a := sha256hex(input)
	b := sha256hex(input)
	if a != b {
		t.Fatalf("same input produced different hashes: %q vs %q", a, b)
	}
}

func TestSha256hex_DifferentInputs(t *testing.T) {
	a := sha256hex([]byte("input A"))
	b := sha256hex([]byte("input B"))
	if a == b {
		t.Fatal("different inputs produced the same hash")
	}
}

// LoadSummary (lives in loader.go, tested alongside)

func TestLoadSummary_NilBundle(t *testing.T) {
	var b *Bundle
	got := b.LoadSummary()
	if got != "no evidence loaded" {
		t.Fatalf("LoadSummary() = %q, want 'no evidence loaded'", got)
	}
}

func TestLoadSummary_PopulatedBundle(t *testing.T) {
	b := testBundle()
	got := b.LoadSummary()

	// should contain release ID, version, and file counts
	wantParts := []string{
		"rel-20260215-abc123",
		"1.2.3",
	}
	for _, part := range wantParts {
		if !strings.Contains(got, part) {
			t.Fatalf("LoadSummary() = %q, missing %q", got, part)
		}
	}
}

func TestLoadSummary_FileCountFormat(t *testing.T) {
	b := &Bundle{
		Release: &ReleaseManifest{
			ReleaseID: "rel-1",
			Version:   "0.1.0",
		},
		FileIndex: map[string]*EvidenceFileRef{
			"a": {}, "b": {}, "c": {},
		},
		Files: map[string]*EvidenceFile{
			"a": {}, "b": {},
		},
	}
	got := b.LoadSummary()
	// should show files=2/3 (fetched/indexed)
	if !strings.Contains(got, "files=2/3") {
		t.Fatalf("LoadSummary() = %q, expected 'files=2/3'", got)
	}
}
