package content

import (
	"context"
	"testing"
)

// NewLoader validation

func TestNewLoader_MissingSSMParam(t *testing.T) {
	_, err := NewLoader(context.Background(), LoaderOptions{
		S3Bucket: "test-bucket",
	})
	if err == nil {
		t.Fatal("expected error for missing SSMParam")
	}
}

func TestNewLoader_MissingS3Bucket(t *testing.T) {
	_, err := NewLoader(context.Background(), LoaderOptions{
		SSMParam: "/app/content/hash",
	})
	if err == nil {
		t.Fatal("expected error for missing S3Bucket")
	}
}

func TestNewLoader_BothMissing(t *testing.T) {
	_, err := NewLoader(context.Background(), LoaderOptions{})
	if err == nil {
		t.Fatal("expected error when both SSMParam and S3Bucket missing")
	}
}

// NewLoader with valid params requires AWS credentials/config,
// so we can't easily test the success path in unit tests without mocking.
// Integration tests or a mock AWS config would be needed for that.

// s3Key

func TestLoader_s3Key_WithPrefix(t *testing.T) {
	l := &Loader{
		opts: LoaderOptions{
			S3Prefix: "content/bundles",
		},
	}
	got := l.s3Key("abc123def456")
	want := "content/bundles/abc123def456.tar.gz"
	if got != want {
		t.Fatalf("s3Key = %q, want %q", got, want)
	}
}

func TestLoader_s3Key_WithoutPrefix(t *testing.T) {
	l := &Loader{
		opts: LoaderOptions{
			S3Prefix: "",
		},
	}
	got := l.s3Key("abc123def456")
	want := "abc123def456.tar.gz"
	if got != want {
		t.Fatalf("s3Key = %q, want %q", got, want)
	}
}

func TestLoader_s3Key_ShortHash(t *testing.T) {
	l := &Loader{
		opts: LoaderOptions{S3Prefix: "prefix"},
	}
	got := l.s3Key("a")
	want := "prefix/a.tar.gz"
	if got != want {
		t.Fatalf("s3Key = %q, want %q", got, want)
	}
}

// provenanceVersion

func TestProvenanceVersion_Nil(t *testing.T) {
	got := provenanceVersion(nil)
	if got != "" {
		t.Fatalf("provenanceVersion(nil) = %q, want empty", got)
	}
}

func TestProvenanceVersion_Empty(t *testing.T) {
	got := provenanceVersion(&Provenance{Version: ""})
	if got != "" {
		t.Fatalf("provenanceVersion(empty) = %q, want empty", got)
	}
}

func TestProvenanceVersion_Present(t *testing.T) {
	got := provenanceVersion(&Provenance{Version: "2.1.0"})
	if got != "2.1.0" {
		t.Fatalf("provenanceVersion = %q, want 2.1.0", got)
	}
}
