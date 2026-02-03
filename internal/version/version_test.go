package version_test

import (
	"testing"

	v "github.com/keithlinneman/linnemanlabs-web/internal/version"
)

func TestVCSDirtyTriState(t *testing.T) {
	v.VCSDirty = nil
	info := v.Get()
	if info.VCSDirty != nil {
		t.Fatalf("VCSDirty = %v, want nil", info.VCSDirty)
	}

	trueVal := true
	v.VCSDirty = &trueVal
	info = v.Get()
	if info.VCSDirty == nil || *info.VCSDirty != true {
		t.Fatalf("VCSDirty = %v, want true", info.VCSDirty)
	}

	falseVal := false
	v.VCSDirty = &falseVal
	info = v.Get()
	if info.VCSDirty == nil || *info.VCSDirty != false {
		t.Fatalf("VCSDirty = %v, want false", info.VCSDirty)
	}
}

func TestLocalBuildDefaults(t *testing.T) {
	// Reset to defaults (simulating local build)
	v.Version = "dev"
	v.Commit = "none"
	v.Repository = ""
	v.BuildSystem = ""
	v.BuilderIdentity = ""
	v.ReleaseId = ""
	v.EvidenceBucket = ""

	info := v.Get()

	if info.Version != "dev" {
		t.Fatalf("Version = %q, want dev", info.Version)
	}
	if info.BuildSystem != "local" {
		t.Fatalf("BuildSystem = %q, want local (inferred)", info.BuildSystem)
	}
	if info.HasProvenance() {
		t.Fatal("HasProvenance() = true for local build, want false")
	}
}

func TestCIBuildProvenance(t *testing.T) {
	// Simulate CI-injected values
	v.Version = "1.2.3"
	v.Commit = "abc123"
	v.BuildSystem = "github-actions"
	v.BuilderIdentity = "arn:aws:iam::123456789012:role/app-linnemanlabs-web-build"
	v.Repository = "https://github.com/keithlinneman/linnemanlabs-web"
	v.ReleaseId = "rel-20260202-abc123"
	v.EvidenceBucket = "phxi-build-prod-use2-deployment-artifacts"
	v.EvidencePrefix = "apps/linnemanlabs-web/server/attestations"
	v.BuildRunID = "12345"
	v.BuildRunURL = "https://github.com/keithlinneman/linnemanlabs-web/actions/runs/12345"
	v.CosignKeyRef = "arn:aws:ssm:us-east-2:123456789012:parameter/app/linnemanlabs-web/signing/cosign/signer"

	info := v.Get()

	if info.BuildSystem != "github-actions" {
		t.Fatalf("BuildSystem = %q, want github-actions", info.BuildSystem)
	}
	if !info.HasProvenance() {
		t.Fatal("HasProvenance() = false for CI build, want true")
	}
	if info.Repository != "https://github.com/keithlinneman/linnemanlabs-web" {
		t.Fatalf("Repository = %q", info.Repository)
	}
	if info.CosignKeyRef == "" {
		t.Fatal("CosignKeyRef empty for CI build")
	}
}

func TestHasProvenance_PartialFields(t *testing.T) {
	// ReleaseId set but no bucket — not enough
	v.ReleaseId = "rel-123"
	v.EvidenceBucket = ""
	info := v.Get()
	if info.HasProvenance() {
		t.Fatal("HasProvenance() = true with no bucket, want false")
	}

	// Bucket set but no release ID — not enough
	v.ReleaseId = ""
	v.EvidenceBucket = "some-bucket"
	info = v.Get()
	if info.HasProvenance() {
		t.Fatal("HasProvenance() = true with no release ID, want false")
	}

	// Both set — should be true
	v.ReleaseId = "rel-123"
	v.EvidenceBucket = "some-bucket"
	info = v.Get()
	if !info.HasProvenance() {
		t.Fatal("HasProvenance() = false with both fields set, want true")
	}
}
