package version

import (
	"runtime/debug"
	"testing"
)

// save and restore package-level vars between tests to prevent cross-contamination.
func saveAndReset(t *testing.T) {
	t.Helper()
	saved := struct {
		Version, Commit, CommitDate, BuildDate, BuildId, GoVersion string
		VCSDirty                                                   *bool
		BuildActor, Repository, BuildSystem, BuilderIdentity       string
		BuildRunID, BuildRunURL, ReleaseId                         string
		EvidenceBucket, EvidencePrefix, CosignKeyRef               string
	}{
		Version, Commit, CommitDate, BuildDate, BuildId, GoVersion,
		VCSDirty,
		BuildActor, Repository, BuildSystem, BuilderIdentity,
		BuildRunID, BuildRunURL, ReleaseId,
		EvidenceBucket, EvidencePrefix, CosignKeyRef,
	}
	t.Cleanup(func() {
		Version = saved.Version
		Commit = saved.Commit
		CommitDate = saved.CommitDate
		BuildDate = saved.BuildDate
		BuildId = saved.BuildId
		GoVersion = saved.GoVersion
		VCSDirty = saved.VCSDirty
		BuildActor = saved.BuildActor
		Repository = saved.Repository
		BuildSystem = saved.BuildSystem
		BuilderIdentity = saved.BuilderIdentity
		BuildRunID = saved.BuildRunID
		BuildRunURL = saved.BuildRunURL
		ReleaseId = saved.ReleaseId
		EvidenceBucket = saved.EvidenceBucket
		EvidencePrefix = saved.EvidencePrefix
		CosignKeyRef = saved.CosignKeyRef
	})
}

func setLocalDefaults() {
	Version = "dev"
	Commit = "none"
	CommitDate = ""
	BuildDate = ""
	BuildId = ""
	GoVersion = ""
	VCSDirty = nil
	BuildActor = ""
	Repository = ""
	BuildSystem = ""
	BuilderIdentity = ""
	BuildRunID = ""
	BuildRunURL = ""
	ReleaseId = ""
	EvidenceBucket = ""
	EvidencePrefix = ""
	CosignKeyRef = ""
}

func setCIDefaults() {
	Version = "1.2.3"
	Commit = "abc123def456"
	CommitDate = "2025-02-01T12:00:00Z"
	BuildDate = "2025-02-01T12:05:00Z"
	BuildId = "build-789"
	GoVersion = "go1.23.0"
	VCSDirty = ptrBool(false)
	BuildActor = "keithlinneman"
	Repository = "https://github.com/keithlinneman/linnemanlabs-web"
	BuildSystem = "github-actions"
	BuilderIdentity = "arn:aws:iam::123456789012:role/build"
	BuildRunID = "12345"
	BuildRunURL = "https://github.com/keithlinneman/linnemanlabs-web/actions/runs/12345"
	ReleaseId = "rel-20250201-abc123"
	EvidenceBucket = "phxi-build-prod-use2-deployment-artifacts"
	EvidencePrefix = "apps/linnemanlabs-web/server/attestations"
	CosignKeyRef = "arn:aws:ssm:us-east-2:123456789012:parameter/signing/cosign"
}

func ptrBool(b bool) *bool { return &b }

// AppName

func TestAppName(t *testing.T) {
	if AppName != "linnemanlabs-web" {
		t.Fatalf("AppName = %q", AppName)
	}
}

// Get - local build defaults

func TestGet_LocalBuild_Defaults(t *testing.T) {
	saveAndReset(t)
	setLocalDefaults()

	info := Get()

	if info.Version != "dev" {
		t.Fatalf("Version = %q, want dev", info.Version)
	}
}

func TestGet_LocalBuild_InfersBuildSystem(t *testing.T) {
	saveAndReset(t)
	setLocalDefaults()

	info := Get()

	if info.BuildSystem != "local" {
		t.Fatalf("BuildSystem = %q, want local (inferred)", info.BuildSystem)
	}
}

func TestGet_LocalBuild_NoProvenanceFields(t *testing.T) {
	saveAndReset(t)
	setLocalDefaults()

	info := Get()

	if info.ReleaseId != "" || info.EvidenceBucket != "" || info.EvidencePrefix != "" {
		t.Fatal("local build should have empty provenance fields")
	}
}

func TestGet_LocalBuild_NoBuildActor(t *testing.T) {
	saveAndReset(t)
	setLocalDefaults()

	info := Get()

	if info.BuildActor != "" || info.BuildRunID != "" || info.BuildRunURL != "" {
		t.Fatal("local build should have empty CI fields")
	}
}

// Get - CI build

func TestGet_CIBuild_AllFields(t *testing.T) {
	saveAndReset(t)
	setCIDefaults()

	info := Get()

	if info.Version != "1.2.3" {
		t.Fatalf("Version = %q", info.Version)
	}
	if info.Commit != "abc123def456" {
		t.Fatalf("Commit = %q", info.Commit)
	}
	if info.BuildSystem != "github-actions" {
		t.Fatalf("BuildSystem = %q", info.BuildSystem)
	}
	if info.BuildActor != "keithlinneman" {
		t.Fatalf("BuildActor = %q", info.BuildActor)
	}
	if info.Repository != "https://github.com/keithlinneman/linnemanlabs-web" {
		t.Fatalf("Repository = %q", info.Repository)
	}
	if info.BuildRunID != "12345" {
		t.Fatalf("BuildRunID = %q", info.BuildRunID)
	}
	if info.CosignKeyRef != "arn:aws:ssm:us-east-2:123456789012:parameter/signing/cosign" {
		t.Fatalf("CosignKeyRef = %q", info.CosignKeyRef)
	}
}

func TestGet_CIBuild_DoesNotOverrideBuildSystem(t *testing.T) {
	saveAndReset(t)
	setCIDefaults()

	info := Get()

	if info.BuildSystem != "github-actions" {
		t.Fatalf("BuildSystem = %q, should not be overridden", info.BuildSystem)
	}
}

func TestGet_CIBuild_ProvenanceFields(t *testing.T) {
	saveAndReset(t)
	setCIDefaults()

	info := Get()

	if info.ReleaseId != "rel-20250201-abc123" {
		t.Fatalf("ReleaseId = %q", info.ReleaseId)
	}
	if info.EvidenceBucket != "phxi-build-prod-use2-deployment-artifacts" {
		t.Fatalf("EvidenceBucket = %q", info.EvidenceBucket)
	}
	if info.EvidencePrefix != "apps/linnemanlabs-web/server/attestations" {
		t.Fatalf("EvidencePrefix = %q", info.EvidencePrefix)
	}
}

// Get - BuildSystem inference

func TestGet_BuildSystem_InferLocal_WhenDevVersion(t *testing.T) {
	saveAndReset(t)
	setLocalDefaults()

	info := Get()

	if info.BuildSystem != "local" {
		t.Fatalf("BuildSystem = %q, want local", info.BuildSystem)
	}
}

func TestGet_BuildSystem_NoInfer_WhenVersionSet(t *testing.T) {
	saveAndReset(t)
	setLocalDefaults()
	Version = "1.0.0"

	info := Get()

	if info.BuildSystem != "" {
		t.Fatalf("BuildSystem = %q, want empty (version is not dev)", info.BuildSystem)
	}
}

func TestGet_BuildSystem_NoInfer_WhenAlreadySet(t *testing.T) {
	saveAndReset(t)
	setLocalDefaults()
	BuildSystem = "custom-ci"

	info := Get()

	if info.BuildSystem != "custom-ci" {
		t.Fatalf("BuildSystem = %q, want custom-ci", info.BuildSystem)
	}
}

// Get - debug.ReadBuildInfo (exercised via Get)

func TestGet_GoVersion_FromBuildInfo(t *testing.T) {
	saveAndReset(t)
	setLocalDefaults()

	info := Get()

	if info.GoVersion == "" {
		t.Fatal("GoVersion should be populated from debug.ReadBuildInfo()")
	}
}

func TestGet_LdflagsCommit_NotOverridden(t *testing.T) {
	saveAndReset(t)
	setLocalDefaults()
	Commit = "ldflags-commit-hash"

	info := Get()

	if info.Commit != "ldflags-commit-hash" {
		t.Fatalf("Commit = %q, ldflags value should take precedence", info.Commit)
	}
}

// applyBuildInfo - vcs.revision

func TestApplyBuildInfo_VCSRevision_OverridesNone(t *testing.T) {
	out := &Info{Commit: "none"}
	applyBuildInfo(out, []debug.BuildSetting{
		{Key: "vcs.revision", Value: "abc123"},
	})

	if out.Commit != "abc123" {
		t.Fatalf("Commit = %q, want abc123", out.Commit)
	}
}

func TestApplyBuildInfo_VCSRevision_DoesNotOverrideLdflags(t *testing.T) {
	out := &Info{Commit: "ldflags-hash"}
	applyBuildInfo(out, []debug.BuildSetting{
		{Key: "vcs.revision", Value: "vcs-hash"},
	})

	if out.Commit != "ldflags-hash" {
		t.Fatalf("Commit = %q, ldflags should take precedence", out.Commit)
	}
}

func TestApplyBuildInfo_VCSRevision_EmptyValueIgnored(t *testing.T) {
	out := &Info{Commit: "none"}
	applyBuildInfo(out, []debug.BuildSetting{
		{Key: "vcs.revision", Value: ""},
	})

	if out.Commit != "none" {
		t.Fatalf("Commit = %q, empty vcs.revision should not override", out.Commit)
	}
}

// applyBuildInfo - vcs.time

func TestApplyBuildInfo_VCSTime_SetsBuildDate(t *testing.T) {
	out := &Info{BuildDate: ""}
	applyBuildInfo(out, []debug.BuildSetting{
		{Key: "vcs.time", Value: "2025-01-15T12:00:00Z"},
	})

	if out.BuildDate != "2025-01-15T12:00:00Z" {
		t.Fatalf("BuildDate = %q", out.BuildDate)
	}
}

func TestApplyBuildInfo_VCSTime_DoesNotOverrideBuildDate(t *testing.T) {
	out := &Info{BuildDate: "2025-01-01T00:00:00Z"}
	applyBuildInfo(out, []debug.BuildSetting{
		{Key: "vcs.time", Value: "2025-01-15T12:00:00Z"},
	})

	if out.BuildDate != "2025-01-01T00:00:00Z" {
		t.Fatalf("BuildDate = %q, ldflags should take precedence", out.BuildDate)
	}
}

func TestApplyBuildInfo_VCSTime_EmptyValueIgnoredForBuildDate(t *testing.T) {
	out := &Info{BuildDate: ""}
	applyBuildInfo(out, []debug.BuildSetting{
		{Key: "vcs.time", Value: ""},
	})

	if out.BuildDate != "" {
		t.Fatalf("BuildDate = %q, empty vcs.time should not set BuildDate", out.BuildDate)
	}
}

func TestApplyBuildInfo_VCSTime_AlwaysSetsCommitDate(t *testing.T) {
	out := &Info{CommitDate: "old-value"}
	applyBuildInfo(out, []debug.BuildSetting{
		{Key: "vcs.time", Value: "2025-01-15T12:00:00Z"},
	})

	// CommitDate is always overwritten (no guard)
	if out.CommitDate != "2025-01-15T12:00:00Z" {
		t.Fatalf("CommitDate = %q, should always be updated", out.CommitDate)
	}
}

func TestApplyBuildInfo_VCSTime_EmptyStillSetsCommitDate(t *testing.T) {
	out := &Info{CommitDate: "previous"}
	applyBuildInfo(out, []debug.BuildSetting{
		{Key: "vcs.time", Value: ""},
	})

	// CommitDate is unconditionally assigned, even to empty
	if out.CommitDate != "" {
		t.Fatalf("CommitDate = %q, should be empty", out.CommitDate)
	}
}

// applyBuildInfo - vcs.modified (VCSDirty)

func TestApplyBuildInfo_VCSModified_True(t *testing.T) {
	out := &Info{}
	applyBuildInfo(out, []debug.BuildSetting{
		{Key: "vcs.modified", Value: "true"},
	})

	if out.VCSDirty == nil {
		t.Fatal("VCSDirty should be set")
	}
	if !*out.VCSDirty {
		t.Fatal("VCSDirty should be true")
	}
}

func TestApplyBuildInfo_VCSModified_False(t *testing.T) {
	out := &Info{}
	applyBuildInfo(out, []debug.BuildSetting{
		{Key: "vcs.modified", Value: "false"},
	})

	if out.VCSDirty == nil {
		t.Fatal("VCSDirty should be set")
	}
	if *out.VCSDirty {
		t.Fatal("VCSDirty should be false")
	}
}

func TestApplyBuildInfo_VCSModified_UnknownValue_Ignored(t *testing.T) {
	out := &Info{}
	applyBuildInfo(out, []debug.BuildSetting{
		{Key: "vcs.modified", Value: "maybe"},
	})

	if out.VCSDirty != nil {
		t.Fatal("VCSDirty should be nil for unknown value")
	}
}

func TestApplyBuildInfo_VCSModified_Missing_LeavesNil(t *testing.T) {
	out := &Info{}
	applyBuildInfo(out, []debug.BuildSetting{})

	if out.VCSDirty != nil {
		t.Fatal("VCSDirty should be nil when no vcs.modified setting")
	}
}

func TestApplyBuildInfo_VCSModified_DoesNotOverrideWhenNil(t *testing.T) {
	// If vcs.modified is not present, existing VCSDirty should be preserved
	existing := true
	out := &Info{VCSDirty: &existing}
	applyBuildInfo(out, []debug.BuildSetting{
		{Key: "vcs.revision", Value: "abc"}, // other settings, but no vcs.modified
	})

	if out.VCSDirty == nil || !*out.VCSDirty {
		t.Fatal("VCSDirty should be preserved when vcs.modified is absent")
	}
}

func TestApplyBuildInfo_VCSModified_OverridesExisting(t *testing.T) {
	existing := true
	out := &Info{VCSDirty: &existing}
	applyBuildInfo(out, []debug.BuildSetting{
		{Key: "vcs.modified", Value: "false"},
	})

	if out.VCSDirty == nil {
		t.Fatal("VCSDirty should be set")
	}
	if *out.VCSDirty {
		t.Fatal("vcs.modified should override existing VCSDirty")
	}
}

// applyBuildInfo - multiple settings combined

func TestApplyBuildInfo_AllSettings(t *testing.T) {
	out := &Info{Commit: "none", BuildDate: ""}
	applyBuildInfo(out, []debug.BuildSetting{
		{Key: "vcs.revision", Value: "abc123"},
		{Key: "vcs.time", Value: "2025-01-15T12:00:00Z"},
		{Key: "vcs.modified", Value: "true"},
	})

	if out.Commit != "abc123" {
		t.Fatalf("Commit = %q", out.Commit)
	}
	if out.BuildDate != "2025-01-15T12:00:00Z" {
		t.Fatalf("BuildDate = %q", out.BuildDate)
	}
	if out.CommitDate != "2025-01-15T12:00:00Z" {
		t.Fatalf("CommitDate = %q", out.CommitDate)
	}
	if out.VCSDirty == nil || !*out.VCSDirty {
		t.Fatal("VCSDirty should be true")
	}
}

func TestApplyBuildInfo_UnknownSettings_Ignored(t *testing.T) {
	out := &Info{Commit: "none"}
	applyBuildInfo(out, []debug.BuildSetting{
		{Key: "GOFLAGS", Value: "-trimpath"},
		{Key: "CGO_ENABLED", Value: "0"},
		{Key: "GOARCH", Value: "amd64"},
	})

	if out.Commit != "none" {
		t.Fatalf("Commit = %q, unknown settings should not affect fields", out.Commit)
	}
	if out.VCSDirty != nil {
		t.Fatal("VCSDirty should be nil")
	}
}

func TestApplyBuildInfo_EmptySettings(t *testing.T) {
	out := &Info{Commit: "none", BuildDate: "original"}
	applyBuildInfo(out, nil)

	if out.Commit != "none" {
		t.Fatalf("Commit = %q", out.Commit)
	}
	if out.BuildDate != "original" {
		t.Fatalf("BuildDate = %q", out.BuildDate)
	}
}

// HasProvenance

func TestHasProvenance_True(t *testing.T) {
	info := Info{ReleaseId: "rel-123", EvidenceBucket: "my-bucket"}
	if !info.HasProvenance() {
		t.Fatal("HasProvenance() should be true")
	}
}

func TestHasProvenance_False_NoReleaseId(t *testing.T) {
	info := Info{ReleaseId: "", EvidenceBucket: "my-bucket"}
	if info.HasProvenance() {
		t.Fatal("HasProvenance() should be false without ReleaseId")
	}
}

func TestHasProvenance_False_NoBucket(t *testing.T) {
	info := Info{ReleaseId: "rel-123", EvidenceBucket: ""}
	if info.HasProvenance() {
		t.Fatal("HasProvenance() should be false without EvidenceBucket")
	}
}

func TestHasProvenance_False_BothEmpty(t *testing.T) {
	info := Info{}
	if info.HasProvenance() {
		t.Fatal("HasProvenance() should be false with zero value")
	}
}

func TestHasProvenance_False_PrefixAloneNotEnough(t *testing.T) {
	info := Info{EvidencePrefix: "some/prefix"}
	if info.HasProvenance() {
		t.Fatal("EvidencePrefix alone should not satisfy HasProvenance()")
	}
}

// Get - returns copy, not reference to globals

func TestGet_ReturnsCopy(t *testing.T) {
	saveAndReset(t)
	setCIDefaults()

	info1 := Get()
	Version = "mutated"
	info2 := Get()

	if info1.Version == info2.Version {
		t.Fatal("Get() should return independent copies")
	}
	if info1.Version != "1.2.3" {
		t.Fatalf("first Get().Version = %q", info1.Version)
	}
	if info2.Version != "mutated" {
		t.Fatalf("second Get().Version = %q", info2.Version)
	}
}

// Integration

func TestIntegration_LocalBuild(t *testing.T) {
	saveAndReset(t)
	setLocalDefaults()

	info := Get()

	if info.HasProvenance() {
		t.Fatal("local build should not have provenance")
	}
	if info.BuildSystem != "local" {
		t.Fatalf("BuildSystem = %q", info.BuildSystem)
	}
	if info.GoVersion == "" {
		t.Fatal("GoVersion should be set from debug.ReadBuildInfo")
	}
}

func TestIntegration_CIBuild(t *testing.T) {
	saveAndReset(t)
	setCIDefaults()

	info := Get()

	if !info.HasProvenance() {
		t.Fatal("CI build should have provenance")
	}
	if info.BuildSystem != "github-actions" {
		t.Fatalf("BuildSystem = %q", info.BuildSystem)
	}
	if info.GoVersion == "" {
		t.Fatal("GoVersion should be set")
	}
}
