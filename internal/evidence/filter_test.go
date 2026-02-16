package evidence

import (
	"encoding/json"
	"runtime"
	"testing"
	"time"
)

// RuntimePlatform

func TestRuntimePlatform(t *testing.T) {
	got := RuntimePlatform()
	want := runtime.GOOS + "/" + runtime.GOARCH
	if got != want {
		t.Fatalf("RuntimePlatform() = %q, want %q", got, want)
	}
}

// filterReleaseRaw

func TestFilterReleaseRaw_Empty(t *testing.T) {
	if got := filterReleaseRaw(nil, "linux/amd64"); got != nil {
		t.Fatal("expected nil for nil input")
	}
	if got := filterReleaseRaw([]byte{}, "linux/amd64"); got != nil {
		t.Fatal("expected nil for empty input")
	}
}

func TestFilterReleaseRaw_InvalidJSON(t *testing.T) {
	if got := filterReleaseRaw([]byte(`{bad`), "linux/amd64"); got != nil {
		t.Fatal("expected nil for invalid JSON")
	}
}

func TestFilterReleaseRaw_NoArtifactsKey(t *testing.T) {
	raw := []byte(`{"version": "1.0", "release_id": "rel-1"}`)
	got := filterReleaseRaw(raw, "linux/amd64")
	// should return original raw when no artifacts key
	if got == nil {
		t.Fatal("expected non-nil (original) when no artifacts key")
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(got, &doc); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
}

func TestFilterReleaseRaw_FiltersToMatchingPlatform(t *testing.T) {
	raw := []byte(`{
		"version": "1.0",
		"artifacts": [
			{"os": "linux", "arch": "amd64", "binary": {"sha256": "aaa", "size": 1000}},
			{"os": "linux", "arch": "arm64", "binary": {"sha256": "bbb", "size": 2000}},
			{"os": "darwin", "arch": "arm64", "binary": {"sha256": "ccc", "size": 3000}}
		]
	}`)

	got := filterReleaseRaw(raw, "linux/arm64")
	if got == nil {
		t.Fatal("expected non-nil output")
	}

	var doc map[string]json.RawMessage
	if err := json.Unmarshal(got, &doc); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}

	var arts []struct {
		OS   string `json:"os"`
		Arch string `json:"arch"`
	}
	if err := json.Unmarshal(doc["artifacts"], &arts); err != nil {
		t.Fatalf("failed to parse artifacts: %v", err)
	}
	if len(arts) != 1 {
		t.Fatalf("expected 1 artifact, got %d", len(arts))
	}
	if arts[0].OS != "linux" || arts[0].Arch != "arm64" {
		t.Fatalf("unexpected artifact: %+v", arts[0])
	}
}

func TestFilterReleaseRaw_NoMatchingPlatform(t *testing.T) {
	raw := []byte(`{
		"artifacts": [
			{"os": "linux", "arch": "amd64", "binary": {"sha256": "aaa"}}
		]
	}`)

	got := filterReleaseRaw(raw, "darwin/arm64")
	if got == nil {
		t.Fatal("expected non-nil output")
	}

	var doc map[string]json.RawMessage
	if err := json.Unmarshal(got, &doc); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}

	var arts []json.RawMessage
	if err := json.Unmarshal(doc["artifacts"], &arts); err != nil {
		t.Fatalf("failed to parse artifacts: %v", err)
	}
	if len(arts) != 0 {
		t.Fatalf("expected 0 artifacts for non-matching platform, got %d", len(arts))
	}
}

func TestFilterReleaseRaw_PreservesOtherFields(t *testing.T) {
	raw := []byte(`{
		"version": "1.2.3",
		"release_id": "rel-abc",
		"extra": {"nested": true},
		"artifacts": [
			{"os": "linux", "arch": "amd64", "binary": {"sha256": "aaa"}}
		]
	}`)

	got := filterReleaseRaw(raw, "linux/amd64")
	if got == nil {
		t.Fatal("expected non-nil output")
	}

	var doc map[string]json.RawMessage
	if err := json.Unmarshal(got, &doc); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}

	// version, release_id, extra should still be present
	if _, ok := doc["version"]; !ok {
		t.Fatal("missing version field")
	}
	if _, ok := doc["release_id"]; !ok {
		t.Fatal("missing release_id field")
	}
	if _, ok := doc["extra"]; !ok {
		t.Fatal("missing extra field")
	}
}

func TestFilterReleaseRaw_PreservesAllArtifactFields(t *testing.T) {
	raw := []byte(`{
		"artifacts": [
			{"os": "linux", "arch": "amd64", "binary": {"path": "bin/app", "sha256": "aaa", "size": 5000}, "custom_field": "preserved"}
		]
	}`)

	got := filterReleaseRaw(raw, "linux/amd64")

	var doc map[string]json.RawMessage
	if err := json.Unmarshal(got, &doc); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}

	var arts []map[string]json.RawMessage
	if err := json.Unmarshal(doc["artifacts"], &arts); err != nil {
		t.Fatalf("failed to parse artifacts: %v", err)
	}
	if len(arts) != 1 {
		t.Fatalf("expected 1 artifact, got %d", len(arts))
	}
	if _, ok := arts[0]["custom_field"]; !ok {
		t.Fatal("custom_field not preserved in artifact")
	}
}

// filterInventoryRaw

func TestFilterInventoryRaw_Empty(t *testing.T) {
	if got := filterInventoryRaw(nil, "linux/amd64"); got != nil {
		t.Fatal("expected nil for nil input")
	}
	if got := filterInventoryRaw([]byte{}, "linux/amd64"); got != nil {
		t.Fatal("expected nil for empty input")
	}
}

func TestFilterInventoryRaw_InvalidJSON(t *testing.T) {
	if got := filterInventoryRaw([]byte(`{bad`), "linux/amd64"); got != nil {
		t.Fatal("expected nil for invalid JSON")
	}
}

func TestFilterInventoryRaw_NoTargetsKey(t *testing.T) {
	raw := []byte(`{"source_evidence": {"sbom": []}}`)
	got := filterInventoryRaw(raw, "linux/amd64")
	if got == nil {
		t.Fatal("expected non-nil output when no targets key")
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(got, &doc); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	if _, ok := doc["source_evidence"]; !ok {
		t.Fatal("source_evidence should be preserved")
	}
}

func TestFilterInventoryRaw_FiltersByPlatformField(t *testing.T) {
	raw := []byte(`{
		"source_evidence": {"sbom": []},
		"targets": [
			{"platform": "linux/amd64", "sbom": [{"report": {"path": "amd64/sbom.json"}}]},
			{"platform": "linux/arm64", "sbom": [{"report": {"path": "arm64/sbom.json"}}]},
			{"platform": "darwin/arm64", "sbom": [{"report": {"path": "darwin/sbom.json"}}]}
		]
	}`)

	got := filterInventoryRaw(raw, "linux/amd64")
	if got == nil {
		t.Fatal("expected non-nil output")
	}

	var doc map[string]json.RawMessage
	if err := json.Unmarshal(got, &doc); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}

	var targets []struct {
		Platform string `json:"platform"`
	}
	if err := json.Unmarshal(doc["targets"], &targets); err != nil {
		t.Fatalf("failed to parse targets: %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("expected 1 target, got %d", len(targets))
	}
	if targets[0].Platform != "linux/amd64" {
		t.Fatalf("unexpected platform: %q", targets[0].Platform)
	}
}

func TestFilterInventoryRaw_FallbackToOSArch(t *testing.T) {
	raw := []byte(`{
		"targets": [
			{"os": "linux", "arch": "amd64", "sbom": []},
			{"os": "linux", "arch": "arm64", "sbom": []}
		]
	}`)

	got := filterInventoryRaw(raw, "linux/arm64")

	var doc map[string]json.RawMessage
	if err := json.Unmarshal(got, &doc); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}

	var targets []struct {
		OS   string `json:"os"`
		Arch string `json:"arch"`
	}
	if err := json.Unmarshal(doc["targets"], &targets); err != nil {
		t.Fatalf("failed to parse targets: %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("expected 1 target, got %d", len(targets))
	}
	if targets[0].OS != "linux" || targets[0].Arch != "arm64" {
		t.Fatalf("unexpected target: %+v", targets[0])
	}
}

func TestFilterInventoryRaw_PreservesSourceEvidence(t *testing.T) {
	raw := []byte(`{
		"source_evidence": {
			"sbom": [{"format": "spdx", "report": {"path": "source/sbom.json"}}],
			"scans": [{"scanner": "trivy"}]
		},
		"targets": [
			{"platform": "linux/amd64"},
			{"platform": "linux/arm64"}
		]
	}`)

	got := filterInventoryRaw(raw, "linux/amd64")

	var doc map[string]json.RawMessage
	if err := json.Unmarshal(got, &doc); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}

	if _, ok := doc["source_evidence"]; !ok {
		t.Fatal("source_evidence should be preserved (not filtered)")
	}
}

func TestFilterInventoryRaw_NoMatchingTargets(t *testing.T) {
	raw := []byte(`{
		"targets": [
			{"platform": "linux/amd64"}
		]
	}`)

	got := filterInventoryRaw(raw, "darwin/arm64")

	var doc map[string]json.RawMessage
	if err := json.Unmarshal(got, &doc); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}

	var targets []json.RawMessage
	if err := json.Unmarshal(doc["targets"], &targets); err != nil {
		t.Fatalf("failed to parse targets: %v", err)
	}
	if len(targets) != 0 {
		t.Fatalf("expected 0 targets, got %d", len(targets))
	}
}

// FilterBundleByPlatform

func TestFilterBundleByPlatform_NilBundle(t *testing.T) {
	got := FilterBundleByPlatform(nil, "linux/amd64")
	if got != nil {
		t.Fatal("expected nil for nil bundle")
	}
}

func TestFilterBundleByPlatform_EmptyPlatform(t *testing.T) {
	b := testBundle()
	got := FilterBundleByPlatform(b, "")
	if got != b {
		t.Fatal("expected same bundle pointer for empty platform")
	}
}

// multiPlatformBundle builds a bundle with source evidence + two target platforms
func multiPlatformBundle() *Bundle {
	refs := map[string]*EvidenceFileRef{
		// source (no platform) — should always survive filtering
		"source/sbom.json": {
			Path: "source/sbom.json", SHA256: "s1", Size: 1000,
			Scope: "source", Category: "sbom", Kind: "report",
		},
		"source/sbom.json.sigstore": {
			Path: "source/sbom.json.sigstore", SHA256: "s2", Size: 500,
			Scope: "source", Category: "sbom", Kind: "attestation",
		},
		// linux/amd64
		"amd64/sbom.json": {
			Path: "amd64/sbom.json", SHA256: "a1", Size: 1500,
			Scope: "artifact", Category: "sbom", Kind: "report", Platform: "linux/amd64",
		},
		"amd64/scan.json": {
			Path: "amd64/scan.json", SHA256: "a2", Size: 1800,
			Scope: "artifact", Category: "scan", Kind: "report", Platform: "linux/amd64",
		},
		// linux/arm64
		"arm64/sbom.json": {
			Path: "arm64/sbom.json", SHA256: "b1", Size: 1400,
			Scope: "artifact", Category: "sbom", Kind: "report", Platform: "linux/arm64",
		},
		"arm64/scan.json": {
			Path: "arm64/scan.json", SHA256: "b2", Size: 1700,
			Scope: "artifact", Category: "scan", Kind: "report", Platform: "linux/arm64",
		},
	}

	files := make(map[string]*EvidenceFile, len(refs))
	for path, ref := range refs {
		files[path] = &EvidenceFile{Ref: ref, Data: []byte(`{}`)}
	}

	releaseRaw := []byte(`{
		"version": "1.0.0",
		"artifacts": [
			{"os": "linux", "arch": "amd64", "binary": {"sha256": "aaa", "size": 1000}},
			{"os": "linux", "arch": "arm64", "binary": {"sha256": "bbb", "size": 2000}}
		]
	}`)

	inventoryRaw := []byte(`{
		"source_evidence": {"sbom": [{"report": {"path": "source/sbom.json"}}]},
		"targets": [
			{"platform": "linux/amd64", "sbom": [{"report": {"path": "amd64/sbom.json"}}]},
			{"platform": "linux/arm64", "sbom": [{"report": {"path": "arm64/sbom.json"}}]}
		]
	}`)

	return &Bundle{
		Release: &ReleaseManifest{
			ReleaseID: "rel-multi",
			Version:   "1.0.0",
			Artifacts: []ReleaseArtifact{
				{OS: "linux", Arch: "amd64", Binary: BinaryRef{SHA256: "aaa", Size: 1000}},
				{OS: "linux", Arch: "arm64", Binary: BinaryRef{SHA256: "bbb", Size: 2000}},
			},
		},
		ReleaseRaw:            releaseRaw,
		ReleaseSigstoreBundle: []byte(`{"sigstore": true}`),
		InventoryRaw:          inventoryRaw,
		InventoryHash:         "inv_hash_123",
		FileIndex:             refs,
		Files:                 files,
		Bucket:                "test-bucket",
		ReleasePrefix:         "apps/test/",
		FetchedAt:             time.Now().UTC(),
	}
}

func TestFilterBundleByPlatform_KeepsSourceAndMatchingArtifact(t *testing.T) {
	b := multiPlatformBundle()
	filtered := FilterBundleByPlatform(b, "linux/amd64")

	// source (no platform) + amd64 entries = 4
	if len(filtered.FileIndex) != 4 {
		t.Fatalf("expected 4 entries in FileIndex, got %d", len(filtered.FileIndex))
	}
	if len(filtered.Files) != 4 {
		t.Fatalf("expected 4 entries in Files, got %d", len(filtered.Files))
	}

	// source entries should survive
	if _, ok := filtered.FileIndex["source/sbom.json"]; !ok {
		t.Fatal("source/sbom.json should be preserved")
	}
	if _, ok := filtered.FileIndex["source/sbom.json.sigstore"]; !ok {
		t.Fatal("source/sbom.json.sigstore should be preserved")
	}

	// amd64 should survive
	if _, ok := filtered.FileIndex["amd64/sbom.json"]; !ok {
		t.Fatal("amd64/sbom.json should be preserved")
	}
	if _, ok := filtered.FileIndex["amd64/scan.json"]; !ok {
		t.Fatal("amd64/scan.json should be preserved")
	}

	// arm64 should be removed
	if _, ok := filtered.FileIndex["arm64/sbom.json"]; ok {
		t.Fatal("arm64/sbom.json should be filtered out")
	}
	if _, ok := filtered.FileIndex["arm64/scan.json"]; ok {
		t.Fatal("arm64/scan.json should be filtered out")
	}
}

func TestFilterBundleByPlatform_FiltersReleaseArtifacts(t *testing.T) {
	b := multiPlatformBundle()
	filtered := FilterBundleByPlatform(b, "linux/arm64")

	if filtered.Release == nil {
		t.Fatal("expected non-nil Release")
	}
	if len(filtered.Release.Artifacts) != 1 {
		t.Fatalf("expected 1 artifact, got %d", len(filtered.Release.Artifacts))
	}
	a := filtered.Release.Artifacts[0]
	if a.OS != "linux" || a.Arch != "arm64" {
		t.Fatalf("unexpected artifact: %+v", a)
	}
}

func TestFilterBundleByPlatform_DoesNotMutateOriginal(t *testing.T) {
	b := multiPlatformBundle()
	origIndexLen := len(b.FileIndex)
	origFilesLen := len(b.Files)
	origArtifactsLen := len(b.Release.Artifacts)

	_ = FilterBundleByPlatform(b, "linux/amd64")

	if len(b.FileIndex) != origIndexLen {
		t.Fatal("original FileIndex was mutated")
	}
	if len(b.Files) != origFilesLen {
		t.Fatal("original Files was mutated")
	}
	if len(b.Release.Artifacts) != origArtifactsLen {
		t.Fatal("original Release.Artifacts was mutated")
	}
}

func TestFilterBundleByPlatform_PreservesMetadata(t *testing.T) {
	b := multiPlatformBundle()
	filtered := FilterBundleByPlatform(b, "linux/amd64")

	if filtered.InventoryHash != b.InventoryHash {
		t.Fatalf("InventoryHash = %q, want %q", filtered.InventoryHash, b.InventoryHash)
	}
	if filtered.Bucket != b.Bucket {
		t.Fatalf("Bucket = %q, want %q", filtered.Bucket, b.Bucket)
	}
	if filtered.ReleasePrefix != b.ReleasePrefix {
		t.Fatalf("ReleasePrefix = %q, want %q", filtered.ReleasePrefix, b.ReleasePrefix)
	}
	if !filtered.FetchedAt.Equal(b.FetchedAt) {
		t.Fatalf("FetchedAt mismatch")
	}
	if string(filtered.ReleaseSigstoreBundle) != string(b.ReleaseSigstoreBundle) {
		t.Fatal("ReleaseSigstoreBundle should be preserved")
	}
}

func TestFilterBundleByPlatform_RewritesReleaseRaw(t *testing.T) {
	b := multiPlatformBundle()
	filtered := FilterBundleByPlatform(b, "linux/amd64")

	var doc map[string]json.RawMessage
	if err := json.Unmarshal(filtered.ReleaseRaw, &doc); err != nil {
		t.Fatalf("filtered ReleaseRaw not valid JSON: %v", err)
	}

	var arts []struct {
		OS   string `json:"os"`
		Arch string `json:"arch"`
	}
	if err := json.Unmarshal(doc["artifacts"], &arts); err != nil {
		t.Fatalf("failed to parse artifacts from filtered ReleaseRaw: %v", err)
	}
	if len(arts) != 1 {
		t.Fatalf("expected 1 artifact in ReleaseRaw, got %d", len(arts))
	}
	if arts[0].OS != "linux" || arts[0].Arch != "amd64" {
		t.Fatalf("unexpected artifact in ReleaseRaw: %+v", arts[0])
	}
}

func TestFilterBundleByPlatform_RewritesInventoryRaw(t *testing.T) {
	b := multiPlatformBundle()
	filtered := FilterBundleByPlatform(b, "linux/arm64")

	var doc map[string]json.RawMessage
	if err := json.Unmarshal(filtered.InventoryRaw, &doc); err != nil {
		t.Fatalf("filtered InventoryRaw not valid JSON: %v", err)
	}

	var targets []struct {
		Platform string `json:"platform"`
	}
	if err := json.Unmarshal(doc["targets"], &targets); err != nil {
		t.Fatalf("failed to parse targets: %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("expected 1 target in InventoryRaw, got %d", len(targets))
	}
	if targets[0].Platform != "linux/arm64" {
		t.Fatalf("unexpected platform: %q", targets[0].Platform)
	}

	// source_evidence should still be present
	if _, ok := doc["source_evidence"]; !ok {
		t.Fatal("source_evidence should be preserved in InventoryRaw")
	}
}

func TestFilterBundleByPlatform_NilRelease(t *testing.T) {
	b := multiPlatformBundle()
	b.Release = nil

	filtered := FilterBundleByPlatform(b, "linux/amd64")
	if filtered.Release != nil {
		t.Fatal("expected nil Release when original is nil")
	}
	// should still filter FileIndex
	if _, ok := filtered.FileIndex["arm64/sbom.json"]; ok {
		t.Fatal("arm64 should be filtered even with nil Release")
	}
}

func TestFilterBundleByPlatform_NoMatchingArtifacts(t *testing.T) {
	b := multiPlatformBundle()
	filtered := FilterBundleByPlatform(b, "darwin/arm64")

	// only source entries (no platform) should survive
	if len(filtered.FileIndex) != 2 {
		t.Fatalf("expected 2 entries (source only), got %d", len(filtered.FileIndex))
	}
	if len(filtered.Release.Artifacts) != 0 {
		t.Fatalf("expected 0 artifacts, got %d", len(filtered.Release.Artifacts))
	}
}
