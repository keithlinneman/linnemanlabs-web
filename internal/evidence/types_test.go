package evidence

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// helpers

// testBundle builds a Bundle with a populated FileIndex and Files map.
// Callers can override fields after creation.
func testBundle() *Bundle {
	refs := map[string]*EvidenceFileRef{
		"source/sbom/spdx.json": {
			Path: "source/sbom/spdx.json", SHA256: "aaa", Size: 1000,
			Scope: "source", Category: "sbom", Kind: "report",
		},
		"source/sbom/spdx.json.sigstore": {
			Path: "source/sbom/spdx.json.sigstore", SHA256: "bbb", Size: 500,
			Scope: "source", Category: "sbom", Kind: "attestation",
		},
		"source/scan/trivy.json": {
			Path: "source/scan/trivy.json", SHA256: "ccc", Size: 2000,
			Scope: "source", Category: "scan", Kind: "report",
		},
		"source/scan/trivy.json.sigstore": {
			Path: "source/scan/trivy.json.sigstore", SHA256: "ddd", Size: 400,
			Scope: "source", Category: "scan", Kind: "attestation",
		},
		"source/license/report.json": {
			Path: "source/license/report.json", SHA256: "eee", Size: 3000,
			Scope: "source", Category: "license", Kind: "report",
		},
		"source/license/report.json.sigstore": {
			Path: "source/license/report.json.sigstore", SHA256: "fff", Size: 300,
			Scope: "source", Category: "license", Kind: "attestation",
		},
		"amd64/sbom.json": {
			Path: "amd64/sbom.json", SHA256: "ggg", Size: 1500,
			Scope: "artifact", Category: "sbom", Kind: "report", Platform: "linux/amd64",
		},
		"amd64/sbom.json.sigstore": {
			Path: "amd64/sbom.json.sigstore", SHA256: "hhh", Size: 450,
			Scope: "artifact", Category: "sbom", Kind: "attestation", Platform: "linux/amd64",
		},
		"amd64/scan.json": {
			Path: "amd64/scan.json", SHA256: "iii", Size: 1800,
			Scope: "artifact", Category: "scan", Kind: "report", Platform: "linux/amd64",
		},
	}

	files := make(map[string]*EvidenceFile, len(refs))
	for path, ref := range refs {
		files[path] = &EvidenceFile{Ref: ref, Data: []byte(`{}`)}
	}

	return &Bundle{
		Release: &ReleaseManifest{
			ReleaseID: "rel-20260215-abc123",
			Version:   "1.2.3",
		},
		FileIndex:     refs,
		Files:         files,
		InventoryHash: "deadbeefdeadbeef",
		FetchedAt:     time.Now().UTC(),
	}
}

// Bundle.File

func TestBundle_File_Found(t *testing.T) {
	b := testBundle()
	f, ok := b.File("source/sbom/spdx.json")
	if !ok {
		t.Fatal("expected File to return true")
	}
	if f == nil {
		t.Fatal("expected non-nil EvidenceFile")
	}
	if f.Ref.SHA256 != "aaa" {
		t.Fatalf("SHA256 = %q, want aaa", f.Ref.SHA256)
	}
}

func TestBundle_File_NotFound(t *testing.T) {
	b := testBundle()
	f, ok := b.File("nonexistent/path.json")
	if ok {
		t.Fatal("expected File to return false for missing path")
	}
	if f != nil {
		t.Fatal("expected nil file for missing path")
	}
}

func TestBundle_File_NilBundle(t *testing.T) {
	var b *Bundle
	f, ok := b.File("any/path.json")
	if ok {
		t.Fatal("expected false for nil bundle")
	}
	if f != nil {
		t.Fatal("expected nil for nil bundle")
	}
}

func TestBundle_File_NilFiles(t *testing.T) {
	b := &Bundle{Files: nil}
	f, ok := b.File("any/path.json")
	if ok {
		t.Fatal("expected false for nil Files map")
	}
	if f != nil {
		t.Fatal("expected nil for nil Files map")
	}
}

// Bundle.FileRef

func TestBundle_FileRef_Found(t *testing.T) {
	b := testBundle()
	ref, ok := b.FileRef("source/sbom/spdx.json")
	if !ok {
		t.Fatal("expected FileRef to return true")
	}
	if ref.Scope != "source" || ref.Category != "sbom" || ref.Kind != "report" {
		t.Fatalf("unexpected ref: %+v", ref)
	}
}

func TestBundle_FileRef_NotFound(t *testing.T) {
	b := testBundle()
	ref, ok := b.FileRef("nonexistent/path.json")
	if ok {
		t.Fatal("expected false for missing path")
	}
	if ref != nil {
		t.Fatal("expected nil ref for missing path")
	}
}

func TestBundle_FileRef_NilBundle(t *testing.T) {
	var b *Bundle
	ref, ok := b.FileRef("any/path.json")
	if ok {
		t.Fatal("expected false for nil bundle")
	}
	if ref != nil {
		t.Fatal("expected nil for nil bundle")
	}
}

func TestBundle_FileRef_NilFileIndex(t *testing.T) {
	b := &Bundle{FileIndex: nil}
	ref, ok := b.FileRef("any/path.json")
	if ok {
		t.Fatal("expected false for nil FileIndex")
	}
	if ref != nil {
		t.Fatal("expected nil for nil FileIndex")
	}
}

// Bundle.FileRefs (filtered)

func TestBundle_FileRefs_ByScope(t *testing.T) {
	b := testBundle()
	refs := b.FileRefs("source", "")
	// source entries: sbom report, sbom att, scan report, scan att, license report, license att = 6
	if len(refs) != 6 {
		t.Fatalf("expected 6 source refs, got %d", len(refs))
	}
	for _, ref := range refs {
		if ref.Scope != "source" {
			t.Fatalf("unexpected scope %q in source-filtered results", ref.Scope)
		}
	}
}

func TestBundle_FileRefs_ByCategory(t *testing.T) {
	b := testBundle()
	refs := b.FileRefs("", "sbom")
	// sbom entries: source report, source att, artifact report, artifact att = 4
	if len(refs) != 4 {
		t.Fatalf("expected 4 sbom refs, got %d", len(refs))
	}
	for _, ref := range refs {
		if ref.Category != "sbom" {
			t.Fatalf("unexpected category %q in sbom-filtered results", ref.Category)
		}
	}
}

func TestBundle_FileRefs_ByScopeAndCategory(t *testing.T) {
	b := testBundle()
	refs := b.FileRefs("artifact", "scan")
	// artifact scan: amd64/scan.json only (report, no attestation)
	if len(refs) != 1 {
		t.Fatalf("expected 1 artifact/scan ref, got %d", len(refs))
	}
	if refs[0].Path != "amd64/scan.json" {
		t.Fatalf("unexpected path: %q", refs[0].Path)
	}
}

func TestBundle_FileRefs_NoMatch(t *testing.T) {
	b := testBundle()
	refs := b.FileRefs("artifact", "license")
	if len(refs) != 0 {
		t.Fatalf("expected 0 artifact/license refs, got %d", len(refs))
	}
}

func TestBundle_FileRefs_EmptyFilters_ReturnsAll(t *testing.T) {
	b := testBundle()
	refs := b.FileRefs("", "")
	if len(refs) != len(b.FileIndex) {
		t.Fatalf("expected %d refs (all), got %d", len(b.FileIndex), len(refs))
	}
}

func TestBundle_FileRefs_NilBundle(t *testing.T) {
	var b *Bundle
	refs := b.FileRefs("source", "sbom")
	if refs != nil {
		t.Fatalf("expected nil for nil bundle, got %d refs", len(refs))
	}
}

// Bundle.Summary

func TestBundle_Summary(t *testing.T) {
	b := testBundle()
	s := b.Summary()
	if s == nil {
		t.Fatal("expected non-nil summary")
	}

	// expected keys from testBundle:
	// source.sbom.report: 1, source.sbom.attestation: 1
	// source.scan.report: 1, source.scan.attestation: 1
	// source.license.report: 1, source.license.attestation: 1
	// artifact.sbom.report: 1, artifact.sbom.attestation: 1
	// artifact.scan.report: 1
	expected := map[string]int{
		"source.sbom.report":         1,
		"source.sbom.attestation":    1,
		"source.scan.report":         1,
		"source.scan.attestation":    1,
		"source.license.report":      1,
		"source.license.attestation": 1,
		"artifact.sbom.report":       1,
		"artifact.sbom.attestation":  1,
		"artifact.scan.report":       1,
	}

	if len(s) != len(expected) {
		t.Fatalf("summary has %d keys, want %d", len(s), len(expected))
	}
	for k, wantCount := range expected {
		if s[k] != wantCount {
			t.Fatalf("Summary[%q] = %d, want %d", k, s[k], wantCount)
		}
	}
}

func TestBundle_Summary_NilBundle(t *testing.T) {
	var b *Bundle
	if s := b.Summary(); s != nil {
		t.Fatal("expected nil for nil bundle")
	}
}

func TestBundle_Summary_NilFileIndex(t *testing.T) {
	b := &Bundle{FileIndex: nil}
	if s := b.Summary(); s != nil {
		t.Fatal("expected nil for nil FileIndex")
	}
}

func TestBundle_Summary_EmptyFileIndex(t *testing.T) {
	b := &Bundle{FileIndex: map[string]*EvidenceFileRef{}}
	s := b.Summary()
	if len(s) != 0 {
		t.Fatalf("expected 0 keys, got %d", len(s))
	}
}

// Bundle.Attestations

func TestBundle_Attestations(t *testing.T) {
	b := testBundle()
	ac := b.Attestations()

	// attestations in testBundle:
	// source/sbom: 1, source/scan: 1, source/license: 1, artifact/sbom: 1 = 4 total
	if ac.Total != 4 {
		t.Fatalf("Total = %d, want 4", ac.Total)
	}
	if ac.Source != 3 {
		t.Fatalf("Source = %d, want 3", ac.Source)
	}
	if ac.Artifact != 1 {
		t.Fatalf("Artifact = %d, want 1", ac.Artifact)
	}
	if !ac.SBOMAttested {
		t.Fatal("SBOMAttested = false")
	}
	if !ac.ScanAttested {
		t.Fatal("ScanAttested = false")
	}
	if !ac.LicenseAttested {
		t.Fatal("LicenseAttested = false")
	}
}

func TestBundle_Attestations_NoAttestations(t *testing.T) {
	b := &Bundle{
		FileIndex: map[string]*EvidenceFileRef{
			"src/sbom.json": {Kind: "report", Scope: "source", Category: "sbom"},
			"src/scan.json": {Kind: "report", Scope: "source", Category: "scan"},
		},
	}
	ac := b.Attestations()
	if ac.Total != 0 {
		t.Fatalf("Total = %d, want 0", ac.Total)
	}
	if ac.SBOMAttested || ac.ScanAttested || ac.LicenseAttested {
		t.Fatal("expected no attestation flags set")
	}
}

func TestBundle_Attestations_PartialCategories(t *testing.T) {
	b := &Bundle{
		FileIndex: map[string]*EvidenceFileRef{
			"sbom.att": {Kind: "attestation", Scope: "source", Category: "sbom"},
			// no scan or license attestations
		},
	}
	ac := b.Attestations()
	if ac.Total != 1 {
		t.Fatalf("Total = %d, want 1", ac.Total)
	}
	if !ac.SBOMAttested {
		t.Fatal("SBOMAttested = false")
	}
	if ac.ScanAttested {
		t.Fatal("ScanAttested = true, want false")
	}
	if ac.LicenseAttested {
		t.Fatal("LicenseAttested = true, want false")
	}
}

func TestBundle_Attestations_NilBundle(t *testing.T) {
	var b *Bundle
	ac := b.Attestations()
	if ac.Total != 0 {
		t.Fatalf("Total = %d, want 0 for nil bundle", ac.Total)
	}
}

func TestBundle_Attestations_NilFileIndex(t *testing.T) {
	b := &Bundle{FileIndex: nil}
	ac := b.Attestations()
	if ac.Total != 0 {
		t.Fatalf("Total = %d, want 0 for nil FileIndex", ac.Total)
	}
}

// Bundle.HasReleaseSigstoreBundle

func TestBundle_HasReleaseSigstoreBundle_True(t *testing.T) {
	b := &Bundle{ReleaseSigstoreBundle: []byte(`{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}`)}
	if !b.HasReleaseSigstoreBundle() {
		t.Fatal("expected true")
	}
}

func TestBundle_HasReleaseSigstoreBundle_Empty(t *testing.T) {
	b := &Bundle{ReleaseSigstoreBundle: []byte{}}
	if b.HasReleaseSigstoreBundle() {
		t.Fatal("expected false for empty bytes")
	}
}

func TestBundle_HasReleaseSigstoreBundle_Nil(t *testing.T) {
	b := &Bundle{ReleaseSigstoreBundle: nil}
	if b.HasReleaseSigstoreBundle() {
		t.Fatal("expected false for nil")
	}
}

func TestBundle_HasReleaseSigstoreBundle_NilBundle(t *testing.T) {
	var b *Bundle
	if b.HasReleaseSigstoreBundle() {
		t.Fatal("expected false for nil bundle")
	}
}

// Bundle.LoadSummary

func TestBundle_LoadSummary(t *testing.T) {
	b := testBundle()
	s := b.LoadSummary()
	if s == "" {
		t.Fatal("expected non-empty summary")
	}
	// Should contain release ID, version, and file counts
	wantParts := []string{"rel-20260215-abc123", "1.2.3"}
	for _, part := range wantParts {
		if !strings.Contains(s, part) {
			t.Fatalf("LoadSummary() = %q, missing %q", s, part)
		}
	}
}

func TestBundle_LoadSummary_NilBundle(t *testing.T) {
	var b *Bundle
	s := b.LoadSummary()
	if s != "no evidence loaded" {
		t.Fatalf("LoadSummary() = %q, want 'no evidence loaded'", s)
	}
}

// ParsePolicy

func TestParsePolicy_Empty(t *testing.T) {
	pol, err := ParsePolicy(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pol != nil {
		t.Fatal("expected nil policy for nil input")
	}

	pol, err = ParsePolicy(json.RawMessage{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pol != nil {
		t.Fatal("expected nil policy for empty input")
	}
}

func TestParsePolicy_InvalidJSON(t *testing.T) {
	_, err := ParsePolicy(json.RawMessage(`{not valid`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestParsePolicy_NoEnforcement(t *testing.T) {
	// Valid JSON but no enforcement field — returns nil (no policy)
	raw := json.RawMessage(`{"defaults": {"signing": {}}}`)
	pol, err := ParsePolicy(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pol != nil {
		t.Fatal("expected nil policy when enforcement is empty")
	}
}

func TestParsePolicy_Full(t *testing.T) {
	raw := json.RawMessage(`{
		"defaults": {
			"enforcement": "block",
			"signing": {
				"require_inventory_signature": true,
				"require_subject_signatures": true
			},
			"evidence": {
				"sbom": {"required": true, "attestation_required": true},
				"scan": {"required": true, "attestation_required": false},
				"license": {"required": true, "attestation_required": true},
				"provenance": {"required": true, "attestation_required": false}
			},
			"vulnerability": {
				"gating": {
					"default": {
						"block_on": ["critical", "high"],
						"allow_if_vex": true
					}
				}
			},
			"license": {
				"deny": ["GPL-*", "AGPL-*"],
				"allow": ["MIT", "Apache-2.0", "BSD-3-Clause"],
				"allow_unknown": false
			}
		}
	}`)

	pol, err := ParsePolicy(raw)
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	if pol == nil {
		t.Fatal("expected non-nil policy")
	}

	if pol.Enforcement != "block" {
		t.Fatalf("Enforcement = %q", pol.Enforcement)
	}

	// signing
	if !pol.Signing.RequireInventorySignature {
		t.Fatal("RequireInventorySignature = false")
	}
	if !pol.Signing.RequireSubjectSignatures {
		t.Fatal("RequireSubjectSignatures = false")
	}

	// evidence
	if !pol.Evidence.SBOMRequired {
		t.Fatal("SBOMRequired = false")
	}
	if !pol.Evidence.ScanRequired {
		t.Fatal("ScanRequired = false")
	}
	if !pol.Evidence.LicenseRequired {
		t.Fatal("LicenseRequired = false")
	}
	if !pol.Evidence.ProvenanceRequired {
		t.Fatal("ProvenanceRequired = false")
	}
	if !pol.Evidence.AttestationsRequired {
		t.Fatal("AttestationsRequired = false (sbom + license have attestation_required)")
	}

	// vulnerability
	if len(pol.Vulnerability.BlockOn) != 2 || pol.Vulnerability.BlockOn[0] != "critical" || pol.Vulnerability.BlockOn[1] != "high" {
		t.Fatalf("Vulnerability.BlockOn = %v", pol.Vulnerability.BlockOn)
	}
	if !pol.Vulnerability.AllowIfVEX {
		t.Fatal("AllowIfVEX = false")
	}

	// license
	if len(pol.License.Denied) != 2 {
		t.Fatalf("License.Denied = %v", pol.License.Denied)
	}
	if len(pol.License.Allowed) != 3 {
		t.Fatalf("License.Allowed = %v", pol.License.Allowed)
	}
	if pol.License.AllowUnknown {
		t.Fatal("AllowUnknown = true")
	}
}

func TestParsePolicy_AttestationsRequired_OnlyWhenFlagSet(t *testing.T) {
	// No attestation_required flags set
	raw := json.RawMessage(`{
		"defaults": {
			"enforcement": "warn",
			"evidence": {
				"sbom": {"required": true, "attestation_required": false},
				"scan": {"required": true, "attestation_required": false},
				"license": {"required": false, "attestation_required": false},
				"provenance": {"required": false, "attestation_required": false}
			}
		}
	}`)

	pol, err := ParsePolicy(raw)
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	if pol.Evidence.AttestationsRequired {
		t.Fatal("AttestationsRequired = true, want false when no attestation flags set")
	}
}

func TestParsePolicy_AttestationsRequired_SingleFlag(t *testing.T) {
	// Only provenance attestation required
	raw := json.RawMessage(`{
		"defaults": {
			"enforcement": "warn",
			"evidence": {
				"sbom": {"required": true, "attestation_required": false},
				"scan": {"required": true, "attestation_required": false},
				"license": {"required": false, "attestation_required": false},
				"provenance": {"required": true, "attestation_required": true}
			}
		}
	}`)

	pol, err := ParsePolicy(raw)
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	if !pol.Evidence.AttestationsRequired {
		t.Fatal("AttestationsRequired = false, want true when provenance attestation required")
	}
}
