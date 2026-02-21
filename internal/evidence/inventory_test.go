package evidence

import (
	"encoding/json"
	"testing"
)

// helpers

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("mustJSON: %v", err)
	}
	return b
}

func wantFileRef(t *testing.T, idx map[string]*EvidenceFileRef, filePath, scope, category, kind, platform, sha string) {
	t.Helper()
	ref, ok := idx[filePath]
	if !ok {
		t.Fatalf("expected path %q in index, not found", filePath)
	}
	if ref.Scope != scope {
		t.Fatalf("path %q: Scope = %q, want %q", filePath, ref.Scope, scope)
	}
	if ref.Category != category {
		t.Fatalf("path %q: Category = %q, want %q", filePath, ref.Category, category)
	}
	if ref.Kind != kind {
		t.Fatalf("path %q: Kind = %q, want %q", filePath, ref.Kind, kind)
	}
	if ref.Platform != platform {
		t.Fatalf("path %q: Platform = %q, want %q", filePath, ref.Platform, platform)
	}
	if ref.SHA256 != sha {
		t.Fatalf("path %q: SHA256 = %q, want %q", filePath, ref.SHA256, sha)
	}
}

//  BuildFileIndex tests

func TestBuildFileIndex_EmptyInventory(t *testing.T) {
	raw := mustJSON(t, inventoryRoot{})
	idx, err := BuildFileIndex(raw)
	if err != nil {
		t.Fatalf("BuildFileIndex() error: %v", err)
	}
	if len(idx) != 0 {
		t.Fatalf("expected empty index, got %d entries", len(idx))
	}
}

func TestBuildFileIndex_InvalidJSON(t *testing.T) {
	_, err := BuildFileIndex([]byte(`{not json`))
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}

func TestBuildFileIndex_NullJSON(t *testing.T) {
	idx, err := BuildFileIndex([]byte(`null`))
	if err != nil {
		t.Fatalf("BuildFileIndex(null) error: %v", err)
	}
	if len(idx) != 0 {
		t.Fatalf("expected empty index for null, got %d entries", len(idx))
	}
}

func TestBuildFileIndex_EmptyBytes(t *testing.T) {
	_, err := BuildFileIndex([]byte{})
	if err == nil {
		t.Fatal("expected error for empty bytes, got nil")
	}
}

func TestBuildFileIndex_SourceEvidence_SBOM(t *testing.T) {
	inv := inventoryRoot{
		SourceEvidence: &sourceEvidence{
			SBOM: []sbomEntry{
				{
					Format:   "spdx",
					Producer: "syft",
					Report: inventoryFile{
						Path:   "source/sbom/spdx.json",
						Hashes: map[string]string{"sha256": "aaa111"},
						Size:   1024,
					},
					Attestations: []inventoryFile{
						{
							Path:   "source/sbom/spdx.json.sigstore",
							Hashes: map[string]string{"sha256": "bbb222"},
							Size:   512,
						},
					},
				},
			},
		},
	}

	idx, err := BuildFileIndex(mustJSON(t, inv))
	if err != nil {
		t.Fatalf("BuildFileIndex() error: %v", err)
	}
	if len(idx) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(idx))
	}

	wantFileRef(t, idx, "source/sbom/spdx.json", "source", "sbom", "report", "", "aaa111")
	wantFileRef(t, idx, "source/sbom/spdx.json.sigstore", "source", "sbom", "attestation", "", "bbb222")

	// verify size is preserved
	if idx["source/sbom/spdx.json"].Size != 1024 {
		t.Fatalf("Size = %d, want 1024", idx["source/sbom/spdx.json"].Size)
	}
}

func TestBuildFileIndex_SourceEvidence_Scans(t *testing.T) {
	inv := inventoryRoot{
		SourceEvidence: &sourceEvidence{
			Scans: []scanEntry{
				{
					Scanner: "trivy",
					Reports: []scanReport{
						{
							Format: "sarif",
							Kind:   "vuln",
							Report: inventoryFile{
								Path:   "source/scans/trivy-vuln.sarif",
								Hashes: map[string]string{"sha256": "ccc333"},
								Size:   2048,
							},
							Attestations: []inventoryFile{
								{
									Path:   "source/scans/trivy-vuln.sarif.sigstore",
									Hashes: map[string]string{"sha256": "ddd444"},
									Size:   256,
								},
							},
						},
						{
							Format: "json",
							Kind:   "secret",
							Report: inventoryFile{
								Path:   "source/scans/trivy-secret.json",
								Hashes: map[string]string{"sha256": "eee555"},
								Size:   100,
							},
						},
					},
				},
			},
		},
	}

	idx, err := BuildFileIndex(mustJSON(t, inv))
	if err != nil {
		t.Fatalf("BuildFileIndex() error: %v", err)
	}
	if len(idx) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(idx))
	}

	wantFileRef(t, idx, "source/scans/trivy-vuln.sarif", "source", "scan", "report", "", "ccc333")
	wantFileRef(t, idx, "source/scans/trivy-vuln.sarif.sigstore", "source", "scan", "attestation", "", "ddd444")
	wantFileRef(t, idx, "source/scans/trivy-secret.json", "source", "scan", "report", "", "eee555")
}

func TestBuildFileIndex_SourceEvidence_License(t *testing.T) {
	inv := inventoryRoot{
		SourceEvidence: &sourceEvidence{
			License: []licenseEntry{
				{
					Format: "phxi.license_report.v1",
					Report: inventoryFile{
						Path:   "source/license/report.json",
						Hashes: map[string]string{"sha256": "fff666"},
						Size:   4096,
					},
					Attestations: []inventoryFile{
						{
							Path:   "source/license/report.json.sigstore",
							Hashes: map[string]string{"sha256": "aaa777"},
							Size:   300,
						},
					},
				},
			},
		},
	}

	idx, err := BuildFileIndex(mustJSON(t, inv))
	if err != nil {
		t.Fatalf("BuildFileIndex() error: %v", err)
	}
	if len(idx) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(idx))
	}

	wantFileRef(t, idx, "source/license/report.json", "source", "license", "report", "", "fff666")
	wantFileRef(t, idx, "source/license/report.json.sigstore", "source", "license", "attestation", "", "aaa777")
}

func TestBuildFileIndex_TargetEvidence_WithPlatform(t *testing.T) {
	inv := inventoryRoot{
		Targets: []target{
			{
				Platform: "linux/amd64",
				Subject: inventoryFile{
					Path:   "artifacts/linnemanlabs-web-linux-amd64",
					Hashes: map[string]string{"sha256": "subj111"},
					Size:   50000,
				},
				SBOM: []sbomEntry{
					{
						Format:   "cyclonedx",
						Producer: "syft",
						Report: inventoryFile{
							Path:   "artifacts/linux-amd64/sbom-cyclonedx.json",
							Hashes: map[string]string{"sha256": "t_sbom1"},
							Size:   3000,
						},
						Attestations: []inventoryFile{
							{
								Path:   "artifacts/linux-amd64/sbom-cyclonedx.json.sigstore",
								Hashes: map[string]string{"sha256": "t_sbom_att1"},
								Size:   400,
							},
						},
					},
				},
				Scans: []scanEntry{
					{
						Scanner: "grype",
						Reports: []scanReport{
							{
								Format: "json",
								Kind:   "vuln",
								Report: inventoryFile{
									Path:   "artifacts/linux-amd64/grype-vuln.json",
									Hashes: map[string]string{"sha256": "t_scan1"},
									Size:   1500,
								},
							},
						},
					},
				},
				License: []licenseEntry{
					{
						Format: "phxi.license_report.v1",
						Report: inventoryFile{
							Path:   "artifacts/linux-amd64/license.json",
							Hashes: map[string]string{"sha256": "t_lic1"},
							Size:   2000,
						},
					},
				},
			},
		},
	}

	idx, err := BuildFileIndex(mustJSON(t, inv))
	if err != nil {
		t.Fatalf("BuildFileIndex() error: %v", err)
	}
	if len(idx) != 4 {
		t.Fatalf("expected 4 entries, got %d", len(idx))
	}

	wantFileRef(t, idx, "artifacts/linux-amd64/sbom-cyclonedx.json", "artifact", "sbom", "report", "linux/amd64", "t_sbom1")
	wantFileRef(t, idx, "artifacts/linux-amd64/sbom-cyclonedx.json.sigstore", "artifact", "sbom", "attestation", "linux/amd64", "t_sbom_att1")
	wantFileRef(t, idx, "artifacts/linux-amd64/grype-vuln.json", "artifact", "scan", "report", "linux/amd64", "t_scan1")
	wantFileRef(t, idx, "artifacts/linux-amd64/license.json", "artifact", "license", "report", "linux/amd64", "t_lic1")
}

func TestBuildFileIndex_TargetEvidence_PlatformFallbackFromOSArch(t *testing.T) {
	inv := inventoryRoot{
		Targets: []target{
			{
				// Platform is empty, should fallback to OS/Arch
				OS:   "linux",
				Arch: "arm64",
				SBOM: []sbomEntry{
					{
						Report: inventoryFile{
							Path:   "artifacts/arm64/sbom.json",
							Hashes: map[string]string{"sha256": "fallback1"},
							Size:   500,
						},
					},
				},
			},
		},
	}

	idx, err := BuildFileIndex(mustJSON(t, inv))
	if err != nil {
		t.Fatalf("BuildFileIndex() error: %v", err)
	}

	wantFileRef(t, idx, "artifacts/arm64/sbom.json", "artifact", "sbom", "report", "linux/arm64", "fallback1")
}

func TestBuildFileIndex_TargetEvidence_PlatformTakesPrecedenceOverOSArch(t *testing.T) {
	inv := inventoryRoot{
		Targets: []target{
			{
				Platform: "darwin/arm64",
				OS:       "linux",
				Arch:     "amd64",
				SBOM: []sbomEntry{
					{
						Report: inventoryFile{
							Path:   "artifacts/darwin-arm64/sbom.json",
							Hashes: map[string]string{"sha256": "plat_wins"},
							Size:   500,
						},
					},
				},
			},
		},
	}

	idx, err := BuildFileIndex(mustJSON(t, inv))
	if err != nil {
		t.Fatalf("BuildFileIndex() error: %v", err)
	}

	// Platform field should be used, not OS/Arch
	wantFileRef(t, idx, "artifacts/darwin-arm64/sbom.json", "artifact", "sbom", "report", "darwin/arm64", "plat_wins")
}

func TestBuildFileIndex_TargetEvidence_NoPlatformNoOSArch(t *testing.T) {
	inv := inventoryRoot{
		Targets: []target{
			{
				// All platform fields empty
				SBOM: []sbomEntry{
					{
						Report: inventoryFile{
							Path:   "artifacts/unknown/sbom.json",
							Hashes: map[string]string{"sha256": "no_plat"},
							Size:   500,
						},
					},
				},
			},
		},
	}

	idx, err := BuildFileIndex(mustJSON(t, inv))
	if err != nil {
		t.Fatalf("BuildFileIndex() error: %v", err)
	}

	// Platform should be empty when neither Platform nor OS is set
	wantFileRef(t, idx, "artifacts/unknown/sbom.json", "artifact", "sbom", "report", "", "no_plat")
}

func TestBuildFileIndex_MultipleTargets(t *testing.T) {
	inv := inventoryRoot{
		Targets: []target{
			{
				Platform: "linux/amd64",
				SBOM: []sbomEntry{
					{Report: inventoryFile{Path: "amd64/sbom.json", Hashes: map[string]string{"sha256": "a1"}, Size: 100}},
				},
			},
			{
				Platform: "linux/arm64",
				SBOM: []sbomEntry{
					{Report: inventoryFile{Path: "arm64/sbom.json", Hashes: map[string]string{"sha256": "a2"}, Size: 200}},
				},
			},
		},
	}

	idx, err := BuildFileIndex(mustJSON(t, inv))
	if err != nil {
		t.Fatalf("BuildFileIndex() error: %v", err)
	}
	if len(idx) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(idx))
	}

	wantFileRef(t, idx, "amd64/sbom.json", "artifact", "sbom", "report", "linux/amd64", "a1")
	wantFileRef(t, idx, "arm64/sbom.json", "artifact", "sbom", "report", "linux/arm64", "a2")
}

func TestBuildFileIndex_SourceAndTargetCombined(t *testing.T) {
	inv := inventoryRoot{
		SourceEvidence: &sourceEvidence{
			SBOM: []sbomEntry{
				{Report: inventoryFile{Path: "source/sbom.json", Hashes: map[string]string{"sha256": "src1"}, Size: 100}},
			},
			Scans: []scanEntry{
				{Reports: []scanReport{{Report: inventoryFile{Path: "source/scan.json", Hashes: map[string]string{"sha256": "src2"}, Size: 200}}}},
			},
			License: []licenseEntry{
				{Report: inventoryFile{Path: "source/license.json", Hashes: map[string]string{"sha256": "src3"}, Size: 300}},
			},
		},
		Targets: []target{
			{
				Platform: "linux/amd64",
				SBOM: []sbomEntry{
					{Report: inventoryFile{Path: "amd64/sbom.json", Hashes: map[string]string{"sha256": "tgt1"}, Size: 400}},
				},
				Scans: []scanEntry{
					{Reports: []scanReport{{Report: inventoryFile{Path: "amd64/scan.json", Hashes: map[string]string{"sha256": "tgt2"}, Size: 500}}}},
				},
				License: []licenseEntry{
					{Report: inventoryFile{Path: "amd64/license.json", Hashes: map[string]string{"sha256": "tgt3"}, Size: 600}},
				},
			},
		},
	}

	idx, err := BuildFileIndex(mustJSON(t, inv))
	if err != nil {
		t.Fatalf("BuildFileIndex() error: %v", err)
	}
	if len(idx) != 6 {
		t.Fatalf("expected 6 entries, got %d", len(idx))
	}

	// source entries
	wantFileRef(t, idx, "source/sbom.json", "source", "sbom", "report", "", "src1")
	wantFileRef(t, idx, "source/scan.json", "source", "scan", "report", "", "src2")
	wantFileRef(t, idx, "source/license.json", "source", "license", "report", "", "src3")

	// target entries
	wantFileRef(t, idx, "amd64/sbom.json", "artifact", "sbom", "report", "linux/amd64", "tgt1")
	wantFileRef(t, idx, "amd64/scan.json", "artifact", "scan", "report", "linux/amd64", "tgt2")
	wantFileRef(t, idx, "amd64/license.json", "artifact", "license", "report", "linux/amd64", "tgt3")
}

func TestBuildFileIndex_MultipleAttestationsPerEntry(t *testing.T) {
	inv := inventoryRoot{
		SourceEvidence: &sourceEvidence{
			SBOM: []sbomEntry{
				{
					Report: inventoryFile{Path: "src/sbom.json", Hashes: map[string]string{"sha256": "r1"}, Size: 100},
					Attestations: []inventoryFile{
						{Path: "src/sbom.json.kms.sigstore", Hashes: map[string]string{"sha256": "att1"}, Size: 50},
						{Path: "src/sbom.json.oidc.sigstore", Hashes: map[string]string{"sha256": "att2"}, Size: 60},
					},
				},
			},
		},
	}

	idx, err := BuildFileIndex(mustJSON(t, inv))
	if err != nil {
		t.Fatalf("BuildFileIndex() error: %v", err)
	}
	if len(idx) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(idx))
	}

	wantFileRef(t, idx, "src/sbom.json", "source", "sbom", "report", "", "r1")
	wantFileRef(t, idx, "src/sbom.json.kms.sigstore", "source", "sbom", "attestation", "", "att1")
	wantFileRef(t, idx, "src/sbom.json.oidc.sigstore", "source", "sbom", "attestation", "", "att2")
}

func TestBuildFileIndex_MultipleScanners(t *testing.T) {
	inv := inventoryRoot{
		Targets: []target{
			{
				Platform: "linux/amd64",
				Scans: []scanEntry{
					{
						Scanner: "trivy",
						Reports: []scanReport{
							{Report: inventoryFile{Path: "amd64/trivy.json", Hashes: map[string]string{"sha256": "t1"}, Size: 100}},
						},
					},
					{
						Scanner: "grype",
						Reports: []scanReport{
							{Report: inventoryFile{Path: "amd64/grype.json", Hashes: map[string]string{"sha256": "g1"}, Size: 200}},
						},
					},
				},
			},
		},
	}

	idx, err := BuildFileIndex(mustJSON(t, inv))
	if err != nil {
		t.Fatalf("BuildFileIndex() error: %v", err)
	}
	if len(idx) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(idx))
	}

	wantFileRef(t, idx, "amd64/trivy.json", "artifact", "scan", "report", "linux/amd64", "t1")
	wantFileRef(t, idx, "amd64/grype.json", "artifact", "scan", "report", "linux/amd64", "g1")
}

// addFile tests

func TestAddFile_EmptyPath_Skipped(t *testing.T) {
	idx := make(map[string]*EvidenceFileRef)
	addFile(idx, inventoryFile{Path: "", Hashes: map[string]string{"sha256": "abc"}, Size: 100}, "source", "sbom", "report", "")
	if len(idx) != 0 {
		t.Fatalf("expected empty index for empty path, got %d entries", len(idx))
	}
}

func TestAddFile_MissingHash(t *testing.T) {
	idx := make(map[string]*EvidenceFileRef)
	addFile(idx, inventoryFile{Path: "some/file.json", Hashes: map[string]string{}, Size: 100}, "source", "sbom", "report", "")
	if len(idx) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(idx))
	}
	ref := idx["some/file.json"]
	if ref.SHA256 != "" {
		t.Fatalf("SHA256 = %q, want empty string for missing hash", ref.SHA256)
	}
}

func TestAddFile_NilHashes(t *testing.T) {
	idx := make(map[string]*EvidenceFileRef)
	addFile(idx, inventoryFile{Path: "some/file.json", Hashes: nil, Size: 100}, "source", "sbom", "report", "")
	if len(idx) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(idx))
	}
	ref := idx["some/file.json"]
	if ref.SHA256 != "" {
		t.Fatalf("SHA256 = %q, want empty string for nil hashes", ref.SHA256)
	}
}

func TestAddFile_AllFieldsPopulated(t *testing.T) {
	idx := make(map[string]*EvidenceFileRef)
	f := inventoryFile{
		Path:   "artifacts/linux-amd64/sbom.json",
		Hashes: map[string]string{"sha256": "deadbeef", "sha512": "ignored"},
		Size:   9876,
	}
	addFile(idx, f, "artifact", "sbom", "report", "linux/amd64")

	ref := idx["artifacts/linux-amd64/sbom.json"]
	if ref == nil {
		t.Fatal("expected non-nil ref")
	}
	if ref.Path != "artifacts/linux-amd64/sbom.json" {
		t.Fatalf("Path = %q", ref.Path)
	}
	if ref.SHA256 != "deadbeef" {
		t.Fatalf("SHA256 = %q", ref.SHA256)
	}
	if ref.Size != 9876 {
		t.Fatalf("Size = %d", ref.Size)
	}
	if ref.Scope != "artifact" {
		t.Fatalf("Scope = %q", ref.Scope)
	}
	if ref.Category != "sbom" {
		t.Fatalf("Category = %q", ref.Category)
	}
	if ref.Kind != "report" {
		t.Fatalf("Kind = %q", ref.Kind)
	}
	if ref.Platform != "linux/amd64" {
		t.Fatalf("Platform = %q", ref.Platform)
	}
}

func TestAddFile_DuplicatePath_LastWins(t *testing.T) {
	idx := make(map[string]*EvidenceFileRef)

	addFile(idx, inventoryFile{Path: "dup.json", Hashes: map[string]string{"sha256": "first"}, Size: 100}, "source", "sbom", "report", "")
	addFile(idx, inventoryFile{Path: "dup.json", Hashes: map[string]string{"sha256": "second"}, Size: 200}, "artifact", "scan", "attestation", "linux/amd64")

	if len(idx) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(idx))
	}
	ref := idx["dup.json"]
	if ref.SHA256 != "second" {
		t.Fatalf("SHA256 = %q, want 'second' (last-write-wins)", ref.SHA256)
	}
	if ref.Scope != "artifact" {
		t.Fatalf("Scope = %q, want 'artifact' (last-write-wins)", ref.Scope)
	}
}

// edge cases and realistic payloads

func TestBuildFileIndex_NilSourceEvidence(t *testing.T) {
	inv := inventoryRoot{
		SourceEvidence: nil,
		Targets: []target{
			{
				Platform: "linux/amd64",
				SBOM: []sbomEntry{
					{Report: inventoryFile{Path: "amd64/sbom.json", Hashes: map[string]string{"sha256": "x"}, Size: 100}},
				},
			},
		},
	}

	idx, err := BuildFileIndex(mustJSON(t, inv))
	if err != nil {
		t.Fatalf("BuildFileIndex() error: %v", err)
	}
	if len(idx) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(idx))
	}
}

func TestBuildFileIndex_EmptySlicesNoEntries(t *testing.T) {
	inv := inventoryRoot{
		SourceEvidence: &sourceEvidence{
			SBOM:    []sbomEntry{},
			Scans:   []scanEntry{},
			License: []licenseEntry{},
		},
		Targets: []target{},
	}

	idx, err := BuildFileIndex(mustJSON(t, inv))
	if err != nil {
		t.Fatalf("BuildFileIndex() error: %v", err)
	}
	if len(idx) != 0 {
		t.Fatalf("expected 0 entries, got %d", len(idx))
	}
}

func TestBuildFileIndex_ScanWithNoReports(t *testing.T) {
	inv := inventoryRoot{
		SourceEvidence: &sourceEvidence{
			Scans: []scanEntry{
				{Scanner: "trivy", Reports: []scanReport{}},
			},
		},
	}

	idx, err := BuildFileIndex(mustJSON(t, inv))
	if err != nil {
		t.Fatalf("BuildFileIndex() error: %v", err)
	}
	if len(idx) != 0 {
		t.Fatalf("expected 0 entries for scanner with no reports, got %d", len(idx))
	}
}

func TestBuildFileIndex_SBOMWithNoAttestations(t *testing.T) {
	inv := inventoryRoot{
		SourceEvidence: &sourceEvidence{
			SBOM: []sbomEntry{
				{
					Report:       inventoryFile{Path: "src/sbom.json", Hashes: map[string]string{"sha256": "r1"}, Size: 100},
					Attestations: nil,
				},
			},
		},
	}

	idx, err := BuildFileIndex(mustJSON(t, inv))
	if err != nil {
		t.Fatalf("BuildFileIndex() error: %v", err)
	}
	if len(idx) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(idx))
	}
	wantFileRef(t, idx, "src/sbom.json", "source", "sbom", "report", "", "r1")
}

func TestBuildFileIndex_TargetScanAttestations(t *testing.T) {
	inv := inventoryRoot{
		Targets: []target{
			{
				Platform: "linux/amd64",
				Scans: []scanEntry{
					{
						Scanner: "trivy",
						Reports: []scanReport{
							{
								Format: "json",
								Kind:   "vuln",
								Report: inventoryFile{
									Path:   "amd64/trivy.json",
									Hashes: map[string]string{"sha256": "scan_r"},
									Size:   1000,
								},
								Attestations: []inventoryFile{
									{
										Path:   "amd64/trivy.json.sigstore",
										Hashes: map[string]string{"sha256": "scan_att"},
										Size:   300,
									},
								},
							},
						},
					},
				},
			},
		},
	}

	idx, err := BuildFileIndex(mustJSON(t, inv))
	if err != nil {
		t.Fatalf("BuildFileIndex() error: %v", err)
	}
	if len(idx) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(idx))
	}

	wantFileRef(t, idx, "amd64/trivy.json", "artifact", "scan", "report", "linux/amd64", "scan_r")
	wantFileRef(t, idx, "amd64/trivy.json.sigstore", "artifact", "scan", "attestation", "linux/amd64", "scan_att")
}

func TestBuildFileIndex_TargetLicenseAttestations(t *testing.T) {
	inv := inventoryRoot{
		Targets: []target{
			{
				Platform: "linux/arm64",
				License: []licenseEntry{
					{
						Format: "phxi.license_report.v1",
						Report: inventoryFile{
							Path:   "arm64/license.json",
							Hashes: map[string]string{"sha256": "lic_r"},
							Size:   800,
						},
						Attestations: []inventoryFile{
							{
								Path:   "arm64/license.json.kms.sigstore",
								Hashes: map[string]string{"sha256": "lic_att_kms"},
								Size:   200,
							},
							{
								Path:   "arm64/license.json.oidc.sigstore",
								Hashes: map[string]string{"sha256": "lic_att_oidc"},
								Size:   250,
							},
						},
					},
				},
			},
		},
	}

	idx, err := BuildFileIndex(mustJSON(t, inv))
	if err != nil {
		t.Fatalf("BuildFileIndex() error: %v", err)
	}
	if len(idx) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(idx))
	}

	wantFileRef(t, idx, "arm64/license.json", "artifact", "license", "report", "linux/arm64", "lic_r")
	wantFileRef(t, idx, "arm64/license.json.kms.sigstore", "artifact", "license", "attestation", "linux/arm64", "lic_att_kms")
	wantFileRef(t, idx, "arm64/license.json.oidc.sigstore", "artifact", "license", "attestation", "linux/arm64", "lic_att_oidc")
}

//  JSON round-trip / realistic payload

func TestBuildFileIndex_RealisticPayload(t *testing.T) {
	// Simulates a real inventory.json with source + two targets
	raw := []byte(`{
		"source_evidence": {
			"sbom": [{
				"format": "spdx-json",
				"producer": "syft",
				"report": {"path": "source/sbom/spdx.json", "hashes": {"sha256": "abc123"}, "size": 15000},
				"attestations": [
					{"path": "source/sbom/spdx.json.kms.sigstore", "hashes": {"sha256": "def456"}, "size": 500},
					{"path": "source/sbom/spdx.json.oidc.sigstore", "hashes": {"sha256": "ghi789"}, "size": 600}
				]
			}],
			"scans": [{
				"scanner": "trivy",
				"reports": [
					{
						"format": "json",
						"kind": "vuln",
						"report": {"path": "source/scans/trivy-vuln.json", "hashes": {"sha256": "scan1"}, "size": 8000},
						"attestations": [{"path": "source/scans/trivy-vuln.json.sigstore", "hashes": {"sha256": "scan1att"}, "size": 400}]
					}
				]
			}],
			"license": [{
				"format": "phxi.license_report.v1",
				"report": {"path": "source/license/report.json", "hashes": {"sha256": "lic1"}, "size": 12000},
				"attestations": [{"path": "source/license/report.json.sigstore", "hashes": {"sha256": "lic1att"}, "size": 350}]
			}]
		},
		"targets": [
			{
				"platform": "linux/amd64",
				"os": "linux",
				"arch": "amd64",
				"subject": {"path": "artifacts/linnemanlabs-web-linux-amd64", "hashes": {"sha256": "bin_amd64"}, "size": 25000000},
				"sbom": [{"format": "cyclonedx-json", "producer": "syft", "report": {"path": "artifacts/linux-amd64/sbom.json", "hashes": {"sha256": "tsbom_amd"}, "size": 14000}}],
				"scans": [{"scanner": "grype", "reports": [{"format": "json", "kind": "vuln", "report": {"path": "artifacts/linux-amd64/grype.json", "hashes": {"sha256": "tscan_amd"}, "size": 5000}}]}],
				"license": [{"format": "phxi.license_report.v1", "report": {"path": "artifacts/linux-amd64/license.json", "hashes": {"sha256": "tlic_amd"}, "size": 11000}}]
			},
			{
				"platform": "linux/arm64",
				"os": "linux",
				"arch": "arm64",
				"subject": {"path": "artifacts/linnemanlabs-web-linux-arm64", "hashes": {"sha256": "bin_arm64"}, "size": 24000000},
				"sbom": [{"format": "cyclonedx-json", "producer": "syft", "report": {"path": "artifacts/linux-arm64/sbom.json", "hashes": {"sha256": "tsbom_arm"}, "size": 14500}}],
				"scans": [{"scanner": "grype", "reports": [{"format": "json", "kind": "vuln", "report": {"path": "artifacts/linux-arm64/grype.json", "hashes": {"sha256": "tscan_arm"}, "size": 4800}}]}],
				"license": [{"format": "phxi.license_report.v1", "report": {"path": "artifacts/linux-arm64/license.json", "hashes": {"sha256": "tlic_arm"}, "size": 10500}}]
			}
		]
	}`)

	idx, err := BuildFileIndex(raw)
	if err != nil {
		t.Fatalf("BuildFileIndex() error: %v", err)
	}

	// source: 1 report + 2 attestations + 1 scan report + 1 scan attestation + 1 license report + 1 license attestation = 7
	// target amd64: 1 sbom + 1 scan + 1 license = 3
	// target arm64: 1 sbom + 1 scan + 1 license = 3
	// total: 13
	if len(idx) != 13 {
		t.Fatalf("expected 13 entries, got %d", len(idx))
	}

	// spot-check a few entries across scopes
	wantFileRef(t, idx, "source/sbom/spdx.json", "source", "sbom", "report", "", "abc123")
	wantFileRef(t, idx, "source/sbom/spdx.json.oidc.sigstore", "source", "sbom", "attestation", "", "ghi789")
	wantFileRef(t, idx, "source/scans/trivy-vuln.json.sigstore", "source", "scan", "attestation", "", "scan1att")
	wantFileRef(t, idx, "source/license/report.json", "source", "license", "report", "", "lic1")

	wantFileRef(t, idx, "artifacts/linux-amd64/sbom.json", "artifact", "sbom", "report", "linux/amd64", "tsbom_amd")
	wantFileRef(t, idx, "artifacts/linux-arm64/grype.json", "artifact", "scan", "report", "linux/arm64", "tscan_arm")
	wantFileRef(t, idx, "artifacts/linux-arm64/license.json", "artifact", "license", "report", "linux/arm64", "tlic_arm")
}

func TestBuildFileIndex_UnknownFieldsIgnored(t *testing.T) {
	// Inventory JSON with extra fields that don't map to the struct - should not error
	raw := []byte(`{
		"version": "2.0",
		"metadata": {"generated_by": "build-system"},
		"source_evidence": {
			"sbom": [{
				"format": "spdx",
				"producer": "syft",
				"extra_field": true,
				"report": {"path": "src/sbom.json", "hashes": {"sha256": "aaa"}, "size": 100}
			}]
		},
		"targets": [],
		"also_unknown": 42
	}`)

	idx, err := BuildFileIndex(raw)
	if err != nil {
		t.Fatalf("BuildFileIndex() error on unknown fields: %v", err)
	}
	if len(idx) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(idx))
	}
}

func TestBuildFileIndex_ZeroSizeFile(t *testing.T) {
	inv := inventoryRoot{
		SourceEvidence: &sourceEvidence{
			SBOM: []sbomEntry{
				{Report: inventoryFile{Path: "empty.json", Hashes: map[string]string{"sha256": "e3b0c44"}, Size: 0}},
			},
		},
	}

	idx, err := BuildFileIndex(mustJSON(t, inv))
	if err != nil {
		t.Fatalf("BuildFileIndex() error: %v", err)
	}
	ref := idx["empty.json"]
	if ref == nil {
		t.Fatal("expected entry for zero-size file")
	}
	if ref.Size != 0 {
		t.Fatalf("Size = %d, want 0", ref.Size)
	}
}
