package evidence

import "encoding/json"

type inventoryRoot struct {
	SourceEvidence *sourceEvidence `json:"source_evidence"`
	Targets        []target        `json:"targets"`
}

type sourceEvidence struct {
	SBOM    []sbomEntry    `json:"sbom"`
	Scans   []scanEntry    `json:"scans"`
	License []licenseEntry `json:"license"`
}

type target struct {
	Platform string         `json:"platform"`
	OS       string         `json:"os"`
	Arch     string         `json:"arch"`
	Subject  inventoryFile  `json:"subject"`
	SBOM     []sbomEntry    `json:"sbom"`
	Scans    []scanEntry    `json:"scans"`
	License  []licenseEntry `json:"license"`
}

type sbomEntry struct {
	Format       string          `json:"format"`
	Producer     string          `json:"producer"`
	Report       inventoryFile   `json:"report"`
	Attestations []inventoryFile `json:"attestations"`
}

type scanEntry struct {
	Scanner string       `json:"scanner"`
	Reports []scanReport `json:"reports"`
}

type scanReport struct {
	Format       string          `json:"format"`
	Kind         string          `json:"kind"`
	Report       inventoryFile   `json:"report"`
	Attestations []inventoryFile `json:"attestations"`
}

type licenseEntry struct {
	Format       string          `json:"format"`
	Report       inventoryFile   `json:"report"`
	Attestations []inventoryFile `json:"attestations"`
}

type inventoryFile struct {
	Path   string            `json:"path"`
	Hashes map[string]string `json:"hashes"`
	Size   int64             `json:"size"`
}

// BuildFileIndex parses inventory.json and returns a flat index of all evidence file references
func BuildFileIndex(raw []byte) (map[string]*EvidenceFileRef, error) {
	var inv inventoryRoot
	if err := json.Unmarshal(raw, &inv); err != nil {
		return nil, err
	}

	idx := make(map[string]*EvidenceFileRef, 64)

	// cource-level evidence
	if se := inv.SourceEvidence; se != nil {
		for _, sb := range se.SBOM {
			addFile(idx, sb.Report, "source", "sbom", "report", "")
			for _, a := range sb.Attestations {
				addFile(idx, a, "source", "sbom", "attestation", "")
			}
		}
		for _, sc := range se.Scans {
			for _, rep := range sc.Reports {
				addFile(idx, rep.Report, "source", "scan", "report", "")
				for _, a := range rep.Attestations {
					addFile(idx, a, "source", "scan", "attestation", "")
				}
			}
		}
		for _, lic := range se.License {
			addFile(idx, lic.Report, "source", "license", "report", "")
			for _, a := range lic.Attestations {
				addFile(idx, a, "source", "license", "attestation", "")
			}
		}
	}

	// binqary evidence (per-target)
	for _, t := range inv.Targets {
		platform := t.Platform
		if platform == "" && t.OS != "" {
			platform = t.OS + "/" + t.Arch
		}

		for _, sb := range t.SBOM {
			addFile(idx, sb.Report, "artifact", "sbom", "report", platform)
			for _, a := range sb.Attestations {
				addFile(idx, a, "artifact", "sbom", "attestation", platform)
			}
		}
		for _, sc := range t.Scans {
			for _, rep := range sc.Reports {
				addFile(idx, rep.Report, "artifact", "scan", "report", platform)
				for _, a := range rep.Attestations {
					addFile(idx, a, "artifact", "scan", "attestation", platform)
				}
			}
		}
		for _, lic := range t.License {
			addFile(idx, lic.Report, "artifact", "license", "report", platform)
			for _, a := range lic.Attestations {
				addFile(idx, a, "artifact", "license", "attestation", platform)
			}
		}
	}

	return idx, nil
}

func addFile(idx map[string]*EvidenceFileRef, f inventoryFile, scope, category, kind, platform string) {
	if f.Path == "" {
		return
	}
	idx[f.Path] = &EvidenceFileRef{
		Path:     f.Path,
		SHA256:   f.Hashes["sha256"],
		Size:     f.Size,
		Scope:    scope,
		Category: category,
		Kind:     kind,
		Platform: platform,
	}
}
