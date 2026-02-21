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

func BuildFileIndex(raw []byte) (map[string]*EvidenceFileRef, error) {
	var inv inventoryRoot
	if err := json.Unmarshal(raw, &inv); err != nil {
		return nil, err
	}

	idx := make(map[string]*EvidenceFileRef, 64)

	if se := inv.SourceEvidence; se != nil {
		indexEvidence(idx, se.SBOM, se.Scans, se.License, "source", "")
	}

	for i := range inv.Targets {
		t := &inv.Targets[i]
		platform := t.Platform
		if platform == "" && t.OS != "" {
			platform = t.OS + "/" + t.Arch
		}
		indexEvidence(idx, t.SBOM, t.Scans, t.License, "artifact", platform)
	}

	return idx, nil
}

func indexEvidence(idx map[string]*EvidenceFileRef, sboms []sbomEntry, scans []scanEntry, licenses []licenseEntry, category, platform string) {
	for _, sb := range sboms {
		addFile(idx, sb.Report, category, "sbom", "report", platform)
		for _, a := range sb.Attestations {
			addFile(idx, a, category, "sbom", "attestation", platform)
		}
	}
	for _, sc := range scans {
		for _, rep := range sc.Reports {
			addFile(idx, rep.Report, category, "scan", "report", platform)
			for _, a := range rep.Attestations {
				addFile(idx, a, category, "scan", "attestation", platform)
			}
		}
	}
	for _, lic := range licenses {
		addFile(idx, lic.Report, category, "license", "report", platform)
		for _, a := range lic.Attestations {
			addFile(idx, a, category, "license", "attestation", platform)
		}
	}
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
