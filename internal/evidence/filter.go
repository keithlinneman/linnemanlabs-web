package evidence

import (
	"encoding/json"
	"runtime"
)

// RuntimePlatform returns the current platform as "os/arch" ("linux/arm64")
func RuntimePlatform() string {
	return runtime.GOOS + "/" + runtime.GOARCH
}

// FilterBundleByPlatform parses bundle and removes entries for other platforms than we are running on and rewrites inventory/release JSON blobs accordingly
func FilterBundleByPlatform(b *Bundle, platform string) *Bundle {
	if b == nil || platform == "" {
		return b
	}

	// filter FileIndex and Files maps
	newIndex := make(map[string]*EvidenceFileRef, len(b.FileIndex))
	newFiles := make(map[string]*EvidenceFile, len(b.Files))

	for path, ref := range b.FileIndex {
		if ref.Platform == "" || ref.Platform == platform {
			newIndex[path] = ref
			if f, ok := b.Files[path]; ok {
				newFiles[path] = f
			}
		}
	}

	// filter Release.Artifacts to matching os/arch
	var filteredRelease *ReleaseManifest
	if b.Release != nil {
		cp := *b.Release
		kept := make([]ReleaseArtifact, 0, 1)
		for _, a := range cp.Artifacts {
			if a.OS+"/"+a.Arch == platform {
				kept = append(kept, a)
			}
		}
		cp.Artifacts = kept
		filteredRelease = &cp
	}

	// rewrite ReleaseRaw
	newReleaseRaw := filterReleaseRaw(b.ReleaseRaw, platform)
	if newReleaseRaw == nil {
		newReleaseRaw = b.ReleaseRaw
	}

	// rewrite InventoryRaw
	newInventoryRaw := filterInventoryRaw(b.InventoryRaw, platform)
	if newInventoryRaw == nil {
		newInventoryRaw = b.InventoryRaw
	}

	return &Bundle{
		Release:               filteredRelease,
		ReleaseRaw:            newReleaseRaw,
		ReleaseSigstoreBundle: b.ReleaseSigstoreBundle,
		InventoryRaw:          newInventoryRaw,
		InventoryHash:         b.InventoryHash,
		FileIndex:             newIndex,
		Files:                 newFiles,
		Bucket:                b.Bucket,
		ReleasePrefix:         b.ReleasePrefix,
		FetchedAt:             b.FetchedAt,
	}
}

// filterReleaseRaw rewrites the "artifacts" array in release.json to keep
// only entries matching the given os/arch. All other fields are preserved
func filterReleaseRaw(raw []byte, platform string) []byte {
	if len(raw) == 0 {
		return nil
	}

	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil
	}

	artsRaw, ok := doc["artifacts"]
	if !ok {
		return raw
	}

	var arts []struct {
		OS   string          `json:"os"`
		Arch string          `json:"arch"`
		Rest json.RawMessage `json:"-"`
	}
	// re-parse as generic to preserve all fields
	var artsGeneric []json.RawMessage
	if err := json.Unmarshal(artsRaw, &artsGeneric); err != nil {
		return nil
	}
	if err := json.Unmarshal(artsRaw, &arts); err != nil {
		return nil
	}

	kept := make([]json.RawMessage, 0, 1)
	for i, a := range arts {
		if a.OS+"/"+a.Arch == platform {
			kept = append(kept, artsGeneric[i])
		}
	}

	newArts, err := json.Marshal(kept)
	if err != nil {
		return nil
	}
	doc["artifacts"] = newArts

	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil
	}
	return out
}

// filterInventoryRaw rewrites inventory.json to keep only source-scoped
// entries and artifact entries matching the given platform. It also filters
// the "targets" array to only the matching platform
func filterInventoryRaw(raw []byte, platform string) []byte {
	if len(raw) == 0 {
		return nil
	}

	// parse just enough structure to filter, preserve everything else
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil
	}

	// filter "targets" array if present
	if targetsRaw, ok := doc["targets"]; ok {
		var targets []json.RawMessage
		if err := json.Unmarshal(targetsRaw, &targets); err == nil {
			kept := make([]json.RawMessage, 0, 1)
			for _, t := range targets {
				var meta struct {
					Platform string `json:"platform"`
					OS       string `json:"os"`
					Arch     string `json:"arch"`
				}
				if err := json.Unmarshal(t, &meta); err != nil {
					continue
				}
				p := meta.Platform
				if p == "" && meta.OS != "" {
					p = meta.OS + "/" + meta.Arch
				}
				if p == platform {
					kept = append(kept, t)
				}
			}
			newTargets, err := json.Marshal(kept)
			if err == nil {
				doc["targets"] = newTargets
			}
		}
	}

	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil
	}
	return out
}
