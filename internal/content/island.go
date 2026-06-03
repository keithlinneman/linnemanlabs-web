// internal/content/island.go
//
// Provenance data-island injection. A content-bundle page ships a <script> data
// island whose content is a fixed sentinel string:
//
//	<script type="application/json" id="provenance-content-data">"__PROVENANCE_CONTENT_DATA__"</script>
//
// and another carrying "__PROVENANCE_APP_DATA__". At bundle-load time the loader
// replaces each sentinel in-memory with the JSON served by
// /api/provenance/content and /api/provenance/app, so the provenance is inline
// and machine-readable without a follow-up request to the API.
package content

import (
	"bytes"
	"context"
	"path"
	"sort"
	"strings"
	"testing/fstest"
)

// ProvenanceInliner builds the JSON payloads embedded into a freshly loaded
// bundle's provenance data islands. It is implemented outside this package (by
// the provenancehttp layer, which already imports content) and injected via
// LoaderOptions.Inliner; defining the port here keeps content free of an import
// cycle. Both methods are called at most once per bundle load, on the load
// goroutine, before the snapshot is published to the Manager.
type ProvenanceInliner interface {
	// AppDataIsland returns the JSON to embed in the app provenance island. It
	// mirrors GET /api/provenance/app and is stable for the life of the process
	// (derived from build evidence, not the bundle).
	AppDataIsland(ctx context.Context) ([]byte, error)

	// ContentDataIsland returns the JSON to embed in the content provenance
	// island for the given just-loaded snapshot. It mirrors
	// GET /api/provenance/content. snap is fully populated but not yet published
	// to the Manager.
	ContentDataIsland(ctx context.Context, snap *Snapshot) ([]byte, error)
}

// Data-island
const (
	contentDataIslandID = "provenance-content-data"
	appDataIslandID     = "provenance-app-data"

	contentDataSentinel = `"__PROVENANCE_CONTENT_DATA__"`
	appDataSentinel     = `"__PROVENANCE_APP_DATA__"`
)

// islandInjectionCounts reports how many sentinel occurrences were replaced for
// each island across the bundle.
type islandInjectionCounts struct {
	content int
	app     int
}

// inlineProvenance replaces the bundle's provenance sentinels in place, before
// the snapshot is published to the Manager. It is a no-op when no inliner is
// configured (local/dev builds, tests) or when the FS is not a mutable MapFS.
//
// Race-safety: the freshly extracted MapFS is single-owner on this goroutine
// until Manager.Set stores it in the atomic pointer, so mutating it here is
// race-free; after publish the serve path treats it as read-only.
//
// Provenance note: the two augmented pages intentionally no longer match the
// per-file SHA-256 recorded in the bundle's release.json. The bundle-level
// tarball signature is verified before extraction and is unaffected.
func (l *Loader) inlineProvenance(ctx context.Context, snap *Snapshot) {
	if l.inliner == nil {
		return
	}

	mfs, ok := snap.FS.(fstest.MapFS)
	if !ok {
		l.logger.Warn(ctx, "content FS is not a mutable MapFS; skipping provenance island injection")
		return
	}

	contentJSON, err := l.inliner.ContentDataIsland(ctx, snap)
	if err != nil {
		l.logger.Warn(ctx, "build content provenance island failed; leaving sentinel unreplaced", "error", err)
		contentJSON = nil
	}
	appJSON, err := l.inliner.AppDataIsland(ctx)
	if err != nil {
		l.logger.Warn(ctx, "build app provenance island failed; leaving sentinel unreplaced", "error", err)
		appJSON = nil
	}
	if contentJSON == nil && appJSON == nil {
		return
	}

	counts, modified := injectDataIslands(mfs, contentJSON, appJSON)

	// A configured island whose sentinel appears in no page
	if contentJSON != nil && counts.content == 0 {
		l.logger.Warn(ctx, "content provenance island sentinel not found in any page", "island_id", contentDataIslandID)
	}
	if appJSON != nil && counts.app == 0 {
		l.logger.Warn(ctx, "app provenance island sentinel not found in any page", "island_id", appDataIslandID)
	}
	if len(modified) > 0 {
		l.logger.Info(ctx, "inlined provenance data islands",
			"content_injections", counts.content,
			"app_injections", counts.app,
			"augmented_files", modified,
		)
	}
}

// injectDataIslands replaces each provenance sentinel with its JSON payload in
// every HTML file of the in-memory bundle. A nil payload skips that island.
func injectDataIslands(mfs fstest.MapFS, contentJSON, appJSON []byte) (counts islandInjectionCounts, modified []string) {
	modified = make([]string, 0, len(mfs))
	contentTok := []byte(contentDataSentinel)
	appTok := []byte(appDataSentinel)

	for name, file := range mfs {
		if file == nil || !isHTMLFile(name) {
			continue
		}

		data := file.Data
		changed := false

		if contentJSON != nil {
			if n := bytes.Count(data, contentTok); n > 0 {
				data = bytes.ReplaceAll(data, contentTok, contentJSON)
				counts.content += n
				changed = true
			}
		}
		if appJSON != nil {
			if n := bytes.Count(data, appTok); n > 0 {
				data = bytes.ReplaceAll(data, appTok, appJSON)
				counts.app += n
				changed = true
			}
		}

		if changed {
			file.Data = data
			modified = append(modified, name)
		}
	}

	sort.Strings(modified)
	return counts, modified
}

// isHTMLFile reports whether name has an HTML extension. Injection is limited to
// HTML so a coincidental sentinel substring in a .json/.js asset is never touched.
func isHTMLFile(name string) bool {
	switch strings.ToLower(path.Ext(name)) {
	case ".html", ".htm":
		return true
	default:
		return false
	}
}
