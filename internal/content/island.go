// internal/content/island.go
//
// Provenance data-island injection. A content-bundle page ships an empty
// placeholder element:
//
//	<script type="application/json" id="provenance-content-data"></script>
//
// and another for id="provenance-app-data". At bundle-load time the loader
// fills these in-memory with the same JSON served by /api/provenance/content
// and /api/provenance/app, so the provenance is inline and machine-readable
// without a follow-up request to the API.
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
	AppDataIsland(ctx context.Context) ([]byte, error)

	// ContentDataIsland returns the JSON to embed in the content provenance
	// island for the given just-loaded snapshot. It mirrors
	// GET /api/provenance/content
	ContentDataIsland(ctx context.Context, snap *Snapshot) ([]byte, error)
}

// Data-island element IDs, matched against the bundle's HTML at load time.
const (
	contentDataIslandID = "provenance-content-data"
	appDataIslandID     = "provenance-app-data"
)

// islandInjectionCounts reports how many HTML files received each island.
type islandInjectionCounts struct {
	content int
	app     int
}

// inlineProvenance fills the bundle's provenance data islands in place, before
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
		l.logger.Warn(ctx, "build content provenance island failed; leaving placeholder empty", "error", err)
		contentJSON = nil
	}
	appJSON, err := l.inliner.AppDataIsland(ctx)
	if err != nil {
		l.logger.Warn(ctx, "build app provenance island failed; leaving placeholder empty", "error", err)
		appJSON = nil
	}
	if contentJSON == nil && appJSON == nil {
		return
	}

	counts, modified := injectDataIslands(mfs, contentJSON, appJSON)

	// A configured island whose placeholder is in no page
	if contentJSON != nil && counts.content == 0 {
		l.logger.Warn(ctx, "content provenance island placeholder not found in any page", "island_id", contentDataIslandID)
	}
	if appJSON != nil && counts.app == 0 {
		l.logger.Warn(ctx, "app provenance island placeholder not found in any page", "island_id", appDataIslandID)
	}
	if len(modified) > 0 {
		l.logger.Info(ctx, "inlined provenance data islands",
			"content_injections", counts.content,
			"app_injections", counts.app,
			"augmented_files", modified,
		)
	}
}

// injectDataIslands fills the provenance data islands in every HTML file of the
// in-memory bundle. A nil payload skips that island.
func injectDataIslands(mfs fstest.MapFS, contentJSON, appJSON []byte) (counts islandInjectionCounts, modified []string) {
	modified = make([]string, 0, len(mfs))

	for name, file := range mfs {
		if file == nil || !isHTMLFile(name) {
			continue
		}

		data := file.Data
		changed := false

		if contentJSON != nil {
			if out, ok := injectIsland(data, contentDataIslandID, contentJSON); ok {
				data = out
				changed = true
				counts.content++
			}
		}
		if appJSON != nil {
			if out, ok := injectIsland(data, appDataIslandID, appJSON); ok {
				data = out
				changed = true
				counts.app++
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

// injectIsland fills a single empty data-island <script> element identified by
// its id attribute with payload, returning the rewritten HTML and true when an
// update happened.
func injectIsland(html []byte, id string, payload []byte) ([]byte, bool) {
	marker := []byte(`id="` + id + `"`)

	searchFrom := 0
	for {
		rel := bytes.Index(html[searchFrom:], marker)
		if rel < 0 {
			return html, false
		}
		idPos := searchFrom + rel

		// The id must live inside a "<script ...>" open tag: the nearest
		// preceding "<script" with no intervening '>'.
		openStart := bytes.LastIndex(html[:idPos], []byte("<script"))
		if openStart < 0 || bytes.IndexByte(html[openStart:idPos], '>') >= 0 {
			// id is not inside a script open tag - keep looking.
			searchFrom = idPos + len(marker)
			continue
		}

		// End of the open tag. (Assumes no '>' inside attribute values, which
		// holds for the simple quoted placeholder.)
		gtRel := bytes.IndexByte(html[idPos:], '>')
		if gtRel < 0 {
			return html, false
		}
		openEnd := idPos + gtRel // index of '>'

		closeRel := bytes.Index(html[openEnd+1:], []byte("</script>"))
		if closeRel < 0 {
			return html, false
		}
		closeStart := openEnd + 1 + closeRel

		// Idempotent: do not overwrite an already-populated island.
		if len(bytes.TrimSpace(html[openEnd+1:closeStart])) != 0 {
			return html, false
		}

		out := make([]byte, 0, len(html)+len(payload))
		out = append(out, html[:openEnd+1]...)
		out = append(out, payload...)
		out = append(out, html[closeStart:]...)
		return out, true
	}
}

// isHTMLFile reports whether name has an HTML extension. Injection is limited to
// HTML so a coincidental marker substring in a .json/.js asset is never touched.
func isHTMLFile(name string) bool {
	switch strings.ToLower(path.Ext(name)) {
	case ".html", ".htm":
		return true
	default:
		return false
	}
}
