package provenancehttp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/keithlinneman/linnemanlabs-web/internal/content"
	"github.com/keithlinneman/linnemanlabs-web/internal/evidence"
	"github.com/keithlinneman/linnemanlabs-web/internal/log"
	"github.com/keithlinneman/linnemanlabs-web/internal/pathutil"
)

// test stubs

// stubSnapshotProvider implements SnapshotProvider for tests.
type stubSnapshotProvider struct {
	snap *content.Snapshot
	ok   bool
}

func (s *stubSnapshotProvider) Get() (*content.Snapshot, bool) {
	return s.snap, s.ok
}

// noContentProvider returns no content (startup / maintenance).
func noContentProvider() *stubSnapshotProvider {
	return &stubSnapshotProvider{nil, false}
}

// contentProvider returns a minimal content snapshot.
func contentProvider() *stubSnapshotProvider {
	return &stubSnapshotProvider{
		snap: &content.Snapshot{
			Meta: content.Meta{
				Hash:    "abc123def456",
				Source:  content.SourceS3,
				Version: "v1.0.0",
			},
			Provenance: &content.Provenance{
				Version:     "v1.0.0",
				ContentHash: "abc123def456",
				Source: content.ProvenanceSource{
					CommitShort: "abc123",
				},
				CreatedAt: time.Date(2025, 1, 15, 0, 0, 0, 0, time.UTC),
				Summary: content.ProvenanceSummary{
					TotalFiles: 42,
					TotalSize:  1024000,
				},
			},
			LoadedAt: time.Date(2025, 1, 15, 12, 0, 0, 0, time.UTC),
		},
		ok: true,
	}
}

// contentProviderNoProvenance returns content without provenance data.
func contentProviderNoProvenance() *stubSnapshotProvider {
	return &stubSnapshotProvider{
		snap: &content.Snapshot{
			Meta: content.Meta{
				Hash:    "deadbeef",
				Source:  content.SourceS3,
				Version: "v0.9.0",
			},
			Provenance: nil,
			LoadedAt:   time.Date(2025, 1, 15, 12, 0, 0, 0, time.UTC),
		},
		ok: true,
	}
}

// testBundle builds a minimal evidence bundle for testing.
func testBundle() *evidence.Bundle {
	return &evidence.Bundle{
		Release: &evidence.ReleaseManifest{
			ReleaseID: "rel-20250115-abc123",
			Version:   "1.2.3",
			Component: "server",
			Track:     "stable",
			CreatedAt: time.Date(2025, 1, 15, 0, 0, 0, 0, time.UTC),
			Source: evidence.ReleaseSource{
				Repo:           "https://github.com/test/repo",
				ResolvedBranch: "main",
				Commit:         "abc123def456",
				CommitShort:    "abc123",
			},
			Builder: evidence.ReleaseBuilder{
				System:          "github-actions",
				Host:            "runner-vm-abc",
				Actor:           "keithlinneman",
				BuilderIdentity: "arn:aws:sts::1234:assumed-role/app-build/GitHubActions",
				User:            "runner",
				RunID:           "26662693047",
				RunURL:          "https://github.com/keithlinneman/linnemanlabs-web/actions/runs/26662693047",
				Repo:            "https://github.com/test/build",
				Branch:          "main",
				Commit:          "build789",
				CommitShort:     "build78",
			},
		},
		ReleaseRaw:   []byte(`{"release_id":"rel-20250115-abc123"}`),
		InventoryRaw: []byte(`{"files":{}}`),
		Tooling: &evidence.InventoryTooling{
			Go:     &evidence.ToolInfo{Version: "go1.25.10", Category: "toolchain"},
			Cosign: &evidence.ToolInfo{Version: "v3.0.6", Category: "signing-tool"},
			Syft:   &evidence.ToolInfo{Version: "1.44.0", Category: "sbom-generator", Commit: "8cb78ce40ced6a731fb83f2a491a67444f541bf1"},
			CyclonedxGomod: &evidence.ToolInfo{
				Version:  "v1.10.0",
				Category: "sbom-generator",
				Modsum:   "h1:9Vy3zcC+lJLgcR4xYQvwPGU6L2Rij/Ld47lyucYjVI0=",
			},
			Grype: &evidence.ToolInfo{
				Version:  "0.112.0",
				Category: "vuln-scanner",
				DB: &evidence.ToolDB{
					CheckedAt:          time.Date(2026, 5, 29, 7, 42, 4, 0, time.UTC),
					Source:             "https://grype.anchore.io/databases/v6/...",
					UpstreamModifiedAt: time.Date(2026, 5, 29, 0, 53, 54, 0, time.UTC),
				},
			},
			Govulncheck: &evidence.ToolInfo{Version: "v1.1.4", Category: "vuln-scanner"},
			Oras:        &evidence.ToolInfo{Version: "1.3.2", Category: "artifact-uploader"},
			Trivy:       &evidence.ToolInfo{Version: "0.69.3", Category: "vuln-scanner"},
		},
		FileIndex: map[string]*evidence.EvidenceFileRef{
			"source/sbom/report.json": {
				Path:     "source/sbom/report.json",
				SHA256:   "aaa111",
				Size:     500,
				Scope:    "source",
				Category: "sbom",
				Kind:     "report",
			},
			"artifact/scan/attestation.json": {
				Path:     "artifact/scan/attestation.json",
				SHA256:   "bbb222",
				Size:     300,
				Scope:    "artifact",
				Category: "scan",
				Kind:     "attestation",
			},
		},
		Files: map[string]*evidence.EvidenceFile{
			"source/sbom/report.json": {
				Ref: &evidence.EvidenceFileRef{
					Path:     "source/sbom/report.json",
					SHA256:   "aaa111",
					Size:     500,
					Scope:    "source",
					Category: "sbom",
					Kind:     "report",
				},
				Data: []byte(`{"sbom":"data"}`),
			},
			"artifact/scan/attestation.json": {
				Ref: &evidence.EvidenceFileRef{
					Path:     "artifact/scan/attestation.json",
					SHA256:   "bbb222",
					Size:     300,
					Scope:    "artifact",
					Category: "scan",
					Kind:     "attestation",
				},
				Data: []byte(`{"attestation":"data"}`),
			},
		},
		InventoryHash: "inv-hash-abc123",
		FetchedAt:     time.Date(2025, 1, 15, 12, 0, 0, 0, time.UTC),
	}
}

// evidenceStore creates a Store pre-loaded with a bundle.
func evidenceStore() *evidence.Store {
	s := evidence.NewStore()
	s.Set(testBundle())
	return s
}

// emptyEvidenceStore creates a Store with no bundle loaded.
func emptyEvidenceStore() *evidence.Store {
	return evidence.NewStore()
}

// serveWithChi wires up a handler through chi so chi.URLParam works.
func serveWithChi(pattern, method, url string, handler http.HandlerFunc) *httptest.ResponseRecorder { //nolint:unparam // pattern will vary this is re-usable for future tests
	r := chi.NewRouter()
	if method == http.MethodGet {
		r.Get(pattern, handler)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, url, http.NoBody)
	r.ServeHTTP(rec, req)
	return rec
}

// parseJSON is a test helper to decode a JSON response body.
func parseJSON(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("parse JSON: %v\nbody: %s", err, rec.Body.String())
	}
	return m
}

// NewAPI

func TestNewAPI_NilLogger(t *testing.T) {
	api := NewAPI(noContentProvider(), nil, nil)
	if api == nil {
		t.Fatal("NewAPI returned nil")
	}
	if api.logger == nil {
		t.Fatal("logger should default to Nop, not nil")
	}
}

func TestNewAPI_NilEvidence(t *testing.T) {
	api := NewAPI(noContentProvider(), nil, log.Nop())
	if api.evidence != nil {
		t.Fatal("evidence should be nil when not provided")
	}
}

func TestNewAPI_AllFieldsSet(t *testing.T) {
	cp := contentProvider()
	es := evidenceStore()
	api := NewAPI(cp, es, log.Nop())

	if api.content == nil || api.evidence == nil || api.logger == nil {
		t.Fatal("all fields should be set")
	}
}

// RegisterRoutes

func TestRegisterRoutes_AllEndpoints(t *testing.T) {
	api := NewAPI(contentProvider(), evidenceStore(), log.Nop())
	r := chi.NewRouter()
	api.RegisterRoutes(r)

	endpoints := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/provenance/app"},
		{http.MethodGet, "/api/provenance/app/summary"},
		{http.MethodGet, "/api/provenance/content"},
		{http.MethodGet, "/api/provenance/content/summary"},
		{http.MethodGet, "/api/provenance/evidence"},
		{http.MethodGet, "/api/provenance/evidence/release.json"},
		{http.MethodGet, "/api/provenance/evidence/inventory.json"},
		{http.MethodGet, "/api/provenance/evidence/files/source/sbom/report.json"},
	}

	for _, ep := range endpoints {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(ep.method, ep.path, http.NoBody)
		r.ServeHTTP(rec, req)

		if rec.Code == http.StatusNotFound || rec.Code == http.StatusMethodNotAllowed {
			t.Errorf("%s %s: got %d, route not registered", ep.method, ep.path, rec.Code)
		}
	}
}

// writeJSON

func TestWriteJSON_ContentType(t *testing.T) {
	api := NewAPI(noContentProvider(), nil, log.Nop())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	api.HandleAppProvenance(rec, req)

	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
}

func TestWriteJSON_CacheControl(t *testing.T) {
	api := NewAPI(noContentProvider(), nil, log.Nop())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	api.HandleAppProvenance(rec, req)

	cc := rec.Header().Get("Cache-Control")
	if cc != "no-cache" {
		t.Fatalf("Cache-Control = %q, want no-cache", cc)
	}
}

// HandleAppProvenance

func TestHandleAppProvenance_NoEvidence(t *testing.T) {
	api := NewAPI(noContentProvider(), nil, log.Nop())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/provenance/app", http.NoBody)
	api.HandleAppProvenance(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	m := parseJSON(t, rec)
	if m["_links"] == nil {
		t.Fatal("_links should always be present")
	}
	if m["release"] != nil {
		t.Fatal("release should be nil without evidence")
	}
}

func TestHandleAppProvenance_EmptyStore(t *testing.T) {
	api := NewAPI(noContentProvider(), emptyEvidenceStore(), log.Nop())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/provenance/app", http.NoBody)
	api.HandleAppProvenance(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}

	m := parseJSON(t, rec)
	if m["release"] != nil {
		t.Fatal("release should be nil when store is empty")
	}
}

func TestHandleAppProvenance_WithEvidence(t *testing.T) {
	api := NewAPI(noContentProvider(), evidenceStore(), log.Nop())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/provenance/app", http.NoBody)
	api.HandleAppProvenance(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}

	m := parseJSON(t, rec)
	if m["release"] == nil {
		t.Fatal("release should be present with evidence")
	}
	if m["evidence"] == nil {
		t.Fatal("evidence section should be present")
	}
}

func TestHandleAppProvenance_AlwaysHasLinks(t *testing.T) {
	// Even with no evidence, links should be present for API discoverability
	api := NewAPI(noContentProvider(), nil, log.Nop())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/provenance/app", http.NoBody)
	api.HandleAppProvenance(rec, req)

	m := parseJSON(t, rec)
	links, ok := m["_links"].(map[string]any)
	if !ok {
		t.Fatal("_links should be a map")
	}

	required := []string{"summary", "evidence", "release", "inventory", "content"}
	for _, key := range required {
		if links[key] == nil {
			t.Errorf("_links missing %q", key)
		}
	}
}

func TestHandleAppProvenance_BuildInfoPresent(t *testing.T) {
	api := NewAPI(noContentProvider(), nil, log.Nop())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/provenance/app", http.NoBody)
	api.HandleAppProvenance(rec, req)

	m := parseJSON(t, rec)
	if m["build"] == nil {
		t.Fatal("build info should always be present")
	}
}

// HandleAppSummary

func TestHandleAppSummary_NoEvidence(t *testing.T) {
	api := NewAPI(noContentProvider(), nil, log.Nop())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/provenance/app/summary", http.NoBody)
	api.HandleAppSummary(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}

	m := parseJSON(t, rec)
	if m["has_evidence"] != false {
		t.Fatal("has_evidence should be false")
	}
	if m["error"] == nil || m["error"] == "" {
		t.Fatal("error message should be present")
	}
}

func TestHandleAppSummary_EmptyStore(t *testing.T) {
	api := NewAPI(noContentProvider(), emptyEvidenceStore(), log.Nop())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/provenance/app/summary", http.NoBody)
	api.HandleAppSummary(rec, req)

	m := parseJSON(t, rec)
	if m["has_evidence"] != false {
		t.Fatal("has_evidence should be false for empty store")
	}
}

func TestHandleAppSummary_WithEvidence(t *testing.T) {
	api := NewAPI(noContentProvider(), evidenceStore(), log.Nop())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/provenance/app/summary", http.NoBody)
	api.HandleAppSummary(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}

	m := parseJSON(t, rec)
	if m["has_evidence"] != true {
		t.Fatal("has_evidence should be true")
	}
	if m["version"] != "1.2.3" {
		t.Fatalf("version = %v", m["version"])
	}
	if m["release_id"] != "rel-20250115-abc123" {
		t.Fatalf("release_id = %v", m["release_id"])
	}
}

func TestHandleAppSummary_BuilderHasBuildAttribution(t *testing.T) {
	api := NewAPI(noContentProvider(), evidenceStore(), log.Nop())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/provenance/app/summary", http.NoBody)
	api.HandleAppSummary(rec, req)

	m := parseJSON(t, rec)
	builder, ok := m["builder"].(map[string]any)
	if !ok {
		t.Fatalf("response missing builder block: %v", m)
	}
	// build environment + attribution fields from release.json's enriched
	// builder block now surface on the summary instead of as top-level fields.
	for _, k := range []string{"system", "actor", "builder_identity", "user", "run_id", "run_url", "host"} {
		if builder[k] == nil || builder[k] == "" {
			t.Fatalf("builder.%s missing or empty: %v", k, builder[k])
		}
	}
	if builder["system"] != "github-actions" {
		t.Fatalf("builder.system = %v", builder["system"])
	}
	if builder["run_id"] != "26662693047" {
		t.Fatalf("builder.run_id = %v", builder["run_id"])
	}
	// build-system source repo state is still in the same block.
	if builder["repository"] != "https://github.com/test/build" {
		t.Fatalf("builder.repository = %v", builder["repository"])
	}
	// scattered top-level fields are dropped - they're all in builder now.
	for _, k := range []string{"build_actor", "build_system", "build_run_url", "builder_identity"} {
		if _, present := m[k]; present {
			t.Fatalf("%s should not be present at top level: %v", k, m[k])
		}
	}
}

func TestHandleAppSummary_IncludesTooling(t *testing.T) {
	api := NewAPI(noContentProvider(), evidenceStore(), log.Nop())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/provenance/app/summary", http.NoBody)
	api.HandleAppSummary(rec, req)

	m := parseJSON(t, rec)
	tooling, ok := m["tooling"].(map[string]any)
	if !ok {
		t.Fatalf("response missing tooling block: %v", m)
	}
	// every tool from inventory.json surfaces with version+category
	cases := []struct {
		key, version, category string
	}{
		{"go", "go1.25.10", "toolchain"},
		{"cosign", "v3.0.6", "signing-tool"},
		{"syft", "1.44.0", "sbom-generator"},
		{"cyclonedx_gomod", "v1.10.0", "sbom-generator"},
		{"grype", "0.112.0", "vuln-scanner"},
		{"govulncheck", "v1.1.4", "vuln-scanner"},
		{"oras", "1.3.2", "artifact-uploader"},
		{"trivy", "0.69.3", "vuln-scanner"},
	}
	for _, c := range cases {
		tool, ok := tooling[c.key].(map[string]any)
		if !ok {
			t.Fatalf("tooling.%s missing: %v", c.key, tooling)
		}
		if tool["version"] != c.version {
			t.Fatalf("tooling.%s.version = %v, want %v", c.key, tool["version"], c.version)
		}
		if tool["category"] != c.category {
			t.Fatalf("tooling.%s.category = %v, want %v", c.key, tool["category"], c.category)
		}
	}

	// richer per-tool fields surface where present
	syft, _ := tooling["syft"].(map[string]any)
	if syft["commit"] != "8cb78ce40ced6a731fb83f2a491a67444f541bf1" {
		t.Fatalf("tooling.syft.commit = %v", syft["commit"])
	}
	cdx, _ := tooling["cyclonedx_gomod"].(map[string]any)
	if cdx["modsum"] != "h1:9Vy3zcC+lJLgcR4xYQvwPGU6L2Rij/Ld47lyucYjVI0=" {
		t.Fatalf("tooling.cyclonedx_gomod.modsum = %v", cdx["modsum"])
	}
	grype, _ := tooling["grype"].(map[string]any)
	db, ok := grype["db"].(map[string]any)
	if !ok {
		t.Fatalf("tooling.grype.db missing: %v", grype)
	}
	if db["source"] != "https://grype.anchore.io/databases/v6/..." {
		t.Fatalf("tooling.grype.db.source = %v", db["source"])
	}
}

func TestHandleAppProvenance_IncludesTooling(t *testing.T) {
	api := NewAPI(noContentProvider(), evidenceStore(), log.Nop())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/provenance/app", http.NoBody)
	api.HandleAppProvenance(rec, req)

	m := parseJSON(t, rec)
	tooling, ok := m["tooling"].(map[string]any)
	if !ok {
		t.Fatalf("response missing top-level tooling block: %v", m)
	}
	goTool, ok := tooling["go"].(map[string]any)
	if !ok {
		t.Fatalf("tooling.go missing: %v", tooling)
	}
	if goTool["version"] != "go1.25.10" {
		t.Fatalf("tooling.go.version = %v", goTool["version"])
	}
	if goTool["category"] != "toolchain" {
		t.Fatalf("tooling.go.category = %v", goTool["category"])
	}
}

func TestHandleAppSummary_AlwaysHasLinks(t *testing.T) {
	api := NewAPI(noContentProvider(), nil, log.Nop())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/provenance/app/summary", http.NoBody)
	api.HandleAppSummary(rec, req)

	m := parseJSON(t, rec)
	if m["_links"] == nil {
		t.Fatal("_links should always be present")
	}
}

// HandleContentProvenance

func TestHandleContentProvenance_NoContent(t *testing.T) {
	api := NewAPI(noContentProvider(), nil, log.Nop())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/provenance/content", http.NoBody)
	api.HandleContentProvenance(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}

	m := parseJSON(t, rec)
	if m["error"] == nil || m["error"] == "" {
		t.Fatal("error should be set")
	}
}

func TestHandleContentProvenance_WithContent(t *testing.T) {
	api := NewAPI(contentProvider(), nil, log.Nop())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/provenance/content", http.NoBody)
	api.HandleContentProvenance(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}

	m := parseJSON(t, rec)
	if m["bundle"] == nil {
		t.Fatal("bundle should be present")
	}
	rt := m["runtime"].(map[string]any)
	if rt["hash"] != "abc123def456" {
		t.Fatalf("hash = %v", rt["hash"])
	}
}

func TestHandleContentProvenance_NoProvenance(t *testing.T) {
	api := NewAPI(contentProviderNoProvenance(), nil, log.Nop())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/provenance/content", http.NoBody)
	api.HandleContentProvenance(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}

	m := parseJSON(t, rec)
	if m["error"] == nil || m["error"] == "" {
		t.Fatal("error should indicate provenance not available")
	}
}

// HandleContentSummary

func TestHandleContentSummary_NoContent(t *testing.T) {
	api := NewAPI(noContentProvider(), nil, log.Nop())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/provenance/content/summary", http.NoBody)
	api.HandleContentSummary(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

func TestHandleContentSummary_WithProvenance(t *testing.T) {
	api := NewAPI(contentProvider(), nil, log.Nop())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/provenance/content/summary", http.NoBody)
	api.HandleContentSummary(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}

	m := parseJSON(t, rec)
	if m["version"] != "v1.0.0" {
		t.Fatalf("version = %v", m["version"])
	}
	if m["content_hash"] != "abc123def456" {
		t.Fatalf("content_hash = %v", m["content_hash"])
	}
	if m["commit_short"] != "abc123" {
		t.Fatalf("commit_short = %v", m["commit_short"])
	}
}

func TestHandleContentSummary_IncludesBuildAndTooling(t *testing.T) {
	cp := &stubSnapshotProvider{
		snap: &content.Snapshot{
			Meta: content.Meta{Hash: "abc", Source: content.SourceS3},
			Provenance: &content.Provenance{
				Version: "v1.2.3",
				Build: content.ProvenanceBuild{
					System:          "github-actions",
					Actor:           "keithlinneman",
					BuilderIdentity: "arn:aws:sts::1234:assumed-role/app-content/GitHubActions",
					Host:            "runnervm3jyl0",
					User:            "runner",
					RunID:           "26598160229",
					RunURL:          "https://github.com/keithlinneman/linnemanlabs-site/actions/runs/26598160229",
				},
				Tooling: content.ProvenanceTooling{
					Hugo: &content.ToolInfo{Version: "v0.160.1", SHA256: "38b179a7"},
					Git:  &content.ToolInfo{Version: "2.54.0", SHA256: "f54a87f6"},
					Bash: &content.ToolInfo{Version: "5.2.21", SHA256: "bc5945fe"},
				},
			},
			LoadedAt: time.Date(2026, 5, 28, 19, 46, 20, 0, time.UTC),
		},
		ok: true,
	}
	api := NewAPI(cp, nil, log.Nop())

	rec := httptest.NewRecorder()
	api.HandleContentSummary(rec, httptest.NewRequest(http.MethodGet, "/api/provenance/content/summary", http.NoBody))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	m := parseJSON(t, rec)

	build, ok := m["build"].(map[string]any)
	if !ok {
		t.Fatalf("response missing build block: %v", m)
	}
	if build["system"] != "github-actions" {
		t.Fatalf("build.system = %v", build["system"])
	}
	if build["actor"] != "keithlinneman" {
		t.Fatalf("build.actor = %v", build["actor"])
	}
	if build["run_id"] != "26598160229" {
		t.Fatalf("build.run_id = %v", build["run_id"])
	}

	tooling, ok := m["tooling"].(map[string]any)
	if !ok {
		t.Fatalf("response missing tooling block: %v", m)
	}
	hugo, _ := tooling["hugo"].(map[string]any)
	if hugo == nil || hugo["version"] != "v0.160.1" {
		t.Fatalf("tooling.hugo = %v", tooling["hugo"])
	}
	if _, ok := tooling["git"].(map[string]any); !ok {
		t.Fatalf("tooling.git missing: %v", tooling)
	}
	if _, ok := tooling["bash"].(map[string]any); !ok {
		t.Fatalf("tooling.bash missing: %v", tooling)
	}
}

func TestHandleContentSummary_NoProvenance_Fallback(t *testing.T) {
	api := NewAPI(contentProviderNoProvenance(), nil, log.Nop())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/provenance/content/summary", http.NoBody)
	api.HandleContentSummary(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}

	m := parseJSON(t, rec)
	// Falls back to Meta fields
	if m["version"] != "v0.9.0" {
		t.Fatalf("version = %v, want v0.9.0 (fallback)", m["version"])
	}
	if m["content_hash"] != "deadbeef" {
		t.Fatalf("content_hash = %v, want deadbeef (fallback)", m["content_hash"])
	}
}

// HandleEvidenceManifest

func TestHandleEvidenceManifest_NoEvidence(t *testing.T) {
	api := NewAPI(noContentProvider(), nil, log.Nop())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/provenance/evidence", http.NoBody)
	api.HandleEvidenceManifest(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}

	m := parseJSON(t, rec)
	if m["available"] != false {
		t.Fatal("available should be false")
	}
}

func TestHandleEvidenceManifest_EmptyStore(t *testing.T) {
	api := NewAPI(noContentProvider(), emptyEvidenceStore(), log.Nop())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/provenance/evidence", http.NoBody)
	api.HandleEvidenceManifest(rec, req)

	m := parseJSON(t, rec)
	if m["available"] != false {
		t.Fatal("available should be false for empty store")
	}
}

func TestHandleEvidenceManifest_WithEvidence(t *testing.T) {
	api := NewAPI(noContentProvider(), evidenceStore(), log.Nop())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/provenance/evidence", http.NoBody)
	api.HandleEvidenceManifest(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}

	m := parseJSON(t, rec)
	if m["available"] != true {
		t.Fatal("available should be true")
	}
	if m["release_id"] != "rel-20250115-abc123" {
		t.Fatalf("release_id = %v", m["release_id"])
	}
	if m["_links"] == nil {
		t.Fatal("_links should be present")
	}
}

// HandleReleaseJSON

func TestHandleReleaseJSON_NoEvidence(t *testing.T) {
	api := NewAPI(noContentProvider(), nil, log.Nop())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/provenance/evidence/release.json", http.NoBody)
	api.HandleReleaseJSON(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestHandleReleaseJSON_EmptyStore(t *testing.T) {
	api := NewAPI(noContentProvider(), emptyEvidenceStore(), log.Nop())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/provenance/evidence/release.json", http.NoBody)
	api.HandleReleaseJSON(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestHandleReleaseJSON_WithEvidence(t *testing.T) {
	api := NewAPI(noContentProvider(), evidenceStore(), log.Nop())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/provenance/evidence/release.json", http.NoBody)
	api.HandleReleaseJSON(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}

	if !strings.Contains(rec.Body.String(), "rel-20250115-abc123") {
		t.Fatal("body should contain release ID")
	}
}

func TestHandleReleaseJSON_CacheHeaders(t *testing.T) {
	api := NewAPI(noContentProvider(), evidenceStore(), log.Nop())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/provenance/evidence/release.json", http.NoBody)
	api.HandleReleaseJSON(rec, req)

	cc := rec.Header().Get("Cache-Control")
	if !strings.Contains(cc, "immutable") {
		t.Fatalf("Cache-Control = %q, want immutable", cc)
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Fatalf("Content-Type = %q", ct)
	}
}

// HandleInventoryJSON

func TestHandleInventoryJSON_NoEvidence(t *testing.T) {
	api := NewAPI(noContentProvider(), nil, log.Nop())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/provenance/evidence/inventory.json", http.NoBody)
	api.HandleInventoryJSON(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestHandleInventoryJSON_WithEvidence(t *testing.T) {
	api := NewAPI(noContentProvider(), evidenceStore(), log.Nop())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/provenance/evidence/inventory.json", http.NoBody)
	api.HandleInventoryJSON(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}

	if !strings.Contains(rec.Body.String(), "files") {
		t.Fatal("body should contain inventory data")
	}
}

func TestHandleInventoryJSON_CacheHeaders(t *testing.T) {
	api := NewAPI(noContentProvider(), evidenceStore(), log.Nop())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/provenance/evidence/inventory.json", http.NoBody)
	api.HandleInventoryJSON(rec, req)

	cc := rec.Header().Get("Cache-Control")
	if !strings.Contains(cc, "immutable") {
		t.Fatalf("Cache-Control = %q, want immutable", cc)
	}
}

// HandleEvidenceFile - functional

func TestHandleEvidenceFile_ValidReport(t *testing.T) {
	api := NewAPI(noContentProvider(), evidenceStore(), log.Nop())

	rec := serveWithChi(
		"/api/provenance/evidence/files/*",
		http.MethodGet,
		"/api/provenance/evidence/files/source/sbom/report.json",
		api.HandleEvidenceFile,
	)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}

	if !strings.Contains(rec.Body.String(), "sbom") {
		t.Fatal("body should contain SBOM data")
	}
}

func TestHandleEvidenceFile_Attestation_ContentType(t *testing.T) {
	api := NewAPI(noContentProvider(), evidenceStore(), log.Nop())

	rec := serveWithChi(
		"/api/provenance/evidence/files/*",
		http.MethodGet,
		"/api/provenance/evidence/files/artifact/scan/attestation.json",
		api.HandleEvidenceFile,
	)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}

	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/vnd.in-toto+json") {
		t.Fatalf("Content-Type = %q, want in-toto for attestations", ct)
	}
}

func TestHandleEvidenceFile_CacheHeaders(t *testing.T) {
	api := NewAPI(noContentProvider(), evidenceStore(), log.Nop())

	rec := serveWithChi(
		"/api/provenance/evidence/files/*",
		http.MethodGet,
		"/api/provenance/evidence/files/source/sbom/report.json",
		api.HandleEvidenceFile,
	)

	cc := rec.Header().Get("Cache-Control")
	if !strings.Contains(cc, "immutable") {
		t.Fatalf("Cache-Control = %q, want immutable", cc)
	}
}

func TestHandleEvidenceFile_NotFound(t *testing.T) {
	api := NewAPI(noContentProvider(), evidenceStore(), log.Nop())

	rec := serveWithChi(
		"/api/provenance/evidence/files/*",
		http.MethodGet,
		"/api/provenance/evidence/files/nonexistent/path.json",
		api.HandleEvidenceFile,
	)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestHandleEvidenceFile_NoEvidence(t *testing.T) {
	api := NewAPI(noContentProvider(), nil, log.Nop())

	rec := serveWithChi(
		"/api/provenance/evidence/files/*",
		http.MethodGet,
		"/api/provenance/evidence/files/anything",
		api.HandleEvidenceFile,
	)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestHandleEvidenceFile_EmptyPath(t *testing.T) {
	api := NewAPI(noContentProvider(), evidenceStore(), log.Nop())

	// chi wildcard with empty match
	rec := serveWithChi(
		"/api/provenance/evidence/files/*",
		http.MethodGet,
		"/api/provenance/evidence/files/",
		api.HandleEvidenceFile,
	)

	// Empty path → 400 or 404 depending on chi behavior
	if rec.Code == http.StatusOK {
		t.Fatal("empty file path should not return 200")
	}
}

func TestHandleEvidenceFile_KnownButNotLoaded(t *testing.T) {
	// Build a store where a file is in the index but not in Files
	s := evidence.NewStore()
	b := testBundle()
	b.FileIndex["missing/file.json"] = &evidence.EvidenceFileRef{
		Path:     "missing/file.json",
		SHA256:   "ccc333",
		Size:     100,
		Scope:    "source",
		Category: "scan",
		Kind:     "report",
	}
	// Don't add to b.Files - simulates a fetch failure at startup
	s.Set(b)

	api := NewAPI(noContentProvider(), s, log.Nop())

	rec := serveWithChi(
		"/api/provenance/evidence/files/*",
		http.MethodGet,
		"/api/provenance/evidence/files/missing/file.json",
		api.HandleEvidenceFile,
	)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 for known-but-not-loaded", rec.Code)
	}

	if !strings.Contains(rec.Body.String(), "not loaded") {
		t.Fatalf("body should explain fetch failure, got: %s", rec.Body.String())
	}
}

// HandleEvidenceFile - SECURITY: path traversal

func TestHandleEvidenceFile_Security_DotDot(t *testing.T) {
	api := NewAPI(noContentProvider(), evidenceStore(), log.Nop())

	payloads := []string{
		"/api/provenance/evidence/files/../../../etc/passwd",
		"/api/provenance/evidence/files/source/../../../etc/shadow",
		"/api/provenance/evidence/files/..%2F..%2Fetc/passwd",
	}

	for _, url := range payloads {
		rec := serveWithChi(
			"/api/provenance/evidence/files/*",
			http.MethodGet,
			url,
			api.HandleEvidenceFile,
		)

		if rec.Code == http.StatusOK {
			t.Fatalf("path traversal should not return 200: %s", url)
		}
	}
}

func TestHandleEvidenceFile_Security_NullByte(t *testing.T) {
	// Go's net/http stack rejects URLs containing null bytes and other
	// control characters before they reach any handler. httptest.NewRequest
	// panics on such URLs. This means null byte injection is blocked at
	// the transport layer - our strings.Contains(filePath, "\x00") guard
	// is defense-in-depth that can't be reached through normal HTTP.
	t.Log("null bytes blocked by Go HTTP stack before reaching handler")
}

func TestHandleEvidenceFile_Security_Backslash(t *testing.T) {
	api := NewAPI(noContentProvider(), evidenceStore(), log.Nop())

	rec := serveWithChi(
		"/api/provenance/evidence/files/*",
		http.MethodGet,
		"/api/provenance/evidence/files/source\\sbom\\report.json",
		api.HandleEvidenceFile,
	)

	if rec.Code == http.StatusOK {
		t.Fatal("backslash in path should not return 200")
	}
}

func TestHandleEvidenceFile_Security_DotSegments(t *testing.T) {
	api := NewAPI(noContentProvider(), evidenceStore(), log.Nop())

	payloads := []string{
		"/api/provenance/evidence/files/./source/sbom/report.json",
		"/api/provenance/evidence/files/source/./sbom/report.json",
	}

	for _, url := range payloads {
		rec := serveWithChi(
			"/api/provenance/evidence/files/*",
			http.MethodGet,
			url,
			api.HandleEvidenceFile,
		)

		if rec.Code == http.StatusOK {
			t.Fatalf("dot segment should not return 200: %s", url)
		}
	}
}

func TestHandleEvidenceFile_Security_UniformErrorMessage(t *testing.T) {
	// Blocked paths should return the same generic "not found" message
	// to avoid leaking information about which filter caught the request
	api := NewAPI(noContentProvider(), evidenceStore(), log.Nop())

	blockedPaths := []string{
		"/api/provenance/evidence/files/../../../etc/passwd",
		"/api/provenance/evidence/files/source\\sbom",
		"/api/provenance/evidence/files/./hidden",
	}

	for _, url := range blockedPaths {
		rec := serveWithChi(
			"/api/provenance/evidence/files/*",
			http.MethodGet,
			url,
			api.HandleEvidenceFile,
		)

		body := rec.Body.String()
		if rec.Code != http.StatusNotFound {
			// chi may normalize some of these before they reach the handler
			continue
		}
		if !strings.Contains(body, "not found") {
			t.Errorf("blocked path %q should return generic 'not found', got: %s", url, body)
		}
	}
}

// buildAppSummarySource

func TestBuildAppSummarySource_Nil(t *testing.T) {
	out := buildAppSummarySource(nil)
	if out != nil {
		t.Fatal("should return nil for nil input")
	}
}

func TestBuildAppSummarySource_TagBuild(t *testing.T) {
	src := &evidence.ReleaseSource{
		Repo:           "https://github.com/test/repo",
		ResolvedBranch: "unknown",
		Commit:         "abc123",
		CommitShort:    "abc12",
		BaseTag:        "v1.0.0",
	}

	out := buildAppSummarySource(src)

	if out.Tag != "v1.0.0" {
		t.Fatalf("tag = %q, want v1.0.0", out.Tag)
	}
	if out.Branch != "" {
		t.Fatalf("branch = %q, want empty (unknown filtered)", out.Branch)
	}
}

func TestBuildAppSummarySource_BranchBuild(t *testing.T) {
	src := &evidence.ReleaseSource{
		Repo:           "https://github.com/test/repo",
		ResolvedBranch: "main",
		Commit:         "abc123",
		CommitShort:    "abc12",
	}

	out := buildAppSummarySource(src)

	if out.Branch != "main" {
		t.Fatalf("branch = %q, want main", out.Branch)
	}
}

// appSummaryLinks

func TestAppSummaryLinks(t *testing.T) {
	links := appSummaryLinks()

	required := []string{"full", "evidence", "release", "inventory", "content"}
	for _, key := range required {
		if links[key] == "" {
			t.Errorf("appSummaryLinks missing %q", key)
		}
	}
}

// Integration: full router round-trip

func TestIntegration_FullRouter(t *testing.T) {
	api := NewAPI(contentProvider(), evidenceStore(), log.Nop())
	r := chi.NewRouter()
	api.RegisterRoutes(r)

	// Every endpoint should return valid JSON (except evidence files which are raw)
	jsonEndpoints := []string{
		"/api/provenance/app",
		"/api/provenance/app/summary",
		"/api/provenance/content",
		"/api/provenance/content/summary",
		"/api/provenance/evidence",
	}

	for _, path := range jsonEndpoints {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, http.NoBody)
		r.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("%s: status = %d, want 200", path, rec.Code)
			continue
		}

		ct := rec.Header().Get("Content-Type")
		if !strings.Contains(ct, "application/json") {
			t.Errorf("%s: Content-Type = %q", path, ct)
		}

		var m map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
			t.Errorf("%s: invalid JSON: %v", path, err)
		}
	}
}

func TestIntegration_EvidenceFileViaRouter(t *testing.T) {
	api := NewAPI(noContentProvider(), evidenceStore(), log.Nop())
	r := chi.NewRouter()
	api.RegisterRoutes(r)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/provenance/evidence/files/source/sbom/report.json", http.NoBody)
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}

	if !strings.Contains(rec.Body.String(), "sbom") {
		t.Fatal("body should contain SBOM data")
	}
}

func FuzzEvidenceFilePath(f *testing.F) {
	seeds := []string{
		"../../../etc/passwd", "foo\x00bar.json",
		"valid/sbom.json", "..\\windows\\system32",
		"foo/../bar.json", "./hidden", "foo/./bar",
		"source/sbom/report.json", // known-good path in testBundle
		"", ".", "..", "/", "//", "///",
		"a/b/c/d/e", "normal.json",
		"\t", "\n", " ", "%00",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	store := evidenceStore()
	api := NewAPI(noContentProvider(), store, log.Nop())

	r := chi.NewRouter()
	r.Get("/api/provenance/evidence/files/*", api.HandleEvidenceFile)

	f.Fuzz(func(t *testing.T, filePath string) {
		hasNull := strings.Contains(filePath, "\x00")
		hasBackslash := strings.Contains(filePath, "\\")
		hasDotDot := strings.Contains(filePath, "..")
		hasDots := pathutil.HasDotSegments(filePath)

		// Build URL safely - net/http rejects control chars, so percent-encode
		// the path to get it through the HTTP layer into chi
		safePath := "/api/provenance/evidence/files/" + filePath

		// If the URL itself is invalid (control chars), Go blocks it at the
		// transport layer. That's fine - attacker can't reach us either.
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, safePath, http.NoBody)
		if err != nil {
			return // Go rejected the URL - transport-layer protection, not our problem
		}

		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)

		// INVARIANT: dangerous patterns must NEVER return 200
		if hasNull || hasBackslash || hasDotDot || hasDots {
			if rec.Code == http.StatusOK {
				t.Fatalf("dangerous path returned 200: %q (null=%v backslash=%v dotdot=%v dots=%v)",
					filePath, hasNull, hasBackslash, hasDotDot, hasDots)
			}
		}

		// INVARIANT: any 200 response must serve data from a known file in the store
		if rec.Code == http.StatusOK {
			_, inFiles := store.File(filePath)
			if !inFiles {
				t.Fatalf("200 for path not in evidence store: %q", filePath)
			}
		}
	})
}
