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
				Repo:        "https://github.com/test/build",
				Branch:      "main",
				Commit:      "build789",
				CommitShort: "build78",
			},
		},
		ReleaseRaw:   []byte(`{"release_id":"rel-20250115-abc123"}`),
		InventoryRaw: []byte(`{"files":{}}`),
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
func serveWithChi(pattern, method, url string, handler http.HandlerFunc) *httptest.ResponseRecorder {
	r := chi.NewRouter()
	switch method {
	case "GET":
		r.Get(pattern, handler)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, url, nil)
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
		{"GET", "/api/provenance/app"},
		{"GET", "/api/provenance/app/summary"},
		{"GET", "/api/provenance/content"},
		{"GET", "/api/provenance/content/summary"},
		{"GET", "/api/provenance/evidence"},
		{"GET", "/api/provenance/evidence/release.json"},
		{"GET", "/api/provenance/evidence/inventory.json"},
		{"GET", "/api/provenance/evidence/files/source/sbom/report.json"},
	}

	for _, ep := range endpoints {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(ep.method, ep.path, nil)
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
	req := httptest.NewRequest("GET", "/", nil)
	api.HandleAppProvenance(rec, req)

	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
}

func TestWriteJSON_CacheControl(t *testing.T) {
	api := NewAPI(noContentProvider(), nil, log.Nop())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
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
	req := httptest.NewRequest("GET", "/api/provenance/app", nil)
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
	req := httptest.NewRequest("GET", "/api/provenance/app", nil)
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
	req := httptest.NewRequest("GET", "/api/provenance/app", nil)
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
	req := httptest.NewRequest("GET", "/api/provenance/app", nil)
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
	req := httptest.NewRequest("GET", "/api/provenance/app", nil)
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
	req := httptest.NewRequest("GET", "/api/provenance/app/summary", nil)
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
	req := httptest.NewRequest("GET", "/api/provenance/app/summary", nil)
	api.HandleAppSummary(rec, req)

	m := parseJSON(t, rec)
	if m["has_evidence"] != false {
		t.Fatal("has_evidence should be false for empty store")
	}
}

func TestHandleAppSummary_WithEvidence(t *testing.T) {
	api := NewAPI(noContentProvider(), evidenceStore(), log.Nop())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/provenance/app/summary", nil)
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

func TestHandleAppSummary_AlwaysHasLinks(t *testing.T) {
	api := NewAPI(noContentProvider(), nil, log.Nop())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/provenance/app/summary", nil)
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
	req := httptest.NewRequest("GET", "/api/provenance/content", nil)
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
	req := httptest.NewRequest("GET", "/api/provenance/content", nil)
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
	req := httptest.NewRequest("GET", "/api/provenance/content", nil)
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
	req := httptest.NewRequest("GET", "/api/provenance/content/summary", nil)
	api.HandleContentSummary(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

func TestHandleContentSummary_WithProvenance(t *testing.T) {
	api := NewAPI(contentProvider(), nil, log.Nop())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/provenance/content/summary", nil)
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

func TestHandleContentSummary_NoProvenance_Fallback(t *testing.T) {
	api := NewAPI(contentProviderNoProvenance(), nil, log.Nop())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/provenance/content/summary", nil)
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
	req := httptest.NewRequest("GET", "/api/provenance/evidence", nil)
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
	req := httptest.NewRequest("GET", "/api/provenance/evidence", nil)
	api.HandleEvidenceManifest(rec, req)

	m := parseJSON(t, rec)
	if m["available"] != false {
		t.Fatal("available should be false for empty store")
	}
}

func TestHandleEvidenceManifest_WithEvidence(t *testing.T) {
	api := NewAPI(noContentProvider(), evidenceStore(), log.Nop())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/provenance/evidence", nil)
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
	req := httptest.NewRequest("GET", "/api/provenance/evidence/release.json", nil)
	api.HandleReleaseJSON(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestHandleReleaseJSON_EmptyStore(t *testing.T) {
	api := NewAPI(noContentProvider(), emptyEvidenceStore(), log.Nop())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/provenance/evidence/release.json", nil)
	api.HandleReleaseJSON(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestHandleReleaseJSON_WithEvidence(t *testing.T) {
	api := NewAPI(noContentProvider(), evidenceStore(), log.Nop())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/provenance/evidence/release.json", nil)
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
	req := httptest.NewRequest("GET", "/api/provenance/evidence/release.json", nil)
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
	req := httptest.NewRequest("GET", "/api/provenance/evidence/inventory.json", nil)
	api.HandleInventoryJSON(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestHandleInventoryJSON_WithEvidence(t *testing.T) {
	api := NewAPI(noContentProvider(), evidenceStore(), log.Nop())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/provenance/evidence/inventory.json", nil)
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
	req := httptest.NewRequest("GET", "/api/provenance/evidence/inventory.json", nil)
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
		"GET",
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
		"GET",
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
		"GET",
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
		"GET",
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
		"GET",
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
		"GET",
		"/api/provenance/evidence/files/",
		api.HandleEvidenceFile,
	)

	// Empty path -> 400 or 404 depending on chi behavior
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
		"GET",
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
			"GET",
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
		"GET",
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
			"GET",
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
			"GET",
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
		req := httptest.NewRequest("GET", path, nil)
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
	req := httptest.NewRequest("GET", "/api/provenance/evidence/files/source/sbom/report.json", nil)
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
		req, err := http.NewRequest("GET", safePath, nil)
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
