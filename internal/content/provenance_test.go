package content

import (
	"encoding/json"
	"testing"
	"testing/fstest"
	"time"
)

// ProvenanceFilePath constant

func TestProvenanceFilePath(t *testing.T) {
	if ProvenanceFilePath != "provenance.json" {
		t.Fatalf("ProvenanceFilePath = %q, want provenance.json", ProvenanceFilePath)
	}
}

// LoadProvenance

func TestLoadProvenance_Valid(t *testing.T) {
	fs := fstest.MapFS{
		"provenance.json": &fstest.MapFile{
			Data: []byte(`{
				"schema": "llabs.content.provenance.v1",
				"type": "content-bundle",
				"version": "1.2.3",
				"content_id": "site-abc123",
				"content_hash": "deadbeef",
				"created_at": "2026-02-10T15:30:00Z",
				"source": {
					"repository": "github.com/test/repo",
					"commit": "abc123def456789012345678901234567890abcd",
					"commit_short": "abc123d",
					"commit_date": "2026-02-10T14:00:00Z",
					"branch": "main",
					"dirty": false
				},
				"build": {
					"host": "runner-1",
					"user": "ci",
					"timestamp": "2026-02-10T15:00:00Z"
				},
				"summary": {
					"total_files": 42,
					"total_size": 1024000,
					"file_types": {"html": 20, "css": 5, "js": 10, "png": 7}
				},
				"files": [
					{"path": "index.html", "sha256": "aaa111", "size": 1000, "type": "html", "modified": "2026-02-10T12:00:00Z"},
					{"path": "style.css", "sha256": "bbb222", "size": 500, "type": "css", "modified": "2026-02-10T11:00:00Z"}
				],
				"tooling": {
					"hugo": {"version": "0.121.1", "sha256": "abc123"},
					"tailwindcss": {"version": "3.4.0"}
				}
			}`),
		},
	}

	p, err := LoadProvenance(fs)
	if err != nil {
		t.Fatalf("LoadProvenance: %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil provenance")
	}

	// top-level fields
	if p.Schema != "llabs.content.provenance.v1" {
		t.Fatalf("Schema = %q", p.Schema)
	}
	if p.Type != "content-bundle" {
		t.Fatalf("Type = %q", p.Type)
	}
	if p.Version != "1.2.3" {
		t.Fatalf("Version = %q", p.Version)
	}
	if p.ContentID != "site-abc123" {
		t.Fatalf("ContentID = %q", p.ContentID)
	}
	if p.ContentHash != "deadbeef" {
		t.Fatalf("ContentHash = %q", p.ContentHash)
	}

	// created_at time parsing
	wantCreated := time.Date(2026, 2, 10, 15, 30, 0, 0, time.UTC)
	if !p.CreatedAt.Equal(wantCreated) {
		t.Fatalf("CreatedAt = %v, want %v", p.CreatedAt, wantCreated)
	}

	// source
	if p.Source.Repository != "github.com/test/repo" {
		t.Fatalf("Source.Repository = %q", p.Source.Repository)
	}
	if p.Source.CommitShort != "abc123d" {
		t.Fatalf("Source.CommitShort = %q", p.Source.CommitShort)
	}
	if p.Source.Branch != "main" {
		t.Fatalf("Source.Branch = %q", p.Source.Branch)
	}
	if p.Source.Dirty {
		t.Fatal("Source.Dirty = true, want false")
	}
	wantCommitDate := time.Date(2026, 2, 10, 14, 0, 0, 0, time.UTC)
	if !p.Source.CommitDate.Equal(wantCommitDate) {
		t.Fatalf("Source.CommitDate = %v, want %v", p.Source.CommitDate, wantCommitDate)
	}

	// build
	if p.Build.Host != "runner-1" {
		t.Fatalf("Build.Host = %q", p.Build.Host)
	}
	if p.Build.User != "ci" {
		t.Fatalf("Build.User = %q", p.Build.User)
	}
	wantBuildTime := time.Date(2026, 2, 10, 15, 0, 0, 0, time.UTC)
	if !p.Build.Timestamp.Equal(wantBuildTime) {
		t.Fatalf("Build.Timestamp = %v, want %v", p.Build.Timestamp, wantBuildTime)
	}

	// summary
	if p.Summary.TotalFiles != 42 {
		t.Fatalf("Summary.TotalFiles = %d", p.Summary.TotalFiles)
	}
	if p.Summary.TotalSize != 1024000 {
		t.Fatalf("Summary.TotalSize = %d", p.Summary.TotalSize)
	}
	if len(p.Summary.FileTypes) != 4 {
		t.Fatalf("Summary.FileTypes has %d entries, want 4", len(p.Summary.FileTypes))
	}
	if p.Summary.FileTypes["html"] != 20 {
		t.Fatalf("FileTypes[html] = %d", p.Summary.FileTypes["html"])
	}

	// files
	if len(p.Files) != 2 {
		t.Fatalf("Files length = %d, want 2", len(p.Files))
	}
	if p.Files[0].Path != "index.html" {
		t.Fatalf("Files[0].Path = %q", p.Files[0].Path)
	}
	if p.Files[0].SHA256 != "aaa111" {
		t.Fatalf("Files[0].SHA256 = %q", p.Files[0].SHA256)
	}
	if p.Files[0].Size != 1000 {
		t.Fatalf("Files[0].Size = %d", p.Files[0].Size)
	}
	if p.Files[0].Type != "html" {
		t.Fatalf("Files[0].Type = %q", p.Files[0].Type)
	}
	if p.Files[1].Path != "style.css" {
		t.Fatalf("Files[1].Path = %q", p.Files[1].Path)
	}

	// tooling
	if p.Tooling.Hugo == nil {
		t.Fatal("expected non-nil Hugo tooling")
	}
	if p.Tooling.Hugo.Version != "0.121.1" {
		t.Fatalf("Hugo.Version = %q", p.Tooling.Hugo.Version)
	}
	if p.Tooling.Hugo.SHA256 != "abc123" {
		t.Fatalf("Hugo.SHA256 = %q", p.Tooling.Hugo.SHA256)
	}
	if p.Tooling.TailwindCSS == nil {
		t.Fatal("expected non-nil TailwindCSS")
	}
	if p.Tooling.TailwindCSS.Version != "3.4.0" {
		t.Fatalf("TailwindCSS.Version = %q", p.Tooling.TailwindCSS.Version)
	}
	// unset tools should be nil
	if p.Tooling.Tidy != nil {
		t.Fatal("expected nil Tidy")
	}
	if p.Tooling.Git != nil {
		t.Fatal("expected nil Git")
	}
	if p.Tooling.Bash != nil {
		t.Fatal("expected nil Bash")
	}
}

func TestLoadProvenance_MissingFile(t *testing.T) {
	fs := fstest.MapFS{}
	_, err := LoadProvenance(fs)
	if err == nil {
		t.Fatal("expected error when provenance.json missing")
	}
}

func TestLoadProvenance_InvalidJSON(t *testing.T) {
	fs := fstest.MapFS{
		"provenance.json": &fstest.MapFile{Data: []byte(`{not valid json`)},
	}
	_, err := LoadProvenance(fs)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestLoadProvenance_EmptyJSON(t *testing.T) {
	fs := fstest.MapFS{
		"provenance.json": &fstest.MapFile{Data: []byte(`{}`)},
	}
	p, err := LoadProvenance(fs)
	if err != nil {
		t.Fatalf("LoadProvenance: %v", err)
	}
	if p.Version != "" {
		t.Fatalf("Version = %q, want empty", p.Version)
	}
	if p.Summary.TotalFiles != 0 {
		t.Fatalf("TotalFiles = %d, want 0", p.Summary.TotalFiles)
	}
	if p.Files != nil {
		t.Fatalf("Files = %v, want nil", p.Files)
	}
}

func TestLoadProvenance_EmptyFile(t *testing.T) {
	fs := fstest.MapFS{
		"provenance.json": &fstest.MapFile{Data: []byte("")},
	}
	_, err := LoadProvenance(fs)
	if err == nil {
		t.Fatal("expected error for empty file")
	}
}

func TestLoadProvenance_DirtySource(t *testing.T) {
	fs := fstest.MapFS{
		"provenance.json": &fstest.MapFile{
			Data: []byte(`{
				"source": {"dirty": true, "branch": "feature/wip", "commit_short": "abc1234"}
			}`),
		},
	}
	p, err := LoadProvenance(fs)
	if err != nil {
		t.Fatalf("LoadProvenance: %v", err)
	}
	if !p.Source.Dirty {
		t.Fatal("Source.Dirty = false, want true")
	}
	if p.Source.Branch != "feature/wip" {
		t.Fatalf("Source.Branch = %q", p.Source.Branch)
	}
}

func TestLoadProvenance_AllTooling(t *testing.T) {
	fs := fstest.MapFS{
		"provenance.json": &fstest.MapFile{
			Data: []byte(`{
				"tooling": {
					"hugo": {"version": "0.121.1"},
					"tailwindcss": {"version": "3.4.0"},
					"tidy": {"version": "5.8.0"},
					"git": {"version": "2.43.0"},
					"bash": {"version": "5.2.21"}
				}
			}`),
		},
	}
	p, err := LoadProvenance(fs)
	if err != nil {
		t.Fatalf("LoadProvenance: %v", err)
	}
	if p.Tooling.Hugo == nil || p.Tooling.Hugo.Version != "0.121.1" {
		t.Fatal("Hugo tooling wrong")
	}
	if p.Tooling.TailwindCSS == nil || p.Tooling.TailwindCSS.Version != "3.4.0" {
		t.Fatal("TailwindCSS tooling wrong")
	}
	if p.Tooling.Tidy == nil || p.Tooling.Tidy.Version != "5.8.0" {
		t.Fatal("Tidy tooling wrong")
	}
	if p.Tooling.Git == nil || p.Tooling.Git.Version != "2.43.0" {
		t.Fatal("Git tooling wrong")
	}
	if p.Tooling.Bash == nil || p.Tooling.Bash.Version != "5.2.21" {
		t.Fatal("Bash tooling wrong")
	}
}

func TestLoadProvenance_FileModifiedTime(t *testing.T) {
	fs := fstest.MapFS{
		"provenance.json": &fstest.MapFile{
			Data: []byte(`{
				"files": [
					{"path": "page.html", "sha256": "aaa", "size": 100, "type": "html", "modified": "2026-01-15T08:30:00Z"}
				]
			}`),
		},
	}
	p, err := LoadProvenance(fs)
	if err != nil {
		t.Fatalf("LoadProvenance: %v", err)
	}
	if len(p.Files) != 1 {
		t.Fatalf("Files length = %d", len(p.Files))
	}
	wantMod := time.Date(2026, 1, 15, 8, 30, 0, 0, time.UTC)
	if !p.Files[0].Modified.Equal(wantMod) {
		t.Fatalf("Files[0].Modified = %v, want %v", p.Files[0].Modified, wantMod)
	}
}

// JSON round-trip: Provenance -> marshal -> unmarshal -> compare

func TestProvenance_JSONRoundTrip(t *testing.T) {
	original := Provenance{
		Schema:      "llabs.content.provenance.v1",
		Type:        "content-bundle",
		Version:     "2.0.0",
		ContentID:   "site-xyz",
		ContentHash: "deadbeef",
		CreatedAt:   time.Date(2026, 2, 15, 12, 0, 0, 0, time.UTC),
		Source: ProvenanceSource{
			Repository:  "github.com/test/repo",
			Commit:      "abc123",
			CommitShort: "abc123",
			CommitDate:  time.Date(2026, 2, 15, 11, 0, 0, 0, time.UTC),
			Branch:      "main",
			Dirty:       false,
		},
		Build: ProvenanceBuild{
			Host:      "ci-runner",
			User:      "deploy",
			Timestamp: time.Date(2026, 2, 15, 11, 30, 0, 0, time.UTC),
		},
		Summary: ProvenanceSummary{
			TotalFiles: 10,
			TotalSize:  50000,
			FileTypes:  map[string]int{"html": 5, "css": 3, "js": 2},
		},
		Files: []ProvenanceFile{
			{Path: "index.html", SHA256: "aaa", Size: 1000, Type: "html", Modified: time.Date(2026, 2, 15, 10, 0, 0, 0, time.UTC)},
		},
		Tooling: ProvenanceTooling{
			Hugo: &ToolInfo{Version: "0.121.1", SHA256: "abc"},
		},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var roundTripped Provenance
	if err := json.Unmarshal(data, &roundTripped); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	// verify key fields survived
	if roundTripped.Schema != original.Schema {
		t.Fatalf("Schema = %q", roundTripped.Schema)
	}
	if roundTripped.Version != original.Version {
		t.Fatalf("Version = %q", roundTripped.Version)
	}
	if roundTripped.ContentHash != original.ContentHash {
		t.Fatalf("ContentHash = %q", roundTripped.ContentHash)
	}
	if !roundTripped.CreatedAt.Equal(original.CreatedAt) {
		t.Fatalf("CreatedAt = %v", roundTripped.CreatedAt)
	}
	if roundTripped.Source.Repository != original.Source.Repository {
		t.Fatalf("Source.Repository = %q", roundTripped.Source.Repository)
	}
	if !roundTripped.Source.CommitDate.Equal(original.Source.CommitDate) {
		t.Fatalf("Source.CommitDate = %v", roundTripped.Source.CommitDate)
	}
	if roundTripped.Build.Host != original.Build.Host {
		t.Fatalf("Build.Host = %q", roundTripped.Build.Host)
	}
	if !roundTripped.Build.Timestamp.Equal(original.Build.Timestamp) {
		t.Fatalf("Build.Timestamp = %v", roundTripped.Build.Timestamp)
	}
	if roundTripped.Summary.TotalFiles != original.Summary.TotalFiles {
		t.Fatalf("Summary.TotalFiles = %d", roundTripped.Summary.TotalFiles)
	}
	if len(roundTripped.Files) != 1 {
		t.Fatalf("Files length = %d", len(roundTripped.Files))
	}
	if roundTripped.Files[0].Path != "index.html" {
		t.Fatalf("Files[0].Path = %q", roundTripped.Files[0].Path)
	}
	if roundTripped.Tooling.Hugo == nil || roundTripped.Tooling.Hugo.Version != "0.121.1" {
		t.Fatal("Tooling.Hugo wrong after round-trip")
	}
	// nil tools should stay nil
	if roundTripped.Tooling.TailwindCSS != nil {
		t.Fatal("Tooling.TailwindCSS should be nil")
	}
}

// JSON: omitempty behavior for optional tooling fields

func TestProvenance_ToolingOmitEmpty(t *testing.T) {
	p := Provenance{
		Tooling: ProvenanceTooling{
			Hugo: &ToolInfo{Version: "1.0"},
			// all others nil
		},
	}

	data, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var doc map[string]json.RawMessage
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("Unmarshal doc: %v", err)
	}

	var tooling map[string]json.RawMessage
	if err := json.Unmarshal(doc["tooling"], &tooling); err != nil {
		t.Fatalf("Unmarshal tooling: %v", err)
	}

	if _, ok := tooling["hugo"]; !ok {
		t.Fatal("expected hugo in tooling JSON")
	}
	// nil fields should be omitted
	for _, key := range []string{"tailwindcss", "tidy", "git", "bash"} {
		if _, ok := tooling[key]; ok {
			t.Fatalf("expected %q to be omitted from tooling JSON", key)
		}
	}
}

// ProvenanceResponse / RuntimeInfo types

func TestProvenanceResponse_JSON(t *testing.T) {
	resp := ProvenanceResponse{
		Bundle: &Provenance{
			Version:     "1.0.0",
			ContentHash: "abc123",
		},
		Runtime: RuntimeInfo{
			LoadedAt:   time.Date(2026, 2, 15, 12, 0, 0, 0, time.UTC),
			ServerTime: time.Date(2026, 2, 15, 12, 5, 0, 0, time.UTC),
			Source:     SourceS3,
		},
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var roundTripped ProvenanceResponse
	if err := json.Unmarshal(data, &roundTripped); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if roundTripped.Bundle == nil {
		t.Fatal("expected non-nil Bundle")
	}
	if roundTripped.Bundle.Version != "1.0.0" {
		t.Fatalf("Bundle.Version = %q", roundTripped.Bundle.Version)
	}
	if roundTripped.Runtime.Source != SourceS3 {
		t.Fatalf("Runtime.Source = %q", roundTripped.Runtime.Source)
	}
	if !roundTripped.Runtime.LoadedAt.Equal(resp.Runtime.LoadedAt) {
		t.Fatalf("Runtime.LoadedAt = %v", roundTripped.Runtime.LoadedAt)
	}
}

func TestProvenanceResponse_NilBundle(t *testing.T) {
	resp := ProvenanceResponse{
		Runtime: RuntimeInfo{
			ServerTime: time.Now().UTC(),
			Source:     SourceSeed,
		},
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var doc map[string]json.RawMessage
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	// bundle should be null when nil
	if string(doc["bundle"]) != "null" {
		t.Fatalf("bundle = %s, want null", string(doc["bundle"]))
	}
}
