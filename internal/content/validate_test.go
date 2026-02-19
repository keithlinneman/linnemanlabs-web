package content

import (
	"strings"
	"testing"
	"testing/fstest"
)

// ValidateSnapshot - nil / empty guards

func TestValidateSnapshot_NilSnapshot(t *testing.T) {
	err := ValidateSnapshot(nil, ValidationOptions{})
	if err == nil {
		t.Fatal("expected error for nil snapshot")
	}
	if !strings.Contains(err.Error(), "nil") {
		t.Fatalf("error should mention nil: %v", err)
	}
}

func TestValidateSnapshot_NilFS(t *testing.T) {
	snap := &Snapshot{FS: nil}
	err := ValidateSnapshot(snap, ValidationOptions{})
	if err == nil {
		t.Fatal("expected error for nil FS")
	}
	if !strings.Contains(err.Error(), "nil filesystem") {
		t.Fatalf("error should mention nil filesystem: %v", err)
	}
}

// index.html checks

func TestValidateSnapshot_MissingIndexHTML(t *testing.T) {
	snap := &Snapshot{
		FS: fstest.MapFS{
			"about.html": &fstest.MapFile{Data: []byte("<html>about</html>")},
		},
	}
	err := ValidateSnapshot(snap, ValidationOptions{})
	if err == nil {
		t.Fatal("expected error for missing index.html")
	}
	if !strings.Contains(err.Error(), "index.html") {
		t.Fatalf("error should mention index.html: %v", err)
	}
}

func TestValidateSnapshot_EmptyIndexHTML(t *testing.T) {
	snap := &Snapshot{
		FS: fstest.MapFS{
			"index.html": &fstest.MapFile{Data: []byte{}},
		},
	}
	err := ValidateSnapshot(snap, ValidationOptions{})
	if err == nil {
		t.Fatal("expected error for empty index.html")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Fatalf("error should mention empty: %v", err)
	}
}

func TestValidateSnapshot_ValidIndexHTML(t *testing.T) {
	snap := &Snapshot{
		FS: fstest.MapFS{
			"index.html": &fstest.MapFile{Data: []byte("<html>hello</html>")},
		},
	}
	err := ValidateSnapshot(snap, ValidationOptions{})
	if err != nil {
		t.Fatalf("expected no error: %v", err)
	}
}

// MinFiles

func TestValidateSnapshot_MinFiles_BelowThreshold(t *testing.T) {
	snap := &Snapshot{
		FS: fstest.MapFS{
			"index.html": &fstest.MapFile{Data: []byte("<html>")},
		},
	}
	err := ValidateSnapshot(snap, ValidationOptions{MinFiles: 5})
	if err == nil {
		t.Fatal("expected error for file count below minimum")
	}
	if !strings.Contains(err.Error(), "1 files") {
		t.Fatalf("error should mention actual count: %v", err)
	}
	if !strings.Contains(err.Error(), "minimum is 5") {
		t.Fatalf("error should mention minimum: %v", err)
	}
}

func TestValidateSnapshot_MinFiles_ExactlyAtThreshold(t *testing.T) {
	snap := &Snapshot{
		FS: fstest.MapFS{
			"index.html": &fstest.MapFile{Data: []byte("<html>")},
			"style.css":  &fstest.MapFile{Data: []byte("body{}")},
			"app.js":     &fstest.MapFile{Data: []byte("//js")},
		},
	}
	err := ValidateSnapshot(snap, ValidationOptions{MinFiles: 3})
	if err != nil {
		t.Fatalf("expected no error at exact threshold: %v", err)
	}
}

func TestValidateSnapshot_MinFiles_AboveThreshold(t *testing.T) {
	snap := &Snapshot{
		FS: fstest.MapFS{
			"index.html": &fstest.MapFile{Data: []byte("<html>")},
			"style.css":  &fstest.MapFile{Data: []byte("body{}")},
			"app.js":     &fstest.MapFile{Data: []byte("//js")},
		},
	}
	err := ValidateSnapshot(snap, ValidationOptions{MinFiles: 2})
	if err != nil {
		t.Fatalf("expected no error above threshold: %v", err)
	}
}

func TestValidateSnapshot_MinFiles_ZeroDisablesCheck(t *testing.T) {
	snap := &Snapshot{
		FS: fstest.MapFS{
			"index.html": &fstest.MapFile{Data: []byte("<html>")},
		},
	}
	// MinFiles=0 should not reject anything
	err := ValidateSnapshot(snap, ValidationOptions{MinFiles: 0})
	if err != nil {
		t.Fatalf("expected no error with MinFiles=0: %v", err)
	}
}

func TestValidateSnapshot_MinFiles_DirectoriesNotCounted(t *testing.T) {
	snap := &Snapshot{
		FS: fstest.MapFS{
			"index.html":    &fstest.MapFile{Data: []byte("<html>")},
			"css/style.css": &fstest.MapFile{Data: []byte("body{}")},
			"js/app.js":     &fstest.MapFile{Data: []byte("//js")},
		},
	}
	// 3 files, directories (css/, js/) are not counted
	err := ValidateSnapshot(snap, ValidationOptions{MinFiles: 4})
	if err == nil {
		t.Fatal("expected error: only 3 files exist, directories should not be counted")
	}
}

// Provenance - RequireProvenance

func TestValidateSnapshot_RequireProvenance_Missing(t *testing.T) {
	snap := &Snapshot{
		FS: fstest.MapFS{
			"index.html": &fstest.MapFile{Data: []byte("<html>")},
		},
		Provenance: nil,
	}
	err := ValidateSnapshot(snap, ValidationOptions{RequireProvenance: true})
	if err == nil {
		t.Fatal("expected error for missing provenance when required")
	}
	if !strings.Contains(err.Error(), "provenance") {
		t.Fatalf("error should mention provenance: %v", err)
	}
}

func TestValidateSnapshot_RequireProvenance_Present(t *testing.T) {
	snap := &Snapshot{
		FS: fstest.MapFS{
			"index.html": &fstest.MapFile{Data: []byte("<html>")},
		},
		Provenance: &Provenance{Version: "1.0.0"},
	}
	err := ValidateSnapshot(snap, ValidationOptions{RequireProvenance: true})
	if err != nil {
		t.Fatalf("expected no error with provenance present: %v", err)
	}
}

func TestValidateSnapshot_ProvenanceNotRequired_MissingOK(t *testing.T) {
	snap := &Snapshot{
		FS: fstest.MapFS{
			"index.html": &fstest.MapFile{Data: []byte("<html>")},
		},
		Provenance: nil,
	}
	err := ValidateSnapshot(snap, ValidationOptions{RequireProvenance: false})
	if err != nil {
		t.Fatalf("expected no error when provenance not required: %v", err)
	}
}

// DefaultValidationOptions

func TestDefaultValidationOptions(t *testing.T) {
	opts := DefaultValidationOptions()

	if opts.MinFiles != 10 {
		t.Fatalf("MinFiles = %d, want 10", opts.MinFiles)
	}
	if !opts.RequireProvenance {
		t.Fatal("RequireProvenance should be true by default")
	}
}

// Full validation with DefaultValidationOptions - integration

func TestValidateSnapshot_DefaultOpts_ValidBundle(t *testing.T) {
	snap := &Snapshot{
		FS: fstest.MapFS{
			"index.html":       &fstest.MapFile{Data: []byte("<html>hello</html>")},
			"css/style.css":    &fstest.MapFile{Data: []byte("body{}")},
			"css/reset.css":    &fstest.MapFile{Data: []byte("*{margin:0}")},
			"js/app.js":        &fstest.MapFile{Data: []byte("//js")},
			"js/vendor.js":     &fstest.MapFile{Data: []byte("//vendor")},
			"img/logo.png":     &fstest.MapFile{Data: []byte("png")},
			"img/favicon.ico":  &fstest.MapFile{Data: []byte("ico")},
			"about/index.html": &fstest.MapFile{Data: []byte("<html>about</html>")},
			"provenance.json":  &fstest.MapFile{Data: []byte("{}")},
			"robots.txt":       &fstest.MapFile{Data: []byte("User-agent: *")},
		},
		Meta:       Meta{Hash: "abc123"},
		Provenance: &Provenance{Version: "1.0.0", ContentHash: "abc123"},
	}
	err := ValidateSnapshot(snap, DefaultValidationOptions())
	if err != nil {
		t.Fatalf("expected valid bundle to pass defaults: %v", err)
	}
}

func TestValidateSnapshot_DefaultOpts_TooFewFiles(t *testing.T) {
	snap := &Snapshot{
		FS: fstest.MapFS{
			"index.html": &fstest.MapFile{Data: []byte("<html>hello</html>")},
		},
		Meta: Meta{Hash: "abc123"},
	}
	err := ValidateSnapshot(snap, DefaultValidationOptions())
	if err == nil {
		t.Fatal("expected error: 1 file is below MinFiles=10 default")
	}
	if !strings.Contains(err.Error(), "minimum is 10") {
		t.Fatalf("error should mention minimum: %v", err)
	}
}

func TestValidateSnapshot_DefaultOpts_NoProvenance_OK(t *testing.T) {
	snap := &Snapshot{
		FS: fstest.MapFS{
			"index.html":         &fstest.MapFile{Data: []byte("<html>hello</html>")},
			"css/style.css":      &fstest.MapFile{Data: []byte("body{}")},
			"css/reset.css":      &fstest.MapFile{Data: []byte("*{margin:0}")},
			"js/app.js":          &fstest.MapFile{Data: []byte("//js")},
			"js/vendor.js":       &fstest.MapFile{Data: []byte("//vendor")},
			"img/logo.png":       &fstest.MapFile{Data: []byte("png")},
			"img/favicon.ico":    &fstest.MapFile{Data: []byte("ico")},
			"about/index.html":   &fstest.MapFile{Data: []byte("<html>about</html>")},
			"contact/index.html": &fstest.MapFile{Data: []byte("<html>contact</html>")},
			"robots.txt":         &fstest.MapFile{Data: []byte("User-agent: *")},
		},
		Meta: Meta{Hash: "abc123"},
	}
	// defaults require provenance
	err := ValidateSnapshot(snap, DefaultValidationOptions())
	if err == nil {
		t.Fatal("expected error without provenance under defaults")
	}
}

// countFiles helper

func TestCountFiles_Empty(t *testing.T) {
	fs := fstest.MapFS{}
	count, err := countFiles(fs)
	if err != nil {
		t.Fatalf("countFiles: %v", err)
	}
	if count != 0 {
		t.Fatalf("count = %d, want 0", count)
	}
}

func TestCountFiles_FilesOnly(t *testing.T) {
	fs := fstest.MapFS{
		"a.html": &fstest.MapFile{Data: []byte("a")},
		"b.css":  &fstest.MapFile{Data: []byte("b")},
		"c.js":   &fstest.MapFile{Data: []byte("c")},
	}
	count, err := countFiles(fs)
	if err != nil {
		t.Fatalf("countFiles: %v", err)
	}
	if count != 3 {
		t.Fatalf("count = %d, want 3", count)
	}
}

func TestCountFiles_NestedDirectories(t *testing.T) {
	fs := fstest.MapFS{
		"index.html":         &fstest.MapFile{Data: []byte("root")},
		"css/style.css":      &fstest.MapFile{Data: []byte("css")},
		"js/app.js":          &fstest.MapFile{Data: []byte("js")},
		"img/deep/photo.png": &fstest.MapFile{Data: []byte("png")},
	}
	count, err := countFiles(fs)
	if err != nil {
		t.Fatalf("countFiles: %v", err)
	}
	// 4 files, directories don't count
	if count != 4 {
		t.Fatalf("count = %d, want 4", count)
	}
}
