package webassets

import (
	"io/fs"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// FallbackFS
// ---------------------------------------------------------------------------

func TestFallbackFS_ReturnsNonNil(t *testing.T) {
	fsys := FallbackFS()
	if fsys == nil {
		t.Fatal("FallbackFS() returned nil")
	}
}

func TestFallbackFS_HasMaintenanceHTML(t *testing.T) {
	fsys := FallbackFS()

	info, err := fs.Stat(fsys, "maintenance.html")
	if err != nil {
		t.Fatalf("maintenance.html not found: %v", err)
	}
	if info.IsDir() {
		t.Fatal("maintenance.html is a directory")
	}
	if info.Size() == 0 {
		t.Fatal("maintenance.html is empty")
	}
}

func TestFallbackFS_MaintenanceContent(t *testing.T) {
	fsys := FallbackFS()

	data, err := fs.ReadFile(fsys, "maintenance.html")
	if err != nil {
		t.Fatalf("read maintenance.html: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("maintenance.html is empty")
	}

	body := string(data)
	// Should contain something about maintenance — don't be too specific
	// to avoid breaking on copy changes
	lower := strings.ToLower(body)
	if !strings.Contains(lower, "maintenance") {
		t.Fatalf("maintenance.html doesn't mention maintenance: %q", body)
	}
}

func TestFallbackFS_Has404HTML(t *testing.T) {
	fsys := FallbackFS()

	info, err := fs.Stat(fsys, "404.html")
	if err != nil {
		t.Fatalf("404.html not found: %v", err)
	}
	if info.IsDir() {
		t.Fatal("404.html is a directory")
	}
	if info.Size() == 0 {
		t.Fatal("404.html is empty")
	}
}

func TestFallbackFS_404Content(t *testing.T) {
	fsys := FallbackFS()

	data, err := fs.ReadFile(fsys, "404.html")
	if err != nil {
		t.Fatalf("read 404.html: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("404.html is empty")
	}
}

func TestFallbackFS_NoParentEscape(t *testing.T) {
	fsys := FallbackFS()

	// Should be rooted at fallback/ — no access to parent or seed/
	_, err := fs.Stat(fsys, "../seed")
	if err == nil {
		t.Fatal("should not be able to escape to parent via ../")
	}
}

func TestFallbackFS_NoSeedAccess(t *testing.T) {
	fsys := FallbackFS()

	// Seed files should not be visible from fallback FS
	_, err := fs.ReadFile(fsys, "seed/index.html")
	if err == nil {
		t.Fatal("seed/ should not be accessible from fallback FS")
	}
}

func TestFallbackFS_Idempotent(t *testing.T) {
	fs1 := FallbackFS()
	fs2 := FallbackFS()

	// Both should work independently
	_, err1 := fs.Stat(fs1, "maintenance.html")
	_, err2 := fs.Stat(fs2, "maintenance.html")

	if err1 != nil || err2 != nil {
		t.Fatalf("multiple FallbackFS() calls should all work: err1=%v err2=%v", err1, err2)
	}
}

// ---------------------------------------------------------------------------
// SeedSiteFS
// ---------------------------------------------------------------------------

func TestSeedSiteFS_ReturnsValidResult(t *testing.T) {
	fsys, ok := SeedSiteFS()

	if ok {
		// If seed has index.html, FS must be non-nil and readable
		if fsys == nil {
			t.Fatal("ok=true but FS is nil")
		}

		info, err := fs.Stat(fsys, "index.html")
		if err != nil {
			t.Fatalf("ok=true but index.html not found: %v", err)
		}
		if info.IsDir() {
			t.Fatal("index.html is a directory")
		}
		if info.Size() == 0 {
			t.Fatal("index.html is empty")
		}
	} else {
		// If seed doesn't have index.html, that's fine — FS may be nil
		t.Log("seed/ has no index.html — SeedSiteFS returns false (expected for placeholder)")
	}
}

func TestSeedSiteFS_Idempotent(t *testing.T) {
	_, ok1 := SeedSiteFS()
	_, ok2 := SeedSiteFS()

	if ok1 != ok2 {
		t.Fatalf("SeedSiteFS() returned different results: %v vs %v", ok1, ok2)
	}
}

func TestSeedSiteFS_NoFallbackAccess(t *testing.T) {
	fsys, ok := SeedSiteFS()
	if !ok {
		t.Skip("seed/ has no index.html, skipping FS isolation test")
	}

	// Fallback files should not be visible from seed FS
	_, err := fs.ReadFile(fsys, "maintenance.html")
	if err == nil {
		t.Fatal("fallback/maintenance.html should not be accessible from seed FS")
	}
}

// ---------------------------------------------------------------------------
// Embedded FS structure
// ---------------------------------------------------------------------------

func TestEmbeddedFS_HasFallbackDir(t *testing.T) {
	// The package-level embedded var should have a fallback directory
	entries, err := fs.ReadDir(embedded, "fallback")
	if err != nil {
		t.Fatalf("read fallback dir: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("fallback/ is empty")
	}

	names := make(map[string]bool)
	for _, e := range entries {
		names[e.Name()] = true
	}

	if !names["maintenance.html"] {
		t.Error("fallback/ missing maintenance.html")
	}
}

func TestEmbeddedFS_HasSeedDir(t *testing.T) {
	// Seed directory must exist (go:embed requires it)
	entries, err := fs.ReadDir(embedded, "seed")
	if err != nil {
		t.Fatalf("read seed dir: %v", err)
	}
	// Must have at least one file to satisfy go:embed
	if len(entries) == 0 {
		t.Fatal("seed/ is empty — go:embed should have caught this at compile time")
	}
}

func TestEmbeddedFS_RootHasBothDirs(t *testing.T) {
	entries, err := fs.ReadDir(embedded, ".")
	if err != nil {
		t.Fatalf("read root: %v", err)
	}

	names := make(map[string]bool)
	for _, e := range entries {
		names[e.Name()] = true
	}

	if !names["fallback"] {
		t.Error("embedded FS missing fallback/")
	}
	if !names["seed"] {
		t.Error("embedded FS missing seed/")
	}
}

// ---------------------------------------------------------------------------
// Contract: FallbackFS is compatible with sitehandler
// ---------------------------------------------------------------------------

func TestFallbackFS_PassesSiteHandlerValidation(t *testing.T) {
	// The fallback FS must pass sitehandler's validate() check:
	// maintenance.html must exist as a regular file
	fsys := FallbackFS()

	info, err := fs.Stat(fsys, "maintenance.html")
	if err != nil {
		t.Fatalf("sitehandler requires maintenance.html: %v", err)
	}
	if info.IsDir() {
		t.Fatal("maintenance.html must be a regular file, not a directory")
	}
}
