package sitehandler

import (
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"
)

// testFS builds a minimal in-memory filesystem for resolve tests.
// Files only need to exist, content doesn't matter for path resolution.
func testFS() fstest.MapFS {
	return fstest.MapFS{
		"index.html":             &fstest.MapFile{Data: []byte("root")},
		"about/index.html":       &fstest.MapFile{Data: []byte("about")},
		"blog/index.html":        &fstest.MapFile{Data: []byte("blog")},
		"blog/first-post.html":   &fstest.MapFile{Data: []byte("post")},
		"css/style.css":          &fstest.MapFile{Data: []byte("css")},
		"js/app.js":              &fstest.MapFile{Data: []byte("js")},
		"images/logo.png":        &fstest.MapFile{Data: []byte("png")},
		"deep/nested/page.html":  &fstest.MapFile{Data: []byte("deep")},
		"deep/nested/index.html": &fstest.MapFile{Data: []byte("deep index")},
		"noext":                  &fstest.MapFile{Data: []byte("no extension")},
		"robots.txt":             &fstest.MapFile{Data: []byte("robots")},
		"favicon.ico":            &fstest.MapFile{Data: []byte("ico")},
		".hidden":                &fstest.MapFile{Data: []byte("hidden")},
		"file with spaces.html":  &fstest.MapFile{Data: []byte("spaces")},
	}
}

func TestResolvePath(t *testing.T) {
	fs := testFS()

	tests := []struct {
		name      string
		path      string
		wantFile  string
		wantRedir string
		wantOK    bool
	}{
		// root
		{
			name:     "root slash",
			path:     "/",
			wantFile: "index.html",
			wantOK:   true,
		},
		{
			name:     "empty string treated as root",
			path:     "",
			wantFile: "index.html",
			wantOK:   true,
		},

		// static files with extensions
		{
			name:     "css file",
			path:     "/css/style.css",
			wantFile: "css/style.css",
			wantOK:   true,
		},
		{
			name:     "js file",
			path:     "/js/app.js",
			wantFile: "js/app.js",
			wantOK:   true,
		},
		{
			name:     "image file",
			path:     "/images/logo.png",
			wantFile: "images/logo.png",
			wantOK:   true,
		},
		{
			name:     "robots.txt",
			path:     "/robots.txt",
			wantFile: "robots.txt",
			wantOK:   true,
		},
		{
			name:     "favicon",
			path:     "/favicon.ico",
			wantFile: "favicon.ico",
			wantOK:   true,
		},
		{
			name:     "html file direct",
			path:     "/blog/first-post.html",
			wantFile: "blog/first-post.html",
			wantOK:   true,
		},
		{
			name:     "deep nested html",
			path:     "/deep/nested/page.html",
			wantFile: "deep/nested/page.html",
			wantOK:   true,
		},

		// directory with trailing slash -> index.html
		{
			name:     "directory with trailing slash",
			path:     "/about/",
			wantFile: "about/index.html",
			wantOK:   true,
		},
		{
			name:     "blog directory with trailing slash",
			path:     "/blog/",
			wantFile: "blog/index.html",
			wantOK:   true,
		},
		{
			name:     "deep nested directory with trailing slash",
			path:     "/deep/nested/",
			wantFile: "deep/nested/index.html",
			wantOK:   true,
		},

		// pretty URLs: no extension, no slash -> redirect to slash
		{
			name:      "pretty URL redirects to trailing slash",
			path:      "/about",
			wantRedir: "/about/",
			wantOK:    true,
		},
		{
			name:      "blog pretty URL redirect",
			path:      "/blog",
			wantRedir: "/blog/",
			wantOK:    true,
		},
		{
			name:      "deep nested pretty URL redirect",
			path:      "/deep/nested",
			wantRedir: "/deep/nested/",
			wantOK:    true,
		},

		// not found
		{
			name:   "nonexistent file",
			path:   "/nope.html",
			wantOK: false,
		},
		{
			name:   "nonexistent directory",
			path:   "/nope/",
			wantOK: false,
		},
		{
			name:   "nonexistent pretty URL no matching dir",
			path:   "/nope",
			wantOK: false,
		},
		{
			name:   "nonexistent deeply nested",
			path:   "/a/b/c/d/e.html",
			wantOK: false,
		},
		{
			name:   "file without extension not found via direct path",
			path:   "/noext.html",
			wantOK: false,
		},

		// security: path traversal
		{
			name:   "dot dot slash",
			path:   "/../etc/passwd",
			wantOK: false,
		},
		{
			name:   "dot dot in middle",
			path:   "/about/../etc/passwd",
			wantOK: false,
		},
		{
			name:   "dot dot at end",
			path:   "/about/..",
			wantOK: false,
		},
		{
			name:   "single dot segment",
			path:   "/./index.html",
			wantOK: false,
		},
		{
			name:   "dot segment in middle",
			path:   "/about/./index.html",
			wantOK: false,
		},
		{
			name:   "encoded dot segments should still be caught if decoded",
			path:   "/about/../index.html",
			wantOK: false,
		},

		// security: null bytes
		{
			name:   "null byte in path",
			path:   "/index.html\x00.jpg",
			wantOK: false,
		},
		{
			name:   "null byte at start",
			path:   "\x00/index.html",
			wantOK: false,
		},
		{
			name:   "null byte alone",
			path:   "/\x00",
			wantOK: false,
		},

		// security: backslashes
		{
			name:   "backslash traversal",
			path:   "/about\\..\\etc\\passwd",
			wantOK: false,
		},
		{
			name:   "single backslash",
			path:   "/about\\index.html",
			wantOK: false,
		},

		// edge cases
		{
			name:     "path without leading slash",
			path:     "css/style.css",
			wantFile: "css/style.css",
			wantOK:   true,
		},
		{
			name:     "double slash normalized",
			path:     "//css/style.css",
			wantFile: "css/style.css",
			wantOK:   true,
		},
		{
			name:     "hidden dotfile not matched as dot segment",
			path:     "/.hidden",
			wantFile: ".hidden",
			wantOK:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file, redir, ok := resolvePath(tt.path, fs)

			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}

			if !tt.wantOK {
				// for rejected/not-found paths, file and redir should both be empty
				if file != "" {
					t.Errorf("file = %q, want empty for not-found", file)
				}
				if redir != "" {
					t.Errorf("redir = %q, want empty for not-found", redir)
				}
				return
			}

			if tt.wantRedir != "" {
				if redir != tt.wantRedir {
					t.Errorf("redir = %q, want %q", redir, tt.wantRedir)
				}
				if file != "" {
					t.Errorf("file = %q, want empty when redirecting", file)
				}
				return
			}

			if file != tt.wantFile {
				t.Errorf("file = %q, want %q", file, tt.wantFile)
			}
			if redir != "" {
				t.Errorf("redir = %q, want empty for direct file serve", redir)
			}
		})
	}
}

// TestResolvePath_EmptyFS ensures we handle a filesystem with no files gracefully
func TestResolvePath_EmptyFS(t *testing.T) {
	empty := fstest.MapFS{}

	tests := []struct {
		name string
		path string
	}{
		{"root on empty fs", "/"},
		{"file on empty fs", "/index.html"},
		{"directory on empty fs", "/about/"},
		{"pretty url on empty fs", "/about"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file, redir, ok := resolvePath(tt.path, empty)
			if ok {
				t.Fatalf("expected not-found on empty FS, got file=%q redir=%q", file, redir)
			}
		})
	}
}

// TestHasDotSegments tests the helper directly for clarity
func TestHasDotSegments(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/normal/path", false},
		{"/path/./here", true},
		{"/path/../up", true},
		{".", true},
		{"..", true},
		{"/...", false},     // three dots is not a dot segment
		{"/.hidden", false}, // dotfile, not a dot segment
		{"/.dotdir/file", false},
		{"/path/to/.", true},
		{"/./", true},
		{"/../", true},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := hasDotSegments(tt.path)
			if got != tt.want {
				t.Errorf("hasDotSegments(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

// TestExistsFile tests the file existence helper
func TestExistsFile(t *testing.T) {
	fs := testFS()

	tests := []struct {
		name string
		path string
		want bool
	}{
		{"existing file", "index.html", true},
		{"nested file", "css/style.css", true},
		{"nonexistent", "nope.html", false},
		{"empty string", "", false},
		{"directory not a file", "about", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := existsFile(fs, tt.path)
			if got != tt.want {
				t.Errorf("existsFile(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func FuzzResolvePath(f *testing.F) {
	// Seed with known attack vectors
	seeds := []string{
		"../etc/passwd", "..\\..\\windows\\system32",
		"foo/../../../etc/shadow", "foo%00.html",
		"\x00", "\\", "..", ".", "./", "../",
		"foo/./bar", "foo/../bar",
		strings.Repeat("../", 100) + "etc/passwd",
		"valid/path.html",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	// Build a test filesystem with known files
	fsys := fstest.MapFS{
		"index.html":    &fstest.MapFile{Data: []byte("ok")},
		"sub/page.html": &fstest.MapFile{Data: []byte("ok")},
	}

	f.Fuzz(func(t *testing.T, input string) {
		file, _, ok := resolvePath(input, fsys)
		if !ok {
			return // rejected — safe
		}
		// INVARIANT: resolved file must be valid within the FS
		if !fs.ValidPath(file) {
			t.Errorf("resolvePath returned invalid fs path: %q", file)
		}
		// INVARIANT: must not contain traversal sequences after resolution
		if strings.Contains(file, "..") {
			t.Errorf("resolvePath returned path with '..': %q", file)
		}
		// INVARIANT: must actually exist in the filesystem
		if _, err := fs.Stat(fsys, file); err != nil {
			t.Errorf("resolvePath returned non-existent file: %q", file)
		}
	})
}

func FuzzHasDotSegments(f *testing.F) {
	f.Add("foo/./bar")
	f.Add("foo/../bar")
	f.Add("./foo")
	f.Add("foo/.")
	f.Add(".")
	f.Add("..")
	f.Add("foo/bar")
	f.Add("...") // triple dot — should NOT trigger

	f.Fuzz(func(t *testing.T, p string) {
		result := hasDotSegments(p)
		// INVARIANT: if result is false, no segment equals "." or ".."
		segments := strings.Split(p, "/")
		hasDangerousSegment := false
		for _, seg := range segments {
			if seg == "." || seg == ".." {
				hasDangerousSegment = true
				break
			}
		}
		if result != hasDangerousSegment {
			t.Errorf("hasDotSegments(%q) = %v, but manual check = %v", p, result, hasDangerousSegment)
		}
	})
}
