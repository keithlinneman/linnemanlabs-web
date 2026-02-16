package pathutil

import (
	"strings"
	"testing"
)

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
			got := HasDotSegments(tt.path)
			if got != tt.want {
				t.Errorf("hasDotSegments(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
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
		result := HasDotSegments(p)
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
