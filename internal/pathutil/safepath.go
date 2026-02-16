package pathutil

import "strings"

// HasDotSegments reports whether any path segment is "." or "..".
func HasDotSegments(p string) bool {
	for _, seg := range strings.Split(p, "/") {
		if seg == "." || seg == ".." {
			return true
		}
	}
	return false
}
