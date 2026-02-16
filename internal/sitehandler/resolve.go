package sitehandler

import (
	"io/fs"
	"path"
	"strings"

	"github.com/keithlinneman/linnemanlabs-web/internal/pathutil"
)

// resolvePath maps a URL path to a file within an FS
//
// Returns:
// - file: relative file path within FS (no leading slash)
// - redirectTo: if non-empty, caller should redirect to this URL path
// - ok: whether the mapping is valid/found
func resolvePath(urlPath string, fsys fs.FS) (file string, redirectTo string, ok bool) {
	p := urlPath
	if p == "" {
		p = "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}

	// basic rejection of ambiguous/unsafe paths
	if strings.Contains(p, "\x00") || strings.Contains(p, "\\") || strings.Contains(p, "..") {
		return "", "", false
	}
	if pathutil.HasDotSegments(p) {
		return "", "", false
	}

	trailingSlash := strings.HasSuffix(p, "/")

	// normalize path and preserve trailing slash if any
	clean := path.Clean(p)
	if trailingSlash && clean != "/" {
		clean += "/"
	}

	// root -> index.html
	if clean == "/" {
		name := "index.html"
		if existsFile(fsys, name) {
			return name, "", true
		}
		return "", "", false
	}

	// Directory -> <dir>/index.html
	if strings.HasSuffix(clean, "/") {
		name := strings.TrimPrefix(clean, "/") + "index.html"
		if existsFile(fsys, name) {
			return name, "", true
		}
		return "", "", false
	}

	// if it has an extension treat as a file
	if path.Ext(clean) != "" {
		name := strings.TrimPrefix(clean, "/")
		if existsFile(fsys, name) {
			return name, "", true
		}
		return "", "", false
	}

	// pretty URL without slash for directories - if <path>/index.html exists, redirect to canonical slash url for correctness
	dirIndex := strings.TrimPrefix(clean, "/") + "/index.html"
	if existsFile(fsys, dirIndex) {
		return "", clean + "/", true
	}

	// otherwise not found
	return "", "", false
}

func existsFile(fsys fs.FS, name string) bool {
	if name == "" || !fs.ValidPath(name) {
		return false
	}
	info, err := fs.Stat(fsys, name)
	if err != nil {
		return false
	}
	return !info.IsDir()
}
