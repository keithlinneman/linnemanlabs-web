package sitehandler

import (
	"path"
	"strings"
)

func cacheControlForFile(name string, o Options) string {
	ext := strings.ToLower(path.Ext(name))

	switch ext {
	case ".html":
		return o.HTMLCacheControl

	// “static asset” extensions
	case ".css", ".js", ".mjs",
		".png", ".jpg", ".jpeg", ".webp", ".gif", ".svg", ".ico",
		".woff", ".woff2", ".ttf", ".eot",
		".map":
		return o.AssetCacheControl

	default:
		// treat no extension like html to be safe
		if ext == "" {
			return o.HTMLCacheControl
		}
		return o.OtherCacheControl
	}
}
