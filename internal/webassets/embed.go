package webassets

import (
	"embed"
	"fmt"
	"io/fs"
)

// fallback/ and seed/ must exist and have at least one file each to satisfy go:embed
//
//go:embed fallback seed
var embedded embed.FS

func FallbackFS() fs.FS {
	sub, err := fs.Sub(embedded, "fallback")
	if err != nil {
		panic(fmt.Errorf("webassets: fallback subfs: %w", err))
	}
	return sub
}

// SeedSiteFS returns (fs, true) only if seed looks like a real site (has index.html)
func SeedSiteFS() (fs.FS, bool) {
	sub, err := fs.Sub(embedded, "seed")
	if err != nil {
		return nil, false
	}
	if _, err := fs.Stat(sub, "index.html"); err != nil {
		return nil, false
	}
	return sub, true
}
