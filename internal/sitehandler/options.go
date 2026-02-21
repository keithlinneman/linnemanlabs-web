package sitehandler

import (
	"fmt"
	"io/fs"

	"github.com/keithlinneman/linnemanlabs-web/internal/content"
	"github.com/keithlinneman/linnemanlabs-web/internal/log"
)

type SnapshotProvider interface {
	Get() (*content.Snapshot, bool)
}

type Options struct {
	Logger log.Logger
	// Active content
	Content SnapshotProvider
	// fallback FS (maintenance page, maybe fallback 404)
	FallbackFS fs.FS

	// file names inside the FS roots (relative path)
	// - MaintenanceFile and Fallback404File are read from FallbackFS
	// - Site404File is read from the active snapshot FS
	MaintenanceFile string // default: "maintenance.html"
	Fallback404File string // default: "404.html"
	Site404File     string // default: "404.html"

	// Cache policies applied by file extension.
	HTMLCacheControl  string // default: "no-cache"
	AssetCacheControl string // default: "public, max-age=31536000, immutable"
	OtherCacheControl string // default: "public, max-age=3600"
}

func (o *Options) setDefaults() {
	if o.MaintenanceFile == "" {
		o.MaintenanceFile = "maintenance.html"
	}
	if o.Fallback404File == "" {
		o.Fallback404File = "404.html"
	}
	if o.Site404File == "" {
		o.Site404File = "404.html"
	}
	if o.HTMLCacheControl == "" {
		o.HTMLCacheControl = "no-cache"
	}
	if o.AssetCacheControl == "" {
		o.AssetCacheControl = "public, max-age=31536000, immutable"
	}
	if o.OtherCacheControl == "" {
		o.OtherCacheControl = "public, max-age=3600"
	}
}

func (o *Options) validate() error {
	if o.Content == nil {
		return fmt.Errorf("%w: Content is nil", ErrInvalidOptions)
	}
	if o.FallbackFS == nil {
		return fmt.Errorf("%w: FallbackFS is nil", ErrInvalidOptions)
	}
	// Ensure maintenance exists (fail fast on boot if mispackaged).
	if _, err := fs.Stat(o.FallbackFS, o.MaintenanceFile); err != nil {
		return fmt.Errorf("%w: missing %q in fallback FS: %v", ErrInvalidOptions, o.MaintenanceFile, err)
	}
	// Fallback 404 is optional; we’ll degrade to plain text if missing.
	return nil
}
