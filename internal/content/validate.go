// internal/content/validate.go
//

package content

import (
	"io/fs"

	"github.com/keithlinneman/linnemanlabs-web/internal/xerrors"
)

// ValidationOptions controls which checks ValidateSnapshot performs.
// Zero value is a sensible default: index.html required, no minimum file
// count, provenance optional.
type ValidationOptions struct {
	// MinFiles rejects bundles with fewer than this many files.
	// 0 disables the check.
	MinFiles int

	// RequireProvenance fails validation if provenance.json is missing
	// or unparseable. When false, missing provenance is a warning, not
	// an error.
	RequireProvenance bool
}

// DefaultValidationOptions returns the recommended production defaults.
func DefaultValidationOptions() ValidationOptions {
	return ValidationOptions{
		MinFiles:          10,
		RequireProvenance: true,
	}
}

// ValidateSnapshot performs health/sanity checks on a content bundle
// before it is swapped into the active Manager. Used by the Watcher
// to prevent serving broken or empty content.
// Returns nil if all checks pass, or an error describing the first failure.
func ValidateSnapshot(snap *Snapshot, opts ValidationOptions) error {
	if snap == nil {
		return xerrors.New("validate: snapshot is nil")
	}

	// FS must be set
	if snap.FS == nil {
		return xerrors.New("validate: snapshot has nil filesystem")
	}

	// index.html must exist and be non-empty
	if err := checkIndexHTML(snap.FS); err != nil {
		return err
	}

	// minimum file count
	if opts.MinFiles > 0 {
		count, err := countFiles(snap.FS)
		if err != nil {
			return xerrors.Wrap(err, "validate: counting files")
		}
		if count < opts.MinFiles {
			return xerrors.Newf("validate: bundle has %d files, minimum is %d", count, opts.MinFiles)
		}
	}

	// provenance checks
	if snap.Provenance == nil && opts.RequireProvenance {
		return xerrors.New("validate: provenance.json is required but missing")
	}

	return nil
}

// checkIndexHTML verifies index.html exists and has content.
func checkIndexHTML(fsys fs.FS) error {
	f, err := fsys.Open("index.html")
	if err != nil {
		return xerrors.Wrap(err, "validate: index.html not found")
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return xerrors.Wrap(err, "validate: cannot stat index.html")
	}
	if info.Size() == 0 {
		return xerrors.New("validate: index.html is empty")
	}

	return nil
}

// countFiles walks the filesystem and returns the total file count
// (not counting directories).
func countFiles(fsys fs.FS) (int, error) {
	count := 0
	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			count++
		}
		return nil
	})
	return count, err
}
