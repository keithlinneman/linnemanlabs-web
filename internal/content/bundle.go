// internal/content/bundle.go
package content

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/keithlinneman/linnemanlabs-web/internal/xerrors"
)

// copyWithHash copies from src to dst while computing SHA256
func copyWithHash(dst io.Writer, src io.Reader) (written int64, hash string, err error) {
	h := sha256.New()
	w := io.MultiWriter(dst, h)

	written, err = io.Copy(w, src)
	if err != nil {
		return written, "", err
	}

	return written, hex.EncodeToString(h.Sum(nil)), nil
}

// extractTarGz extracts a .tar.gz file to the destination directory
func extractTarGz(src, dst string) error {
	f, err := os.Open(src)
	if err != nil {
		return xerrors.Wrapf(err, "open %s", src)
	}
	defer f.Close()

	gr, err := gzip.NewReader(f)
	if err != nil {
		return xerrors.Wrap(err, "gzip reader")
	}
	defer gr.Close()

	tr := tar.NewReader(gr)

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return xerrors.Wrap(err, "read tar header")
		}

		// sanitize path to prevent directory traversal
		target, err := sanitizeTarPath(dst, hdr.Name)
		if err != nil {
			return err
		}

		switch hdr.Typeflag {
		// handle directories
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0750); err != nil {
				return xerrors.Wrapf(err, "mkdir %s", target)
			}

		// handle regular files
		case tar.TypeReg:
			// ensure parent directory exists
			if err := os.MkdirAll(filepath.Dir(target), 0750); err != nil {
				return xerrors.Wrapf(err, "mkdir parent of %s", target)
			}

			if err := writeFile(target, tr, 0640); err != nil {
				return err
			}

		// no need for symlinks currently
		// case tar.TypeSymlink:
		// 	// validate symlink target doesnt escape
		// 	linkTarget := hdr.Linkname
		// 	if filepath.IsAbs(linkTarget) {
		// 		return xerrors.Newf("absolute symlink not allowed: %s -> %s", hdr.Name, linkTarget)
		// 	}
		// 	resolved := filepath.Join(filepath.Dir(target), linkTarget)
		// 	if !strings.HasPrefix(filepath.Clean(resolved), filepath.Clean(dst)) {
		// 		return xerrors.Newf("symlink escapes destination: %s -> %s", hdr.Name, linkTarget)
		// 	}

		// 	// ensure parent directory exists
		// 	if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
		// 		return xerrors.Wrapf(err, "mkdir parent of %s", target)
		// 	}

		// 	if err := os.Symlink(linkTarget, target); err != nil {
		// 		return xerrors.Wrapf(err, "symlink %s -> %s", target, linkTarget)
		// 	}

		default:
			// reject other types (symlinks, hard links, devices, fifos, etc).. need to replace tar with something simpler
			return xerrors.Newf("unsupported file type in archive: %s (type %c)", hdr.Name, hdr.Typeflag)
		}
	}

	return nil
}

// sanitizeTarPath prevents directory traversal attacks
func sanitizeTarPath(dst, name string) (string, error) {
	// clean the name
	name = filepath.Clean(name)

	// reject absolute paths
	if filepath.IsAbs(name) {
		return "", xerrors.Newf("absolute path in tar: %s", name)
	}

	// reject paths with ..
	if strings.Contains(name, "..") {
		return "", xerrors.Newf("path traversal in tar: %s", name)
	}

	target := filepath.Join(dst, name)

	// double-check the result is within dst
	if !strings.HasPrefix(filepath.Clean(target)+string(os.PathSeparator), filepath.Clean(dst)+string(os.PathSeparator)) {
		if filepath.Clean(target) != filepath.Clean(dst) {
			return "", xerrors.Newf("path escapes destination: %s", name)
		}
	}

	return target, nil
}

// writeFile writes a file from the tar reader with size limit
func writeFile(path string, r io.Reader, mode os.FileMode) error {
	// limit file size to prevent decompression bombs (10MB per file)
	const maxFileSize = 10 * 1024 * 1024

	// create file
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return xerrors.Wrapf(err, "create %s", path)
	}
	defer f.Close()

	// copy with size limit
	lr := io.LimitReader(r, maxFileSize+1)
	n, err := io.Copy(f, lr)
	if err != nil {
		return xerrors.Wrapf(err, "write %s", path)
	}
	if n > maxFileSize {
		return xerrors.Newf("file too large: %s (%d bytes)", path, n)
	}

	return nil
}

// ComputeFileHash computes SHA256 of a file
func ComputeFileHash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

// ValidateBundle checks if a bundle file matches the expected hash
func ValidateBundle(path, expectedHash string) error {
	hash, err := ComputeFileHash(path)
	if err != nil {
		return xerrors.Wrapf(err, "compute hash of %s", path)
	}

	if hash != expectedHash {
		return fmt.Errorf("hash mismatch: expected %s, got %s", expectedHash, hash)
	}

	return nil
}
