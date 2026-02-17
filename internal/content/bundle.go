// internal/content/bundle.go
package content

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing/fstest"

	"github.com/keithlinneman/linnemanlabs-web/internal/cryptoutil"
	"github.com/keithlinneman/linnemanlabs-web/internal/xerrors"
)

const (
	// maxBundleSize is the maximum size of a compressed content bundle from s3
	maxBundleSize int64 = 50 * 1024 * 1024 // 50MB

	// maxSingleFile is the maximum size of a single file in the bundle
	maxSingleFile int64 = 10 * 1024 * 1024 // 10MB

	// maxTotalExtract is the maximum total size of extracted content
	maxTotalExtract int64 = 100 * 1024 * 1024 // 100MB
)

// readWithHash reads all bytes from r up to maxSize, computing SHA256
// as it reads. Returns the data, hex-encoded hash, and any error.
// Used by LoadHash to verify bundle integrity without temp files.
func readWithHash(r io.Reader, maxSize int64) ([]byte, string, error) {
	h := sha256.New()
	lr := io.LimitReader(r, maxSize+1)
	tr := io.TeeReader(lr, h)

	data, err := io.ReadAll(tr)
	if err != nil {
		return nil, "", err
	}
	if int64(len(data)) > maxSize {
		return nil, "", fmt.Errorf("content exceeds max size (%d bytes, limit %d)", len(data), maxSize)
	}

	return data, hex.EncodeToString(h.Sum(nil)), nil
}

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

// extractTarGzToMem extracts a .tar.gz file to an in-memory filesystem
func extractTarGzToMem(data []byte) (fs.FS, error) {
	gr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("open gzip: %w", err)
	}
	defer gr.Close()

	mfs := make(fstest.MapFS)
	tr := tar.NewReader(gr)

	var totalBytes int64

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read tar header: %w", err)
		}

		// clean and validate the path - same rules as disk extraction
		cleanName := path.Clean(hdr.Name)
		if cleanName == "." || cleanName == "" {
			continue
		}
		if path.IsAbs(cleanName) {
			return nil, fmt.Errorf("absolute path in archive: %s", hdr.Name)
		}
		if strings.Contains(cleanName, "..") {
			return nil, fmt.Errorf("path traversal in archive: %s", hdr.Name)
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			// directories are implicit in MapFS - skip
			continue

		case tar.TypeReg:
			if hdr.Size > maxSingleFile {
				return nil, fmt.Errorf("file %s exceeds max size (%d > %d)",
					cleanName, hdr.Size, maxSingleFile)
			}

			lr := io.LimitReader(tr, maxSingleFile+1)
			content, err := io.ReadAll(lr)
			if err != nil {
				return nil, fmt.Errorf("read %s: %w", cleanName, err)
			}
			if int64(len(content)) > maxSingleFile {
				return nil, fmt.Errorf("file %s exceeds max size after read", cleanName)
			}

			totalBytes += int64(len(content))
			if totalBytes > maxTotalExtract {
				return nil, fmt.Errorf("total extracted size exceeds limit (%d bytes, max %d)",
					totalBytes, maxTotalExtract)
			}

			mfs[cleanName] = &fstest.MapFile{
				Data: content,
				Mode: hdr.FileInfo().Mode().Perm(),
			}

		default:
			return nil, fmt.Errorf("unsupported file type in archive: %s (type=%d)",
				cleanName, hdr.Typeflag)
		}
	}

	return mfs, nil
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

	if !cryptoutil.HashEqual(hash, expectedHash) {
		return fmt.Errorf("hash mismatch: expected %s, got %s", expectedHash, hash)
	}

	return nil
}
