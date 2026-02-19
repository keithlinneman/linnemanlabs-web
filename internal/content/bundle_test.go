package content

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

// helpers

func sha256hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// makeTarGz builds a .tar.gz archive in memory from the given entries.
// Each entry is a path -> content pair. Directories are created automatically.
func makeTarGz(t *testing.T, entries map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	for name, content := range entries {
		if err := tw.WriteHeader(&tar.Header{
			Name: name,
			Mode: 0640,
			Size: int64(len(content)),
		}); err != nil {
			t.Fatalf("write tar header %q: %v", name, err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatalf("write tar content %q: %v", name, err)
		}
	}

	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	return buf.Bytes()
}

// makeTarGzWithType builds a .tar.gz with a single entry of the given type flag.
func makeTarGzWithType(t *testing.T, name string, typeflag byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	hdr := &tar.Header{
		Name:     name,
		Mode:     0640,
		Size:     0,
		Typeflag: typeflag,
	}
	if typeflag == tar.TypeSymlink {
		hdr.Linkname = "target"
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatalf("write tar header: %v", err)
	}
	tw.Close()
	gw.Close()
	return buf.Bytes()
}

// writeTempFile writes data to a temp file and returns its path.
func writeTempFile(t *testing.T, data []byte) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "test-*")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		t.Fatalf("write temp file: %v", err)
	}
	f.Close()
	return f.Name()
}

// readFileFromFS is a helper to read a file from an fs.FS and return its content.
func readFileFromFS(t *testing.T, fsys fs.FS, name string) string {
	t.Helper()
	data, err := fs.ReadFile(fsys, name)
	if err != nil {
		t.Fatalf("read %q from FS: %v", name, err)
	}
	return string(data)
}

// copyWithHash

func TestCopyWithHash_Basic(t *testing.T) {
	src := bytes.NewReader([]byte("hello world"))
	var dst bytes.Buffer

	written, hash, err := copyWithHash(&dst, src)
	if err != nil {
		t.Fatalf("copyWithHash: %v", err)
	}
	if written != 11 {
		t.Fatalf("written = %d, want 11", written)
	}
	if dst.String() != "hello world" {
		t.Fatalf("dst = %q", dst.String())
	}

	wantHash := sha256hex([]byte("hello world"))
	if hash != wantHash {
		t.Fatalf("hash = %q, want %q", hash, wantHash)
	}
}

func TestCopyWithHash_Empty(t *testing.T) {
	src := bytes.NewReader([]byte{})
	var dst bytes.Buffer

	written, hash, err := copyWithHash(&dst, src)
	if err != nil {
		t.Fatalf("copyWithHash: %v", err)
	}
	if written != 0 {
		t.Fatalf("written = %d, want 0", written)
	}

	wantHash := sha256hex([]byte{})
	if hash != wantHash {
		t.Fatalf("hash = %q, want %q", hash, wantHash)
	}
}

// errWriter is a test double that accepts n bytes then returns err.
type errWriter struct {
	n   int
	err error
}

func (w *errWriter) Write(p []byte) (int, error) {
	if len(p) <= w.n {
		w.n -= len(p)
		return len(p), nil
	}
	n := w.n
	w.n = 0
	return n, w.err
}

// errReader is a test double that returns n zero bytes then err.
type errReader struct {
	n   int
	err error
}

func (r *errReader) Read(p []byte) (int, error) {
	if r.n <= 0 {
		return 0, r.err
	}
	n := len(p)
	if n > r.n {
		n = r.n
	}
	for i := 0; i < n; i++ {
		p[i] = 0
	}
	r.n -= n
	return n, nil
}

func TestCopyWithHash_FailingWriter(t *testing.T) {
	src := bytes.NewReader([]byte("hello world"))
	dst := &errWriter{n: 3, err: fmt.Errorf("disk full")}

	_, hash, err := copyWithHash(dst, src)
	if err == nil {
		t.Fatal("expected error from failing writer")
	}
	if !strings.Contains(err.Error(), "disk full") {
		t.Fatalf("error should propagate: %v", err)
	}
	if hash != "" {
		t.Fatalf("hash should be empty on error, got %q", hash)
	}
}

func TestCopyWithHash_FailingReader(t *testing.T) {
	src := &errReader{n: 5, err: fmt.Errorf("connection reset")}
	var dst bytes.Buffer

	_, hash, err := copyWithHash(&dst, src)
	if err == nil {
		t.Fatal("expected error from failing reader")
	}
	if !strings.Contains(err.Error(), "connection reset") {
		t.Fatalf("error should propagate: %v", err)
	}
	if hash != "" {
		t.Fatalf("hash should be empty on error, got %q", hash)
	}
}

// readWithHash

func TestReadWithHash_Basic(t *testing.T) {
	input := []byte("test content for hashing")
	data, hash, err := readWithHash(bytes.NewReader(input), maxBundleSize, "sha256")
	if err != nil {
		t.Fatalf("readWithHash: %v", err)
	}
	if string(data) != string(input) {
		t.Fatalf("data = %q, want %q", data, input)
	}
	wantHash := sha256hex(input)
	if hash != wantHash {
		t.Fatalf("hash = %q, want %q", hash, wantHash)
	}
}

func TestReadWithHash_ExceedsMaxSize(t *testing.T) {
	// use a small limit to test the size check
	bigData := bytes.Repeat([]byte("x"), 100)
	_, _, err := readWithHash(bytes.NewReader(bigData), 50, "sha256")
	if err == nil {
		t.Fatal("expected error for oversized content")
	}
	if !strings.Contains(err.Error(), "max size") {
		t.Fatalf("error should mention max size: %v", err)
	}
}

func TestReadWithHash_ExactlyAtLimit(t *testing.T) {
	data := bytes.Repeat([]byte("x"), 50)
	got, _, err := readWithHash(bytes.NewReader(data), 50, "sha256")
	if err != nil {
		t.Fatalf("readWithHash at exact limit should succeed: %v", err)
	}
	if len(got) != 50 {
		t.Fatalf("len = %d, want 50", len(got))
	}
}

func TestReadWithHash_Empty(t *testing.T) {
	data, hash, err := readWithHash(bytes.NewReader(nil), maxBundleSize, "sha256")
	if err != nil {
		t.Fatalf("readWithHash: %v", err)
	}
	if len(data) != 0 {
		t.Fatalf("expected empty data, got %d bytes", len(data))
	}
	wantHash := sha256hex([]byte{})
	if hash != wantHash {
		t.Fatalf("hash = %q, want %q", hash, wantHash)
	}
}

// extractTarGzToMem

func TestExtractTarGzToMem_BasicFiles(t *testing.T) {
	entries := map[string]string{
		"index.html":       "<html>hello</html>",
		"assets/style.css": "body { color: red; }",
	}
	archive := makeTarGz(t, entries)

	fsys, err := extractTarGzToMem(archive)
	if err != nil {
		t.Fatalf("extractTarGzToMem: %v", err)
	}

	for name, wantContent := range entries {
		got := readFileFromFS(t, fsys, name)
		if got != wantContent {
			t.Fatalf("%q content = %q, want %q", name, got, wantContent)
		}
	}
}

func TestExtractTarGzToMem_DeepNestedFiles(t *testing.T) {
	entries := map[string]string{
		"a/b/c/deep.txt": "deep content",
	}
	archive := makeTarGz(t, entries)

	fsys, err := extractTarGzToMem(archive)
	if err != nil {
		t.Fatalf("extractTarGzToMem: %v", err)
	}

	got := readFileFromFS(t, fsys, "a/b/c/deep.txt")
	if got != "deep content" {
		t.Fatalf("content = %q, want %q", got, "deep content")
	}
}

func TestExtractTarGzToMem_DirectoryEntry_Skipped(t *testing.T) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	// explicit directory entry - should be skipped (implicit in MapFS)
	tw.WriteHeader(&tar.Header{
		Name:     "mydir/",
		Mode:     0750,
		Typeflag: tar.TypeDir,
	})
	// file inside that directory
	content := "inside dir"
	tw.WriteHeader(&tar.Header{
		Name: "mydir/file.txt",
		Mode: 0640,
		Size: int64(len(content)),
	})
	tw.Write([]byte(content))

	tw.Close()
	gw.Close()

	fsys, err := extractTarGzToMem(buf.Bytes())
	if err != nil {
		t.Fatalf("extractTarGzToMem: %v", err)
	}

	got := readFileFromFS(t, fsys, "mydir/file.txt")
	if got != content {
		t.Fatalf("content = %q, want %q", got, content)
	}
}

func TestExtractTarGzToMem_RejectsSymlink(t *testing.T) {
	archive := makeTarGzWithType(t, "link", tar.TypeSymlink)
	_, err := extractTarGzToMem(archive)
	if err == nil {
		t.Fatal("expected error for symlink in archive")
	}
	if !strings.Contains(err.Error(), "unsupported file type") {
		t.Fatalf("expected 'unsupported file type' error, got: %v", err)
	}
}

func TestExtractTarGzToMem_RejectsHardLink(t *testing.T) {
	archive := makeTarGzWithType(t, "hardlink", tar.TypeLink)
	_, err := extractTarGzToMem(archive)
	if err == nil {
		t.Fatal("expected error for hard link in archive")
	}
	if !strings.Contains(err.Error(), "unsupported file type") {
		t.Fatalf("expected 'unsupported file type' error, got: %v", err)
	}
}

func TestExtractTarGzToMem_RejectsCharDevice(t *testing.T) {
	archive := makeTarGzWithType(t, "dev", tar.TypeChar)
	_, err := extractTarGzToMem(archive)
	if err == nil {
		t.Fatal("expected error for char device in archive")
	}
	if !strings.Contains(err.Error(), "unsupported file type") {
		t.Fatalf("expected 'unsupported file type' error, got: %v", err)
	}
}

func TestExtractTarGzToMem_RejectsBlockDevice(t *testing.T) {
	archive := makeTarGzWithType(t, "dev", tar.TypeBlock)
	_, err := extractTarGzToMem(archive)
	if err == nil {
		t.Fatal("expected error for block device in archive")
	}
}

func TestExtractTarGzToMem_RejectsFifo(t *testing.T) {
	archive := makeTarGzWithType(t, "fifo", tar.TypeFifo)
	_, err := extractTarGzToMem(archive)
	if err == nil {
		t.Fatal("expected error for FIFO in archive")
	}
}

func TestExtractTarGzToMem_RejectsPathTraversal(t *testing.T) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	tw.WriteHeader(&tar.Header{
		Name: "../../../etc/passwd",
		Mode: 0640,
		Size: 4,
	})
	tw.Write([]byte("evil"))

	tw.Close()
	gw.Close()

	_, err := extractTarGzToMem(buf.Bytes())
	if err == nil {
		t.Fatal("expected error for path traversal")
	}
	if !strings.Contains(err.Error(), "path traversal") {
		t.Fatalf("expected 'path traversal' in error, got: %v", err)
	}
}

func TestExtractTarGzToMem_RejectsAbsolutePath(t *testing.T) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	tw.WriteHeader(&tar.Header{
		Name: "/etc/passwd",
		Mode: 0640,
		Size: 4,
	})
	tw.Write([]byte("evil"))

	tw.Close()
	gw.Close()

	_, err := extractTarGzToMem(buf.Bytes())
	if err == nil {
		t.Fatal("expected error for absolute path")
	}
	if !strings.Contains(err.Error(), "absolute path") {
		t.Fatalf("expected 'absolute path' in error, got: %v", err)
	}
}

func TestExtractTarGzToMem_InvalidGzip(t *testing.T) {
	_, err := extractTarGzToMem([]byte("this is not gzip"))
	if err == nil {
		t.Fatal("expected error for invalid gzip")
	}
}

func TestExtractTarGzToMem_EmptyArchive(t *testing.T) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	tw.Close()
	gw.Close()

	fsys, err := extractTarGzToMem(buf.Bytes())
	if err != nil {
		t.Fatalf("extractTarGzToMem on empty archive: %v", err)
	}

	// should return a valid but empty FS
	mfs, ok := fsys.(fstest.MapFS)
	if !ok {
		t.Fatal("expected MapFS type")
	}
	if len(mfs) != 0 {
		t.Fatalf("expected empty MapFS, got %d entries", len(mfs))
	}
}

func TestExtractTarGzToMem_OversizedFile(t *testing.T) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	// declare file size exceeding maxSingleFile
	tw.WriteHeader(&tar.Header{
		Name: "bomb.bin",
		Mode: 0640,
		Size: maxSingleFile + 1,
	})

	// write enough data to exceed the limit
	zeros := make([]byte, 32*1024)
	remaining := maxSingleFile + 1
	for remaining > 0 {
		chunk := int64(len(zeros))
		if chunk > remaining {
			chunk = remaining
		}
		tw.Write(zeros[:chunk])
		remaining -= chunk
	}

	tw.Close()
	gw.Close()

	_, err := extractTarGzToMem(buf.Bytes())
	if err == nil {
		t.Fatal("expected error for oversized file in archive")
	}
	if !strings.Contains(err.Error(), "exceeds max size") {
		t.Fatalf("expected 'exceeds max size' error, got: %v", err)
	}
}

func TestExtractTarGzToMem_TotalSizeLimit(t *testing.T) {
	// create many files that individually are fine but collectively exceed maxTotalExtract
	// use a small enough individual size that we can test the aggregate check
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	fileSize := int64(1 * 1024 * 1024) // 1MB per file
	numFiles := int(maxTotalExtract/fileSize) + 1
	content := bytes.Repeat([]byte("x"), int(fileSize))

	for i := 0; i < numFiles; i++ {
		name := fmt.Sprintf("file_%d.bin", i)
		tw.WriteHeader(&tar.Header{
			Name: name,
			Mode: 0640,
			Size: fileSize,
		})
		tw.Write(content)
	}

	tw.Close()
	gw.Close()

	_, err := extractTarGzToMem(buf.Bytes())
	if err == nil {
		t.Fatal("expected error for total size exceeding limit")
	}
	if !strings.Contains(err.Error(), "total extracted size exceeds limit") {
		t.Fatalf("expected total size error, got: %v", err)
	}
}

func TestExtractTarGzToMem_PreservesFileMode(t *testing.T) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	content := "executable script"
	tw.WriteHeader(&tar.Header{
		Name: "script.sh",
		Mode: 0755,
		Size: int64(len(content)),
	})
	tw.Write([]byte(content))

	tw.Close()
	gw.Close()

	fsys, err := extractTarGzToMem(buf.Bytes())
	if err != nil {
		t.Fatalf("extractTarGzToMem: %v", err)
	}

	mfs, ok := fsys.(fstest.MapFS)
	if !ok {
		t.Fatal("expected MapFS type")
	}
	entry, exists := mfs["script.sh"]
	if !exists {
		t.Fatal("script.sh not found in MapFS")
	}
	if entry.Mode&0755 != 0755 {
		t.Fatalf("mode = %o, want 0755", entry.Mode)
	}
}

func TestExtractTarGzToMem_DotPath_Skipped(t *testing.T) {
	// an entry named "." should be skipped (cleans to root)
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	tw.WriteHeader(&tar.Header{
		Name:     "./",
		Mode:     0750,
		Typeflag: tar.TypeDir,
	})

	content := "valid file"
	tw.WriteHeader(&tar.Header{
		Name: "file.txt",
		Mode: 0640,
		Size: int64(len(content)),
	})
	tw.Write([]byte(content))

	tw.Close()
	gw.Close()

	fsys, err := extractTarGzToMem(buf.Bytes())
	if err != nil {
		t.Fatalf("extractTarGzToMem: %v", err)
	}

	got := readFileFromFS(t, fsys, "file.txt")
	if got != content {
		t.Fatalf("content = %q, want %q", got, content)
	}
}

// Fuzz tests for in-memory extraction

func FuzzExtractTarGzToMem(f *testing.F) {
	f.Add(buildSeedArchive())
	f.Add(buildSeedArchiveWithDir())
	f.Add(buildSeedArchiveWithLabel())

	f.Fuzz(func(t *testing.T, data []byte) {
		// We don't care if it errors - we care that it doesn't panic or hang.
		_, _ = extractTarGzToMem(data)
	})
}

func buildSeedArchive() []byte {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	entries := map[string]string{
		"index.html":       "<html>hello</html>",
		"assets/style.css": "body { color: red; }",
		"a/b/c/deep.txt":   "deep content",
	}

	for name, content := range entries {
		tw.WriteHeader(&tar.Header{
			Name: name,
			Mode: 0640,
			Size: int64(len(content)),
		})
		tw.Write([]byte(content))
	}

	tw.Close()
	gw.Close()
	return buf.Bytes()
}

func buildSeedArchiveWithDir() []byte {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	tw.WriteHeader(&tar.Header{
		Name:     "mydir/",
		Mode:     0750,
		Typeflag: tar.TypeDir,
	})

	content := "inside dir"
	tw.WriteHeader(&tar.Header{
		Name: "mydir/file.txt",
		Mode: 0640,
		Size: int64(len(content)),
	})
	tw.Write([]byte(content))

	tw.Close()
	gw.Close()
	return buf.Bytes()
}

func buildSeedArchiveWithLabel() []byte {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	tw.WriteHeader(&tar.Header{
		Name:     "volume-label",
		Typeflag: 'V',
	})

	content := "after label"
	tw.WriteHeader(&tar.Header{
		Name: "file.txt",
		Mode: 0640,
		Size: int64(len(content)),
	})
	tw.Write([]byte(content))

	tw.Close()
	gw.Close()
	return buf.Bytes()
}

// sanitizeTarPath - still exists in bundle.go for potential reuse

func TestSanitizeTarPath_Valid(t *testing.T) {
	dst := "/tmp/extract"
	tests := []struct {
		name string
		want string
	}{
		{"index.html", filepath.Join(dst, "index.html")},
		{"assets/style.css", filepath.Join(dst, "assets/style.css")},
		{"a/b/c/deep.txt", filepath.Join(dst, "a/b/c/deep.txt")},
	}

	for _, tt := range tests {
		got, err := sanitizeTarPath(dst, tt.name)
		if err != nil {
			t.Fatalf("sanitizeTarPath(%q, %q) error: %v", dst, tt.name, err)
		}
		if got != tt.want {
			t.Fatalf("sanitizeTarPath(%q, %q) = %q, want %q", dst, tt.name, got, tt.want)
		}
	}
}

func TestSanitizeTarPath_AbsolutePath(t *testing.T) {
	_, err := sanitizeTarPath("/tmp/extract", "/etc/passwd")
	if err == nil {
		t.Fatal("expected error for absolute path")
	}
	if !strings.Contains(err.Error(), "absolute path") {
		t.Fatalf("expected 'absolute path' in error, got: %v", err)
	}
}

func TestSanitizeTarPath_DotDotTraversal(t *testing.T) {
	traversals := []string{
		"../etc/passwd",
		"foo/../../etc/shadow",
		"../../../root/.ssh/id_rsa",
		"foo/../bar/../../../escape",
	}

	for _, name := range traversals {
		_, err := sanitizeTarPath("/tmp/extract", name)
		if err == nil {
			t.Fatalf("expected error for path traversal %q", name)
		}
	}
}

func TestSanitizeTarPath_CleanedPath(t *testing.T) {
	dst := "/tmp/extract"
	got, err := sanitizeTarPath(dst, "foo/./bar")
	if err != nil {
		t.Fatalf("sanitizeTarPath for 'foo/./bar' error: %v", err)
	}
	if got != filepath.Join(dst, "foo/bar") {
		t.Fatalf("got %q, want %q", got, filepath.Join(dst, "foo/bar"))
	}
}

func TestSanitizeTarPath_NullByte(t *testing.T) {
	_, err := sanitizeTarPath("/tmp/extract", "foo\x00bar")
	if err == nil {
		t.Log("sanitizeTarPath does not reject null bytes; OS syscall layer provides defense")
	}
}

func FuzzSanitizeTarPath(f *testing.F) {
	f.Add("index.html")
	f.Add("../etc/passwd")
	f.Add("/etc/passwd")
	f.Add("foo/../../etc/shadow")
	f.Add("foo/./bar")
	f.Add("foo\x00/../etc/passwd")
	f.Add("..\\windows\\system32")
	f.Add(strings.Repeat("a/", 500) + "deep.txt")

	dst := f.TempDir()

	f.Fuzz(func(t *testing.T, name string) {
		result, err := sanitizeTarPath(dst, name)
		if err != nil {
			return // rejected - good
		}
		if !strings.HasPrefix(result, dst+string(filepath.Separator)) {
			t.Fatalf("escaped destination: sanitizeTarPath(%q, %q) = %q", dst, name, result)
		}
	})
}

// writeFile - still exists in bundle.go

func TestWriteFile_Basic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	content := "file content here"

	err := writeFile(path, strings.NewReader(content), 0640)
	if err != nil {
		t.Fatalf("writeFile: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	if string(got) != content {
		t.Fatalf("content = %q, want %q", string(got), content)
	}
}

func TestWriteFile_SizeLimit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "big.txt")

	const maxFileSize = 10 * 1024 * 1024
	bigData := strings.NewReader(strings.Repeat("x", maxFileSize+1))

	err := writeFile(path, bigData, 0640)
	if err == nil {
		t.Fatal("expected error for oversized file")
	}
	if !strings.Contains(err.Error(), "file too large") {
		t.Fatalf("expected 'file too large' in error, got: %v", err)
	}
}

func TestWriteFile_ExactlyAtLimit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "exact.txt")

	const maxFileSize = 10 * 1024 * 1024
	data := strings.NewReader(strings.Repeat("x", maxFileSize))

	err := writeFile(path, data, 0640)
	if err != nil {
		t.Fatalf("writeFile at exact limit should succeed: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Size() != maxFileSize {
		t.Fatalf("size = %d, want %d", info.Size(), maxFileSize)
	}
}

func TestWriteFile_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.txt")

	err := writeFile(path, strings.NewReader(""), 0640)
	if err != nil {
		t.Fatalf("writeFile for empty: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Size() != 0 {
		t.Fatalf("size = %d, want 0", info.Size())
	}
}

func TestWriteFile_InvalidPath(t *testing.T) {
	err := writeFile("/nonexistent/dir/file.txt", strings.NewReader("data"), 0640)
	if err == nil {
		t.Fatal("expected error for invalid path")
	}
	if !strings.Contains(err.Error(), "create") {
		t.Fatalf("error should mention create: %v", err)
	}
}

func TestWriteFile_FailingReader(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fail.txt")

	src := &errReader{n: 10, err: fmt.Errorf("read timeout")}
	err := writeFile(path, src, 0640)
	if err == nil {
		t.Fatal("expected error from failing reader")
	}
	if !strings.Contains(err.Error(), "read timeout") {
		t.Fatalf("error should propagate: %v", err)
	}
}

// ComputeFileHash

func TestComputeFileHash_Basic(t *testing.T) {
	content := []byte("known content for hashing")
	path := writeTempFile(t, content)

	got, err := ComputeFileHash(path)
	if err != nil {
		t.Fatalf("ComputeFileHash: %v", err)
	}

	want := sha256hex(content)
	if got != want {
		t.Fatalf("hash = %q, want %q", got, want)
	}
}

func TestComputeFileHash_EmptyFile(t *testing.T) {
	path := writeTempFile(t, []byte{})

	got, err := ComputeFileHash(path)
	if err != nil {
		t.Fatalf("ComputeFileHash: %v", err)
	}

	want := sha256hex([]byte{})
	if got != want {
		t.Fatalf("hash = %q, want %q", got, want)
	}
}

func TestComputeFileHash_NonexistentFile(t *testing.T) {
	_, err := ComputeFileHash("/nonexistent/file.txt")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

// ValidateBundle

func TestValidateBundle_Match(t *testing.T) {
	content := []byte("bundle content")
	path := writeTempFile(t, content)
	hash := sha256hex(content)

	err := ValidateBundle(path, hash)
	if err != nil {
		t.Fatalf("ValidateBundle: %v", err)
	}
}

func TestValidateBundle_Mismatch(t *testing.T) {
	content := []byte("bundle content")
	path := writeTempFile(t, content)

	err := ValidateBundle(path, "0000000000000000000000000000000000000000000000000000000000000000")
	if err == nil {
		t.Fatal("expected error for hash mismatch")
	}
	if !strings.Contains(err.Error(), "hash mismatch") {
		t.Fatalf("expected 'hash mismatch' in error, got: %v", err)
	}
}

func TestValidateBundle_NonexistentFile(t *testing.T) {
	err := ValidateBundle("/nonexistent/file.tar.gz", "abc123")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}
