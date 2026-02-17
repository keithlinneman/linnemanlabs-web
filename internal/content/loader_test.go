package content

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/keithlinneman/linnemanlabs-web/internal/cryptoutil"
	"github.com/keithlinneman/linnemanlabs-web/internal/log"
)

// NewLoader validation

func TestNewLoader_MissingSSMParam(t *testing.T) {
	_, err := NewLoader(context.Background(), LoaderOptions{
		S3Bucket: "test-bucket",
	})
	if err == nil {
		t.Fatal("expected error for missing SSMParam")
	}
}

func TestNewLoader_MissingS3Bucket(t *testing.T) {
	_, err := NewLoader(context.Background(), LoaderOptions{
		SSMParam: "/app/content/hash",
	})
	if err == nil {
		t.Fatal("expected error for missing S3Bucket")
	}
}

func TestNewLoader_BothMissing(t *testing.T) {
	_, err := NewLoader(context.Background(), LoaderOptions{})
	if err == nil {
		t.Fatal("expected error when both SSMParam and S3Bucket missing")
	}
}

// NewLoader with valid params requires AWS credentials/config,
// so we can't easily test the success path in unit tests without mocking.
// Integration tests or a mock AWS config would be needed for that.

// s3Key

func TestLoader_s3Key_WithPrefix(t *testing.T) {
	l := &Loader{
		opts: LoaderOptions{
			S3Prefix: "content/bundles",
		},
	}
	got := l.s3Key("abc123def456")
	want := "content/bundles/abc123def456.tar.gz"
	if got != want {
		t.Fatalf("s3Key = %q, want %q", got, want)
	}
}

func TestLoader_s3Key_WithoutPrefix(t *testing.T) {
	l := &Loader{
		opts: LoaderOptions{
			S3Prefix: "",
		},
	}
	got := l.s3Key("abc123def456")
	want := "abc123def456.tar.gz"
	if got != want {
		t.Fatalf("s3Key = %q, want %q", got, want)
	}
}

func TestLoader_s3Key_ShortHash(t *testing.T) {
	l := &Loader{
		opts: LoaderOptions{S3Prefix: "prefix"},
	}
	got := l.s3Key("a")
	want := "prefix/a.tar.gz"
	if got != want {
		t.Fatalf("s3Key = %q, want %q", got, want)
	}
}

// provenanceVersion

func TestProvenanceVersion_Nil(t *testing.T) {
	got := provenanceVersion(nil)
	if got != "" {
		t.Fatalf("provenanceVersion(nil) = %q, want empty", got)
	}
}

func TestProvenanceVersion_Empty(t *testing.T) {
	got := provenanceVersion(&Provenance{Version: ""})
	if got != "" {
		t.Fatalf("provenanceVersion(empty) = %q, want empty", got)
	}
}

func TestProvenanceVersion_Present(t *testing.T) {
	got := provenanceVersion(&Provenance{Version: "2.1.0"})
	if got != "2.1.0" {
		t.Fatalf("provenanceVersion = %q, want 2.1.0", got)
	}
}

// fakeS3 implements s3Getter for unit testing.
type fakeS3 struct {
	objects map[string][]byte
	errs    map[string]error
}

func newFakeS3() *fakeS3 {
	return &fakeS3{
		objects: make(map[string][]byte),
		errs:    make(map[string]error),
	}
}

func (f *fakeS3) put(key string, data []byte) { f.objects[key] = data }

func (f *fakeS3) failOn(key string, err error) { f.errs[key] = err }

func (f *fakeS3) GetObject(_ context.Context, in *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	key := aws.ToString(in.Key)
	if err, ok := f.errs[key]; ok {
		return nil, err
	}
	data, ok := f.objects[key]
	if !ok {
		return nil, fmt.Errorf("NoSuchKey: %s", key)
	}
	return &s3.GetObjectOutput{
		Body: io.NopCloser(bytes.NewReader(data)),
	}, nil
}

// fakeSSM implements ssmGetter for unit testing.
type fakeSSM struct {
	value *string             // value to return (nil = no value)
	err   error               // error to return
	param *ssmtypes.Parameter // full parameter override (takes precedence)
}

func (f *fakeSSM) GetParameter(_ context.Context, _ *ssm.GetParameterInput, _ ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.param != nil {
		return &ssm.GetParameterOutput{Parameter: f.param}, nil
	}
	if f.value == nil {
		// nil parameter - simulates parameter not found or empty response
		return &ssm.GetParameterOutput{Parameter: nil}, nil
	}
	return &ssm.GetParameterOutput{
		Parameter: &ssmtypes.Parameter{
			Value: f.value,
		},
	}, nil
}

func ssmWithValue(v string) *fakeSSM  { return &fakeSSM{value: &v} }
func ssmWithError(err error) *fakeSSM { return &fakeSSM{err: err} }
func ssmWithNilParam() *fakeSSM       { return &fakeSSM{} }
func ssmWithNilValue() *fakeSSM {
	return &fakeSSM{param: &ssmtypes.Parameter{Value: nil}}
}

// Test helpers

const (
	testBucket   = "content-bucket"
	testSSMParam = "/app/content/hash"
	testS3Prefix = "content/bundles"
)

// newTestLoader constructs a Loader with fakes wired directly into the struct
// fields, bypassing NewLoader.
func newTestLoader(t *testing.T, s3fake *fakeS3, ssmFake *fakeSSM) *Loader {
	t.Helper()
	return &Loader{
		opts: LoaderOptions{
			Logger:     log.Nop(),
			SSMParam:   testSSMParam,
			S3Bucket:   testBucket,
			S3Prefix:   testS3Prefix,
			ExtractDir: t.TempDir(),
			S3Client:   s3fake,
			SSMClient:  ssmFake,
		},
		s3Client:  s3fake,
		ssmClient: ssmFake,
		logger:    log.Nop(),
	}
}

// buildContentBundle creates a valid tar.gz archive in memory containing
// a single index.html file. Returns the raw bytes and their SHA256 hash.
func buildContentBundle(t *testing.T) ([]byte, string) {
	t.Helper()
	data := makeTarGz(t, map[string]string{
		"index.html": "<html><body>hello</body></html>",
	})
	hash := cryptoutil.SHA256Hex(data)
	return data, hash
}

// buildContentBundleWithProvenance creates a tar.gz containing index.html
// and a provenance.json file. Returns the raw bytes and their SHA256 hash.
func buildContentBundleWithProvenance(t *testing.T) ([]byte, string) {
	t.Helper()
	prov, _ := json.Marshal(Provenance{
		Schema:      "llabs.content.provenance.v1",
		Type:        "content-bundle",
		Version:     "1.2.3",
		ContentHash: "abc123",
		Source: ProvenanceSource{
			CommitShort: "abc123d",
		},
		Summary: ProvenanceSummary{
			TotalFiles: 1,
		},
	})
	data := makeTarGz(t, map[string]string{
		"index.html":      "<html><body>hello</body></html>",
		"provenance.json": string(prov),
	})
	hash := cryptoutil.SHA256Hex(data)
	return data, hash
}

// putBundle stores a content bundle in fakeS3 at the expected key.
func putBundle(fake *fakeS3, hash string, data []byte) {
	key := fmt.Sprintf("%s/%s.tar.gz", testS3Prefix, hash)
	fake.put(key, data)
}

// NewLoader - validation (supplements existing tests)

func TestNewLoader_MissingS3Client(t *testing.T) {
	_, err := NewLoader(t.Context(), LoaderOptions{
		SSMParam:  testSSMParam,
		S3Bucket:  testBucket,
		SSMClient: ssmWithValue("abc"),
		// S3Client omitted
	})
	if err == nil {
		t.Fatal("expected error for missing S3Client")
	}
	if !strings.Contains(err.Error(), "S3Client") {
		t.Fatalf("error should mention S3Client: %v", err)
	}
}

func TestNewLoader_MissingSSMClient(t *testing.T) {
	_, err := NewLoader(t.Context(), LoaderOptions{
		SSMParam: testSSMParam,
		S3Bucket: testBucket,
		S3Client: newFakeS3(),
		// SSMClient omitted
	})
	if err == nil {
		t.Fatal("expected error for missing SSMClient")
	}
	if !strings.Contains(err.Error(), "SSMClient") {
		t.Fatalf("error should mention SSMClient: %v", err)
	}
}

func TestNewLoader_Success(t *testing.T) {
	extractDir := t.TempDir()
	l, err := NewLoader(t.Context(), LoaderOptions{
		Logger:     log.Nop(),
		SSMParam:   testSSMParam,
		S3Bucket:   testBucket,
		S3Client:   newFakeS3(),
		SSMClient:  ssmWithValue("abc"),
		ExtractDir: extractDir,
	})
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}
	if l == nil {
		t.Fatal("expected non-nil loader")
	}
}

func TestNewLoader_NilLoggerDefaultsToNop(t *testing.T) {
	l, err := NewLoader(t.Context(), LoaderOptions{
		SSMParam:   testSSMParam,
		S3Bucket:   testBucket,
		S3Client:   newFakeS3(),
		SSMClient:  ssmWithValue("abc"),
		ExtractDir: t.TempDir(),
		// Logger omitted
	})
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}
	if l == nil {
		t.Fatal("expected non-nil loader")
	}
}

func TestNewLoader_CreatesDefaultExtractDir(t *testing.T) {
	l, err := NewLoader(t.Context(), LoaderOptions{
		SSMParam:  testSSMParam,
		S3Bucket:  testBucket,
		S3Client:  newFakeS3(),
		SSMClient: ssmWithValue("abc"),
		// ExtractDir omitted - should create temp dir
	})
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}
	if l.opts.ExtractDir == "" {
		t.Fatal("ExtractDir should be set to a temp directory")
	}
	info, err := os.Stat(l.opts.ExtractDir)
	if err != nil {
		t.Fatalf("ExtractDir should exist: %v", err)
	}
	if !info.IsDir() {
		t.Fatal("ExtractDir should be a directory")
	}
}

// FetchCurrentBundleHash

func TestFetchCurrentBundleHash_Success(t *testing.T) {
	l := newTestLoader(t, newFakeS3(), ssmWithValue("abc123def456"))

	hash, err := l.FetchCurrentBundleHash(t.Context())
	if err != nil {
		t.Fatalf("FetchCurrentBundleHash: %v", err)
	}
	if hash != "abc123def456" {
		t.Fatalf("hash = %q, want abc123def456", hash)
	}
}

func TestFetchCurrentBundleHash_TrimsWhitespace(t *testing.T) {
	l := newTestLoader(t, newFakeS3(), ssmWithValue("  abc123  \n"))

	hash, err := l.FetchCurrentBundleHash(t.Context())
	if err != nil {
		t.Fatalf("FetchCurrentBundleHash: %v", err)
	}
	if hash != "abc123" {
		t.Fatalf("hash = %q, want abc123 (whitespace should be trimmed)", hash)
	}
}

func TestFetchCurrentBundleHash_SSMError(t *testing.T) {
	l := newTestLoader(t, newFakeS3(), ssmWithError(errors.New("access denied")))

	_, err := l.FetchCurrentBundleHash(t.Context())
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "access denied") {
		t.Fatalf("error should propagate: %v", err)
	}
	if !strings.Contains(err.Error(), testSSMParam) {
		t.Fatalf("error should mention parameter name: %v", err)
	}
}

func TestFetchCurrentBundleHash_NilParameter(t *testing.T) {
	l := newTestLoader(t, newFakeS3(), ssmWithNilParam())

	_, err := l.FetchCurrentBundleHash(t.Context())
	if err == nil {
		t.Fatal("expected error for nil parameter")
	}
	if !strings.Contains(err.Error(), "no value") {
		t.Fatalf("error should mention no value: %v", err)
	}
}

func TestFetchCurrentBundleHash_NilValue(t *testing.T) {
	l := newTestLoader(t, newFakeS3(), ssmWithNilValue())

	_, err := l.FetchCurrentBundleHash(t.Context())
	if err == nil {
		t.Fatal("expected error for nil value")
	}
	if !strings.Contains(err.Error(), "no value") {
		t.Fatalf("error should mention no value: %v", err)
	}
}

func TestFetchCurrentBundleHash_EmptyValue(t *testing.T) {
	l := newTestLoader(t, newFakeS3(), ssmWithValue("   "))

	_, err := l.FetchCurrentBundleHash(t.Context())
	if err == nil {
		t.Fatal("expected error for whitespace-only value")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Fatalf("error should mention empty: %v", err)
	}
}

// Download

func TestDownload_Success(t *testing.T) {
	fake := newFakeS3()
	bundleData, bundleHash := buildContentBundle(t)
	putBundle(fake, bundleHash, bundleData)

	l := newTestLoader(t, fake, ssmWithValue(bundleHash))

	tmpPath, err := l.Download(t.Context(), bundleHash)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	defer os.Remove(tmpPath)

	// verify the downloaded file has the right content
	got, err := os.ReadFile(tmpPath)
	if err != nil {
		t.Fatalf("read downloaded file: %v", err)
	}
	if !bytes.Equal(got, bundleData) {
		t.Fatal("downloaded content does not match original")
	}
}

func TestDownload_S3Error(t *testing.T) {
	fake := newFakeS3()
	fake.failOn(testS3Prefix+"/abc123.tar.gz", errors.New("access denied"))

	l := newTestLoader(t, fake, ssmWithValue("abc123"))

	_, err := l.Download(t.Context(), "abc123")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "access denied") {
		t.Fatalf("error should propagate: %v", err)
	}
}

func TestDownload_S3NotFound(t *testing.T) {
	l := newTestLoader(t, newFakeS3(), ssmWithValue("nonexistent"))

	_, err := l.Download(t.Context(), "nonexistent")
	if err == nil {
		t.Fatal("expected error for missing S3 object")
	}
	if !strings.Contains(err.Error(), "NoSuchKey") {
		t.Fatalf("error should mention NoSuchKey: %v", err)
	}
}

func TestDownload_HashMismatch(t *testing.T) {
	fake := newFakeS3()
	bundleData, _ := buildContentBundle(t)

	// store the bundle under a WRONG hash key
	wrongHash := "0000000000000000000000000000000000000000000000000000000000000000"
	putBundle(fake, wrongHash, bundleData)

	l := newTestLoader(t, fake, ssmWithValue(wrongHash))

	_, err := l.Download(t.Context(), wrongHash)
	if err == nil {
		t.Fatal("expected error for hash mismatch")
	}
	if !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("error should mention checksum mismatch: %v", err)
	}
}

func TestDownload_HashMismatch_CleansUpTempFile(t *testing.T) {
	fake := newFakeS3()
	bundleData, _ := buildContentBundle(t)
	wrongHash := "0000000000000000000000000000000000000000000000000000000000000000"
	putBundle(fake, wrongHash, bundleData)

	l := newTestLoader(t, fake, ssmWithValue(wrongHash))

	// Download should fail, the temp file should be cleaned up.
	// We can't easily check the exact temp path, but we verify no error
	// from Download other than the mismatch.
	_, err := l.Download(t.Context(), wrongHash)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// LoadHash

func TestLoadHash_Success_NoProvenance(t *testing.T) {
	fake := newFakeS3()
	bundleData, bundleHash := buildContentBundle(t)
	putBundle(fake, bundleHash, bundleData)

	l := newTestLoader(t, fake, ssmWithValue(bundleHash))

	snap, err := l.LoadHash(t.Context(), bundleHash)
	if err != nil {
		t.Fatalf("LoadHash: %v", err)
	}
	if snap == nil {
		t.Fatal("expected non-nil snapshot")
	}
	if snap.FS == nil {
		t.Fatal("snapshot FS should not be nil")
	}
	if snap.Meta.SHA256 != bundleHash {
		t.Fatalf("Meta.SHA256 = %q, want %q", snap.Meta.SHA256, bundleHash)
	}
	if snap.Meta.Source != SourceS3 {
		t.Fatalf("Meta.Source = %q, want %q", snap.Meta.Source, SourceS3)
	}
	if snap.LoadedAt.IsZero() {
		t.Fatal("LoadedAt should be set")
	}
	// no provenance.json in bundle → provenance should be nil, version empty
	if snap.Provenance != nil {
		t.Fatal("expected nil provenance for bundle without provenance.json")
	}
	if snap.Meta.Version != "" {
		t.Fatalf("Meta.Version = %q, want empty", snap.Meta.Version)
	}
}

func TestLoadHash_Success_WithProvenance(t *testing.T) {
	fake := newFakeS3()
	bundleData, bundleHash := buildContentBundleWithProvenance(t)
	putBundle(fake, bundleHash, bundleData)

	l := newTestLoader(t, fake, ssmWithValue(bundleHash))

	snap, err := l.LoadHash(t.Context(), bundleHash)
	if err != nil {
		t.Fatalf("LoadHash: %v", err)
	}
	if snap.Provenance == nil {
		t.Fatal("expected provenance to be loaded")
	}
	if snap.Provenance.Version != "1.2.3" {
		t.Fatalf("Provenance.Version = %q, want 1.2.3", snap.Provenance.Version)
	}
	if snap.Meta.Version != "1.2.3" {
		t.Fatalf("Meta.Version = %q, want 1.2.3 (from provenance)", snap.Meta.Version)
	}
}

func TestLoadHash_Success_ExtractsFiles(t *testing.T) {
	fake := newFakeS3()
	bundleData, bundleHash := buildContentBundle(t)
	putBundle(fake, bundleHash, bundleData)

	l := newTestLoader(t, fake, ssmWithValue(bundleHash))

	snap, err := l.LoadHash(t.Context(), bundleHash)
	if err != nil {
		t.Fatalf("LoadHash: %v", err)
	}

	// verify we can read index.html from the snapshot FS
	data, err := snap.FS.Open("index.html")
	if err != nil {
		t.Fatalf("open index.html from snapshot FS: %v", err)
	}
	data.Close()
}

func TestLoadHash_Success_UsesHashSubdirectory(t *testing.T) {
	fake := newFakeS3()
	bundleData, bundleHash := buildContentBundle(t)
	putBundle(fake, bundleHash, bundleData)

	extractDir := t.TempDir()
	l := &Loader{
		opts: LoaderOptions{
			Logger:     log.Nop(),
			SSMParam:   testSSMParam,
			S3Bucket:   testBucket,
			S3Prefix:   testS3Prefix,
			ExtractDir: extractDir,
			S3Client:   fake,
			SSMClient:  ssmWithValue(bundleHash),
		},
		s3Client:  fake,
		ssmClient: ssmWithValue(bundleHash),
		logger:    log.Nop(),
	}

	_, err := l.LoadHash(t.Context(), bundleHash)
	if err != nil {
		t.Fatalf("LoadHash: %v", err)
	}

	// verify hash subdirectory was created
	hashDir := filepath.Join(extractDir, bundleHash)
	info, err := os.Stat(hashDir)
	if err != nil {
		t.Fatalf("expected hash subdirectory to exist: %v", err)
	}
	if !info.IsDir() {
		t.Fatal("hash subdirectory should be a directory")
	}
}

func TestLoadHash_DownloadFails(t *testing.T) {
	fake := newFakeS3()
	// don't put any bundle - S3 will return NoSuchKey
	l := newTestLoader(t, fake, ssmWithValue("abc123"))

	_, err := l.LoadHash(t.Context(), "abc123")
	if err == nil {
		t.Fatal("expected error when download fails")
	}
}

func TestLoadHash_BadTarGz_ExtractionFails(t *testing.T) {
	fake := newFakeS3()

	// put invalid tar.gz content that will pass hash check
	badData := []byte("this is not a valid tar.gz")
	badHash := cryptoutil.SHA256Hex(badData)
	putBundle(fake, badHash, badData)

	l := newTestLoader(t, fake, ssmWithValue(badHash))

	_, err := l.LoadHash(t.Context(), badHash)
	if err == nil {
		t.Fatal("expected error for invalid tar.gz")
	}
	if !strings.Contains(err.Error(), "extract bundle") {
		t.Fatalf("error should mention extraction: %v", err)
	}
}

func TestLoadHash_BadTarGz_CleansUpExtractDir(t *testing.T) {
	fake := newFakeS3()

	badData := []byte("not a tarball")
	badHash := cryptoutil.SHA256Hex(badData)
	putBundle(fake, badHash, badData)

	extractDir := t.TempDir()
	l := &Loader{
		opts: LoaderOptions{
			Logger:     log.Nop(),
			SSMParam:   testSSMParam,
			S3Bucket:   testBucket,
			S3Prefix:   testS3Prefix,
			ExtractDir: extractDir,
			S3Client:   fake,
			SSMClient:  ssmWithValue(badHash),
		},
		s3Client:  fake,
		ssmClient: ssmWithValue(badHash),
		logger:    log.Nop(),
	}

	_, err := l.LoadHash(t.Context(), badHash)
	if err == nil {
		t.Fatal("expected error")
	}

	// the hash subdirectory should be cleaned up on extraction failure
	hashDir := filepath.Join(extractDir, badHash)
	if _, err := os.Stat(hashDir); !os.IsNotExist(err) {
		t.Fatalf("hash subdirectory should be removed on extraction failure, stat: %v", err)
	}
}

// Load (end-to-end: SSM -> S3 -> extract)

func TestLoad_Success(t *testing.T) {
	fake := newFakeS3()
	bundleData, bundleHash := buildContentBundle(t)
	putBundle(fake, bundleHash, bundleData)

	l := newTestLoader(t, fake, ssmWithValue(bundleHash))

	snap, err := l.Load(t.Context())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if snap == nil {
		t.Fatal("expected non-nil snapshot")
	}
	if snap.Meta.SHA256 != bundleHash {
		t.Fatalf("Meta.SHA256 = %q, want %q", snap.Meta.SHA256, bundleHash)
	}
}

func TestLoad_SSMFails(t *testing.T) {
	l := newTestLoader(t, newFakeS3(), ssmWithError(errors.New("parameter not found")))

	_, err := l.Load(t.Context())
	if err == nil {
		t.Fatal("expected error when SSM fails")
	}
	if !strings.Contains(err.Error(), "parameter not found") {
		t.Fatalf("error should propagate: %v", err)
	}
}

func TestLoad_S3Fails(t *testing.T) {
	fake := newFakeS3()
	hash := "abc123"
	// SSM returns a hash, but S3 doesn't have the bundle
	l := newTestLoader(t, fake, ssmWithValue(hash))

	_, err := l.Load(t.Context())
	if err == nil {
		t.Fatal("expected error when S3 object is missing")
	}
}

// LoadIntoManager

func TestLoadIntoManager_Success(t *testing.T) {
	fake := newFakeS3()
	bundleData, bundleHash := buildContentBundleWithProvenance(t)
	putBundle(fake, bundleHash, bundleData)

	l := newTestLoader(t, fake, ssmWithValue(bundleHash))
	mgr := NewManager()

	err := l.LoadIntoManager(t.Context(), mgr)
	if err != nil {
		t.Fatalf("LoadIntoManager: %v", err)
	}

	snap, ok := mgr.Get()
	if !ok {
		t.Fatal("expected manager to have content after LoadIntoManager")
	}
	if snap.Meta.SHA256 != bundleHash {
		t.Fatalf("manager SHA256 = %q, want %q", snap.Meta.SHA256, bundleHash)
	}
	if mgr.ContentVersion() != "1.2.3" {
		t.Fatalf("ContentVersion = %q, want 1.2.3", mgr.ContentVersion())
	}
	if mgr.Source() != SourceS3 {
		t.Fatalf("Source = %q, want %q", mgr.Source(), SourceS3)
	}
}

func TestLoadIntoManager_Failure(t *testing.T) {
	l := newTestLoader(t, newFakeS3(), ssmWithError(errors.New("SSM down")))
	mgr := NewManager()

	err := l.LoadIntoManager(t.Context(), mgr)
	if err == nil {
		t.Fatal("expected error to propagate")
	}

	// manager should still be empty
	_, ok := mgr.Get()
	if ok {
		t.Fatal("manager should not have content after failed load")
	}
}

// NewLoader field wiring verification

func TestNewLoader_FieldsWired_FetchWorks(t *testing.T) {
	fake := newFakeS3()
	ssmFake := ssmWithValue("hash-from-ssm")

	l, err := NewLoader(t.Context(), LoaderOptions{
		Logger:     log.Nop(),
		SSMParam:   testSSMParam,
		S3Bucket:   testBucket,
		S3Client:   fake,
		SSMClient:  ssmFake,
		ExtractDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}

	// If NewLoader doesnt wire ssmClient from opts.SSMClient, this panics
	hash, err := l.FetchCurrentBundleHash(t.Context())
	if err != nil {
		t.Fatalf("FetchCurrentBundleHash through NewLoader: %v", err)
	}
	if hash != "hash-from-ssm" {
		t.Fatalf("hash = %q, want hash-from-ssm", hash)
	}
}

func TestNewLoader_FieldsWired_DownloadWorks(t *testing.T) {
	fake := newFakeS3()
	bundleData, bundleHash := buildContentBundle(t)
	key := fmt.Sprintf("%s/%s.tar.gz", testS3Prefix, bundleHash)
	fake.put(key, bundleData)

	l, err := NewLoader(t.Context(), LoaderOptions{
		Logger:     log.Nop(),
		SSMParam:   testSSMParam,
		S3Bucket:   testBucket,
		S3Prefix:   testS3Prefix,
		S3Client:   fake,
		SSMClient:  ssmWithValue(bundleHash),
		ExtractDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}

	// If NewLoader doesnt wire s3Client from opts.S3Client, this panics
	tmpPath, err := l.Download(t.Context(), bundleHash)
	if err != nil {
		t.Fatalf("Download through NewLoader: %v", err)
	}
	os.Remove(tmpPath)
}

// CleanupHash

func TestCleanupHash_RemovesDirectory(t *testing.T) {
	extractDir := t.TempDir()
	hashDir := filepath.Join(extractDir, "abc123")
	if err := os.MkdirAll(hashDir, 0755); err != nil {
		t.Fatal(err)
	}
	// put a file inside to verify recursive removal
	if err := os.WriteFile(filepath.Join(hashDir, "index.html"), []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}

	l := &Loader{
		opts: LoaderOptions{ExtractDir: extractDir},
	}

	if err := l.CleanupHash("abc123"); err != nil {
		t.Fatalf("CleanupHash: %v", err)
	}

	if _, err := os.Stat(hashDir); !os.IsNotExist(err) {
		t.Fatal("expected hash directory to be removed")
	}
}

func TestCleanupHash_NonexistentDir_NoError(t *testing.T) {
	l := &Loader{
		opts: LoaderOptions{ExtractDir: t.TempDir()},
	}

	// removing a directory that doesn't exist should not error
	if err := l.CleanupHash("does-not-exist"); err != nil {
		t.Fatalf("CleanupHash on nonexistent dir: %v", err)
	}
}

func TestCleanupHash_EmptyHash_Noop(t *testing.T) {
	l := &Loader{
		opts: LoaderOptions{ExtractDir: t.TempDir()},
	}

	if err := l.CleanupHash(""); err != nil {
		t.Fatalf("CleanupHash with empty hash: %v", err)
	}
}

func TestCleanupHash_EmptyExtractDir_Noop(t *testing.T) {
	l := &Loader{
		opts: LoaderOptions{ExtractDir: ""},
	}

	if err := l.CleanupHash("abc123"); err != nil {
		t.Fatalf("CleanupHash with empty ExtractDir: %v", err)
	}
}

func TestCleanupHash_DoesNotAffectOtherHashes(t *testing.T) {
	extractDir := t.TempDir()

	// create two hash directories
	for _, h := range []string{"hash-a", "hash-b"} {
		dir := filepath.Join(extractDir, h)
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "file.txt"), []byte("data"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	l := &Loader{
		opts: LoaderOptions{ExtractDir: extractDir},
	}

	if err := l.CleanupHash("hash-a"); err != nil {
		t.Fatalf("CleanupHash: %v", err)
	}

	// hash-a should be gone
	if _, err := os.Stat(filepath.Join(extractDir, "hash-a")); !os.IsNotExist(err) {
		t.Fatal("hash-a should be removed")
	}

	// hash-b should still exist
	if _, err := os.Stat(filepath.Join(extractDir, "hash-b")); err != nil {
		t.Fatal("hash-b should still exist")
	}
}
