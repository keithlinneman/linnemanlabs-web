package content

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"

	"github.com/keithlinneman/linnemanlabs-web/internal/cryptoutil"
	"github.com/keithlinneman/linnemanlabs-web/internal/log"
)

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
func (f *fakeS3) failOn(key string, err error) {
	if f.errs == nil {
		f.errs = make(map[string]error)
	}
	f.errs[key] = err
}

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

// fakeVerifier implements BlobVerifier for unit testing.
type fakeVerifier struct {
	err         error  // error to return from VerifyBlob
	gotBundle   []byte // last bundleJSON passed
	gotArtifact []byte // last artifact passed
}

func passVerifier() *fakeVerifier           { return &fakeVerifier{} }
func failVerifier(msg string) *fakeVerifier { return &fakeVerifier{err: errors.New(msg)} }

func (f *fakeVerifier) VerifyBlob(_ context.Context, bundleJSON, artifact []byte) error {
	f.gotBundle = bundleJSON
	f.gotArtifact = artifact
	return f.err
}

// Test helpers

const (
	testBucket   = "content-bucket"
	testSSMParam = "/app/content/hash"
	testS3Prefix = "content/bundles"
)

// newTestLoader constructs a Loader with fakes and a passing verifier.
func newTestLoader(t *testing.T, s3fake *fakeS3, ssmFake *fakeSSM) *Loader {
	t.Helper()
	return newTestLoaderWithVerifier(t, s3fake, ssmFake, passVerifier())
}

// newTestLoaderWithVerifier constructs a Loader with a custom verifier.
func newTestLoaderWithVerifier(t *testing.T, s3fake *fakeS3, ssmFake *fakeSSM, verifier BlobVerifier) *Loader {
	t.Helper()
	return &Loader{
		opts: LoaderOptions{
			Logger:    log.Nop(),
			SSMParam:  testSSMParam,
			S3Bucket:  testBucket,
			S3Prefix:  testS3Prefix,
			S3Client:  s3fake,
			SSMClient: ssmFake,
			Verifier:  verifier,
		},
		s3Client:  s3fake,
		ssmClient: ssmFake,
		logger:    log.Nop(),
	}
}

// buildContentBundle creates a valid tar.gz archive in memory containing
// a single index.html file. Returns the raw bytes and their SHA-384 hash.
func buildContentBundle(t *testing.T) ([]byte, string) {
	t.Helper()
	data := makeTarGz(t, map[string]string{
		"index.html": "<html><body>hello</body></html>",
	})
	hash := cryptoutil.SHA384Hex(data)
	return data, hash
}

// buildContentBundleWithProvenance creates a tar.gz containing index.html
// and a provenance.json file. Returns the raw bytes and their SHA-384 hash.
func buildContentBundleWithProvenance(t *testing.T) ([]byte, string) {
	t.Helper()
	data := makeTarGz(t, map[string]string{
		"index.html":      "<html><body>hello</body></html>",
		"provenance.json": `{"version":"1.0.0","content_hash":"test","summary":{"total_files":2},"source":{"commit_short":"abc1234"}}`,
	})
	hash := cryptoutil.SHA384Hex(data)
	return data, hash
}

// putBundle stores a bundle in fakeS3 at the expected key for the given algorithm.
func putBundle(fake *fakeS3, algorithm, hash string, data []byte) {
	key := fmt.Sprintf("%s/%s/%s.tar.gz", testS3Prefix, algorithm, hash)
	fake.put(key, data)
}

// putSigBundle stores a sigstore bundle in fakeS3 at the expected key.
func putSigBundle(fake *fakeS3, algorithm, hash string, data []byte) {
	key := fmt.Sprintf("%s/%s/%s.tar.gz.sigstore.json", testS3Prefix, algorithm, hash)
	fake.put(key, data)
}

// ssmValue formats an algorithm:hash SSM parameter value.
func ssmValue(algorithm, hash string) string {
	return algorithm + ":" + hash
}

// NewLoader

func TestNewLoader_RequiresS3Client(t *testing.T) {
	_, err := NewLoader(t.Context(), LoaderOptions{
		SSMParam:  testSSMParam,
		S3Bucket:  testBucket,
		SSMClient: ssmWithValue("x"),
	})
	if err == nil {
		t.Fatal("expected error when S3Client is nil")
	}
}

func TestNewLoader_RequiresSSMClient(t *testing.T) {
	_, err := NewLoader(t.Context(), LoaderOptions{
		SSMParam: testSSMParam,
		S3Bucket: testBucket,
		S3Client: newFakeS3(),
	})
	if err == nil {
		t.Fatal("expected error when SSMClient is nil")
	}
}

func TestNewLoader_RequiresSSMParam(t *testing.T) {
	_, err := NewLoader(t.Context(), LoaderOptions{
		S3Bucket:  testBucket,
		S3Client:  newFakeS3(),
		SSMClient: ssmWithValue("x"),
	})
	if err == nil {
		t.Fatal("expected error when SSMParam is empty")
	}
}

func TestNewLoader_RequiresS3Bucket(t *testing.T) {
	_, err := NewLoader(t.Context(), LoaderOptions{
		SSMParam:  testSSMParam,
		S3Client:  newFakeS3(),
		SSMClient: ssmWithValue("x"),
	})
	if err == nil {
		t.Fatal("expected error when S3Bucket is empty")
	}
}

func TestNewLoader_RequiresVerifier(t *testing.T) {
	_, err := NewLoader(t.Context(), LoaderOptions{
		SSMParam:  testSSMParam,
		S3Bucket:  testBucket,
		S3Client:  newFakeS3(),
		SSMClient: ssmWithValue("x"),
	})
	if err == nil {
		t.Fatal("expected error when Verifier is nil")
	}
}

func TestNewLoader_DefaultsLogger(t *testing.T) {
	l, err := NewLoader(t.Context(), LoaderOptions{
		SSMParam:  testSSMParam,
		S3Bucket:  testBucket,
		S3Client:  newFakeS3(),
		SSMClient: ssmWithValue("x"),
		Verifier:  passVerifier(),
	})
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}
	if l.logger == nil {
		t.Fatal("expected logger to be set")
	}
}

// FetchCurrentBundleHash

func TestFetchCurrentBundleHash_SHA384(t *testing.T) {
	l := newTestLoader(t, newFakeS3(), ssmWithValue("sha384:abc123"))

	algorithm, hash, err := l.FetchCurrentBundleHash(t.Context())
	if err != nil {
		t.Fatalf("FetchCurrentBundleHash: %v", err)
	}
	if algorithm != "sha384" {
		t.Fatalf("algorithm = %q, want sha384", algorithm)
	}
	if hash != "abc123" {
		t.Fatalf("hash = %q, want abc123", hash)
	}
}

func TestFetchCurrentBundleHash_SHA256(t *testing.T) {
	l := newTestLoader(t, newFakeS3(), ssmWithValue("sha256:def456"))

	algorithm, hash, err := l.FetchCurrentBundleHash(t.Context())
	if err != nil {
		t.Fatalf("FetchCurrentBundleHash: %v", err)
	}
	if algorithm != "sha256" {
		t.Fatalf("algorithm = %q, want sha256", algorithm)
	}
	if hash != "def456" {
		t.Fatalf("hash = %q, want def456", hash)
	}
}

func TestFetchCurrentBundleHash_TrimsWhitespace(t *testing.T) {
	l := newTestLoader(t, newFakeS3(), ssmWithValue("  sha384:abc123  \n"))

	algorithm, hash, err := l.FetchCurrentBundleHash(t.Context())
	if err != nil {
		t.Fatalf("FetchCurrentBundleHash: %v", err)
	}
	if algorithm != "sha384" {
		t.Fatalf("algorithm = %q, want sha384", algorithm)
	}
	if hash != "abc123" {
		t.Fatalf("hash = %q, want abc123", hash)
	}
}

func TestFetchCurrentBundleHash_MissingPrefix(t *testing.T) {
	l := newTestLoader(t, newFakeS3(), ssmWithValue("justahashwithoutcolon"))

	_, _, err := l.FetchCurrentBundleHash(t.Context())
	if err == nil {
		t.Fatal("expected error when algorithm prefix is missing")
	}
	if !strings.Contains(err.Error(), "algorithm prefix") {
		t.Fatalf("error should mention algorithm prefix: %v", err)
	}
}

func TestFetchCurrentBundleHash_SSMError(t *testing.T) {
	l := newTestLoader(t, newFakeS3(), ssmWithError(errors.New("access denied")))

	_, _, err := l.FetchCurrentBundleHash(t.Context())
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestFetchCurrentBundleHash_NilParameter(t *testing.T) {
	l := newTestLoader(t, newFakeS3(), ssmWithNilParam())

	_, _, err := l.FetchCurrentBundleHash(t.Context())
	if err == nil {
		t.Fatal("expected error for nil parameter")
	}
}

func TestFetchCurrentBundleHash_NilValue(t *testing.T) {
	l := newTestLoader(t, newFakeS3(), ssmWithNilValue())

	_, _, err := l.FetchCurrentBundleHash(t.Context())
	if err == nil {
		t.Fatal("expected error for nil value")
	}
}

func TestFetchCurrentBundleHash_EmptyValue(t *testing.T) {
	l := newTestLoader(t, newFakeS3(), ssmWithValue("   "))

	_, _, err := l.FetchCurrentBundleHash(t.Context())
	if err == nil {
		t.Fatal("expected error for empty/whitespace value")
	}
}

// s3Key

func TestS3Key_WithPrefix(t *testing.T) {
	l := newTestLoader(t, newFakeS3(), ssmWithValue("x"))

	key := l.s3Key("sha384", "abc123")
	want := "content/bundles/sha384/abc123.tar.gz"
	if key != want {
		t.Fatalf("key = %q, want %q", key, want)
	}
}

func TestS3Key_WithoutPrefix(t *testing.T) {
	l := &Loader{opts: LoaderOptions{S3Prefix: ""}}

	key := l.s3Key("sha384", "abc123")
	want := "sha384/abc123.tar.gz"
	if key != want {
		t.Fatalf("key = %q, want %q", key, want)
	}
}

func TestS3Key_SHA256(t *testing.T) {
	l := newTestLoader(t, newFakeS3(), ssmWithValue("x"))

	key := l.s3Key("sha256", "def456")
	want := "content/bundles/sha256/def456.tar.gz"
	if key != want {
		t.Fatalf("key = %q, want %q", key, want)
	}
}

// sigBundleKey

func TestSigBundleKey_WithPrefix(t *testing.T) {
	l := newTestLoader(t, newFakeS3(), ssmWithValue("x"))

	key := l.sigBundleKey("sha384", "abc123")
	want := "content/bundles/sha384/abc123.tar.gz.sigstore.json"
	if key != want {
		t.Fatalf("key = %q, want %q", key, want)
	}
}

func TestSigBundleKey_WithoutPrefix(t *testing.T) {
	l := &Loader{opts: LoaderOptions{S3Prefix: ""}}

	key := l.sigBundleKey("sha384", "abc123")
	want := "sha384/abc123.tar.gz.sigstore.json"
	if key != want {
		t.Fatalf("key = %q, want %q", key, want)
	}
}

// fetchS3

func TestFetchS3_Success(t *testing.T) {
	fake := newFakeS3()
	fake.put("some/key.json", []byte(`{"data":"hello"}`))

	l := newTestLoader(t, fake, ssmWithValue("x"))

	data, err := l.fetchS3(t.Context(), "some/key.json", 1024)
	if err != nil {
		t.Fatalf("fetchS3: %v", err)
	}
	if string(data) != `{"data":"hello"}` {
		t.Fatalf("data = %q, want {\"data\":\"hello\"}", data)
	}
}

func TestFetchS3_KeyNotFound(t *testing.T) {
	l := newTestLoader(t, newFakeS3(), ssmWithValue("x"))

	_, err := l.fetchS3(t.Context(), "missing/key.json", 1024)
	if err == nil {
		t.Fatal("expected error for missing key")
	}
}

func TestFetchS3_ExceedsMaxSize(t *testing.T) {
	fake := newFakeS3()
	fake.put("big.json", bytes.Repeat([]byte("x"), 100))

	l := newTestLoader(t, fake, ssmWithValue("x"))

	_, err := l.fetchS3(t.Context(), "big.json", 50)
	if err == nil {
		t.Fatal("expected error when object exceeds max size")
	}
	if !strings.Contains(err.Error(), "exceeds max size") {
		t.Fatalf("error should mention max size: %v", err)
	}
}

func TestFetchS3_S3Error(t *testing.T) {
	fake := newFakeS3()
	fake.failOn("fail/key.json", errors.New("network timeout"))

	l := newTestLoader(t, fake, ssmWithValue("x"))

	_, err := l.fetchS3(t.Context(), "fail/key.json", 1024)
	if err == nil {
		t.Fatal("expected error")
	}
}

// LoadHash

func TestLoadHash_Success(t *testing.T) {
	fake := newFakeS3()
	bundleData, bundleHash := buildContentBundle(t)
	putBundle(fake, "sha384", bundleHash, bundleData)
	putSigBundle(fake, "sha384", bundleHash, []byte(`{"mock":"sig"}`))

	l := newTestLoader(t, fake, ssmWithValue(ssmValue("sha384", bundleHash)))

	snap, err := l.LoadHash(t.Context(), "sha384", bundleHash)
	if err != nil {
		t.Fatalf("LoadHash: %v", err)
	}
	if snap == nil {
		t.Fatal("expected non-nil snapshot")
	}
	if snap.Meta.Hash != bundleHash {
		t.Fatalf("Meta.Hash = %q, want %q", snap.Meta.Hash, bundleHash)
	}
	if snap.Meta.HashAlgorithm != "sha384" {
		t.Fatalf("Meta.HashAlgorithm = %q, want sha384", snap.Meta.HashAlgorithm)
	}
	if snap.Meta.Source != SourceS3 {
		t.Fatalf("Meta.Source = %q, want %q", snap.Meta.Source, SourceS3)
	}
	if snap.FS == nil {
		t.Fatal("expected non-nil FS")
	}

	data, err := fs.ReadFile(snap.FS, "index.html")
	if err != nil {
		t.Fatalf("read index.html from snapshot FS: %v", err)
	}
	if !strings.Contains(string(data), "hello") {
		t.Fatalf("index.html content = %q, expected it to contain 'hello'", data)
	}
}

func TestLoadHash_WithVerifier_Success(t *testing.T) {
	fake := newFakeS3()
	bundleData, bundleHash := buildContentBundle(t)
	putBundle(fake, "sha384", bundleHash, bundleData)
	putSigBundle(fake, "sha384", bundleHash, []byte(`{"mock":"sig"}`))

	v := passVerifier()
	l := newTestLoaderWithVerifier(t, fake, ssmWithValue(ssmValue("sha384", bundleHash)), v)

	snap, err := l.LoadHash(t.Context(), "sha384", bundleHash)
	if err != nil {
		t.Fatalf("LoadHash: %v", err)
	}
	if snap == nil {
		t.Fatal("expected non-nil snapshot")
	}
	if !bytes.Equal(v.gotArtifact, bundleData) {
		t.Fatalf("verifier artifact should be the bundle bytes (%d bytes), got %d bytes", len(bundleData), len(v.gotArtifact))
	}
}

func TestLoadHash_WithVerifier_SignatureFails(t *testing.T) {
	fake := newFakeS3()
	bundleData, bundleHash := buildContentBundle(t)
	putBundle(fake, "sha384", bundleHash, bundleData)
	putSigBundle(fake, "sha384", bundleHash, []byte(`{"mock":"sig"}`))

	v := failVerifier("bad signature")
	l := newTestLoaderWithVerifier(t, fake, ssmWithValue(ssmValue("sha384", bundleHash)), v)

	_, err := l.LoadHash(t.Context(), "sha384", bundleHash)
	if err == nil {
		t.Fatal("expected error when signature verification fails")
	}
	if !strings.Contains(err.Error(), "signature verification failed") {
		t.Fatalf("error should mention verification failure: %v", err)
	}
}

func TestLoadHash_DownloadFails(t *testing.T) {
	fake := newFakeS3()
	l := newTestLoader(t, fake, ssmWithValue("sha384:abc123"))

	_, err := l.LoadHash(t.Context(), "sha384", "abc123")
	if err == nil {
		t.Fatal("expected error when download fails")
	}
}

func TestLoadHash_ChecksumMismatch(t *testing.T) {
	fake := newFakeS3()
	bundleData, _ := buildContentBundle(t)

	wrongHash := strings.Repeat("0", 96)
	putBundle(fake, "sha384", wrongHash, bundleData)

	l := newTestLoader(t, fake, ssmWithValue(ssmValue("sha384", wrongHash)))

	_, err := l.LoadHash(t.Context(), "sha384", wrongHash)
	if err == nil {
		t.Fatal("expected error for checksum mismatch")
	}
	if !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("expected 'checksum mismatch' in error, got: %v", err)
	}
}

func TestLoadHash_BadTarGz(t *testing.T) {
	fake := newFakeS3()

	badData := []byte("this is not a valid tar.gz")
	badHash := cryptoutil.SHA384Hex(badData)
	putBundle(fake, "sha384", badHash, badData)
	putSigBundle(fake, "sha384", badHash, []byte(`{"mock":"sig"}`))

	l := newTestLoader(t, fake, ssmWithValue(ssmValue("sha384", badHash)))

	_, err := l.LoadHash(t.Context(), "sha384", badHash)
	if err == nil {
		t.Fatal("expected error for invalid tar.gz")
	}
	if !strings.Contains(err.Error(), "extract bundle") {
		t.Fatalf("error should mention extraction: %v", err)
	}
}

func TestLoadHash_UnsupportedAlgorithm(t *testing.T) {
	fake := newFakeS3()
	fake.put("content/bundles/md5/abc123.tar.gz", []byte("data"))

	l := newTestLoader(t, fake, ssmWithValue("md5:abc123"))

	_, err := l.LoadHash(t.Context(), "md5", "abc123")
	if err == nil {
		t.Fatal("expected error for unsupported algorithm")
	}
	if !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("error should mention unsupported: %v", err)
	}
}

func TestLoadHash_WithProvenance(t *testing.T) {
	fake := newFakeS3()
	bundleData, bundleHash := buildContentBundleWithProvenance(t)
	putBundle(fake, "sha384", bundleHash, bundleData)
	putSigBundle(fake, "sha384", bundleHash, []byte(`{"mock":"sig"}`))

	l := newTestLoader(t, fake, ssmWithValue(ssmValue("sha384", bundleHash)))

	snap, err := l.LoadHash(t.Context(), "sha384", bundleHash)
	if err != nil {
		t.Fatalf("LoadHash: %v", err)
	}
	if snap.Provenance == nil {
		t.Fatal("expected provenance to be loaded")
	}
	if snap.Provenance.Version != "1.0.0" {
		t.Fatalf("Provenance.Version = %q, want 1.0.0", snap.Provenance.Version)
	}
	if snap.Meta.Version != "1.0.0" {
		t.Fatalf("Meta.Version = %q, want 1.0.0 (from provenance)", snap.Meta.Version)
	}
}

func TestLoadHash_WithoutProvenance(t *testing.T) {
	fake := newFakeS3()
	bundleData, bundleHash := buildContentBundle(t)
	putBundle(fake, "sha384", bundleHash, bundleData)
	putSigBundle(fake, "sha384", bundleHash, []byte(`{"mock":"sig"}`))

	l := newTestLoader(t, fake, ssmWithValue(ssmValue("sha384", bundleHash)))

	snap, err := l.LoadHash(t.Context(), "sha384", bundleHash)
	if err != nil {
		t.Fatalf("LoadHash: %v", err)
	}
	if snap.Provenance != nil {
		t.Fatal("expected nil provenance when provenance.json is missing")
	}
	if snap.Meta.Version != "" {
		t.Fatalf("Meta.Version = %q, want empty when no provenance", snap.Meta.Version)
	}
}

func TestLoadHash_SetsLoadedAt(t *testing.T) {
	fake := newFakeS3()
	bundleData, bundleHash := buildContentBundle(t)
	putBundle(fake, "sha384", bundleHash, bundleData)
	putSigBundle(fake, "sha384", bundleHash, []byte(`{"mock":"sig"}`))

	l := newTestLoader(t, fake, ssmWithValue(ssmValue("sha384", bundleHash)))

	snap, err := l.LoadHash(t.Context(), "sha384", bundleHash)
	if err != nil {
		t.Fatalf("LoadHash: %v", err)
	}
	if snap.LoadedAt.IsZero() {
		t.Fatal("LoadedAt should be set")
	}
}

func TestLoadHash_SetsVerifiedAt(t *testing.T) {
	fake := newFakeS3()
	bundleData, bundleHash := buildContentBundle(t)
	putBundle(fake, "sha384", bundleHash, bundleData)
	putSigBundle(fake, "sha384", bundleHash, []byte(`{"mock":"sig"}`))

	l := newTestLoader(t, fake, ssmWithValue(ssmValue("sha384", bundleHash)))

	snap, err := l.LoadHash(t.Context(), "sha384", bundleHash)
	if err != nil {
		t.Fatalf("LoadHash: %v", err)
	}
	if snap.Meta.VerifiedAt.IsZero() {
		t.Fatal("Meta.VerifiedAt should be set")
	}
}

// Load (end-to-end: SSM -> S3 -> extract)

func TestLoad_Success(t *testing.T) {
	fake := newFakeS3()
	bundleData, bundleHash := buildContentBundle(t)
	putBundle(fake, "sha384", bundleHash, bundleData)
	putSigBundle(fake, "sha384", bundleHash, []byte(`{"mock":"sig"}`))

	l := newTestLoader(t, fake, ssmWithValue(ssmValue("sha384", bundleHash)))

	snap, err := l.Load(t.Context())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if snap == nil {
		t.Fatal("expected non-nil snapshot")
	}
	if snap.Meta.Hash != bundleHash {
		t.Fatalf("Meta.Hash = %q, want %q", snap.Meta.Hash, bundleHash)
	}
	if snap.Meta.HashAlgorithm != "sha384" {
		t.Fatalf("Meta.HashAlgorithm = %q, want sha384", snap.Meta.HashAlgorithm)
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

func TestLoad_SSMMissingAlgorithmPrefix(t *testing.T) {
	l := newTestLoader(t, newFakeS3(), ssmWithValue("nocolonhere"))

	_, err := l.Load(t.Context())
	if err == nil {
		t.Fatal("expected error when SSM value has no algorithm prefix")
	}
}

func TestLoad_S3Fails(t *testing.T) {
	fake := newFakeS3()
	l := newTestLoader(t, fake, ssmWithValue("sha384:abc123"))

	_, err := l.Load(t.Context())
	if err == nil {
		t.Fatal("expected error when S3 object is missing")
	}
}

// LoadIntoManager

func TestLoadIntoManager_Success(t *testing.T) {
	fake := newFakeS3()
	bundleData, bundleHash := buildContentBundleWithProvenance(t)
	putBundle(fake, "sha384", bundleHash, bundleData)
	putSigBundle(fake, "sha384", bundleHash, []byte(`{"mock":"sig"}`))

	l := newTestLoader(t, fake, ssmWithValue(ssmValue("sha384", bundleHash)))
	mgr := NewManager()

	err := l.LoadIntoManager(t.Context(), mgr)
	if err != nil {
		t.Fatalf("LoadIntoManager: %v", err)
	}

	snap, ok := mgr.Get()
	if !ok {
		t.Fatal("expected manager to have content after LoadIntoManager")
	}
	if snap.Meta.Hash != bundleHash {
		t.Fatalf("Meta.Hash = %q, want %q", snap.Meta.Hash, bundleHash)
	}
}

func TestLoadIntoManager_Failure(t *testing.T) {
	l := newTestLoader(t, newFakeS3(), ssmWithError(errors.New("unavailable")))
	mgr := NewManager()

	err := l.LoadIntoManager(t.Context(), mgr)
	if err == nil {
		t.Fatal("expected error")
	}

	_, ok := mgr.Get()
	if ok {
		t.Fatal("manager should not have content after failed load")
	}
}

// provenanceVersion helper

func TestProvenanceVersion_Nil(t *testing.T) {
	if v := provenanceVersion(nil); v != "" {
		t.Fatalf("provenanceVersion(nil) = %q, want empty", v)
	}
}

func TestProvenanceVersion_WithVersion(t *testing.T) {
	p := &Provenance{Version: "2.0.0"}
	if v := provenanceVersion(p); v != "2.0.0" {
		t.Fatalf("provenanceVersion = %q, want 2.0.0", v)
	}
}

func TestProvenanceVersion_EmptyVersion(t *testing.T) {
	p := &Provenance{}
	if v := provenanceVersion(p); v != "" {
		t.Fatalf("provenanceVersion = %q, want empty", v)
	}
}
