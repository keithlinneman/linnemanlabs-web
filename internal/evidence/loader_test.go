package evidence

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/keithlinneman/linnemanlabs-web/internal/cryptoutil"
	"github.com/keithlinneman/linnemanlabs-web/internal/log"
)

// fakeS3: test double for s3Getter

// fakeS3 implements s3Getter for unit testing. Objects are served from an
// in-memory map; forced errors can be injected per key.
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

func (f *fakeS3) putJSON(key string, v any) []byte {
	data, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("putJSON: %v", err))
	}
	f.objects[key] = data
	return data
}

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

// stubVerifier: test double for BlobVerifier

// stubVerifier implements BlobVerifier for testing.
type stubVerifier struct {
	err         error  // error to return (nil = success)
	gotBundle   []byte // last bundleJSON received
	gotArtifact []byte // last artifact received
}

func (v *stubVerifier) VerifyBlob(_ context.Context, bundleJSON, artifact []byte) error {
	v.gotBundle = bundleJSON
	v.gotArtifact = artifact
	return v.err
}

// passVerifier returns a verifier that always succeeds.
func passVerifier() *stubVerifier { return &stubVerifier{} }

// failVerifier returns a verifier that always returns the given error.
func failVerifier(msg string) *stubVerifier {
	return &stubVerifier{err: errors.New(msg)}
}

// test fixture helpers

const (
	testBucket    = "evidence-bucket"
	testPrefix    = "apps/web"
	testReleaseID = "rel-20260215-abc123"
)

func testReleasePrefix() string { return testPrefix + "/" + testReleaseID + "/" }

// validReleaseManifest builds a ReleaseManifest that passes all validation.
func validReleaseManifest(invHash string) ReleaseManifest {
	return ReleaseManifest{
		ReleaseID: testReleaseID,
		Version:   "1.0.0",
		Component: "server",
		Files: map[string]FileRef{
			"inventory": {
				Path:   "inventory.json",
				Hashes: map[string]string{"sha256": invHash},
			},
		},
	}
}

// emptyInventoryJSON returns valid but empty inventory JSON.
func emptyInventoryJSON() []byte { return []byte(`{}`) }

// inventoryWithFile returns inventory JSON referencing one evidence file.
func inventoryWithFile(path, sha256 string, size int64) []byte {
	inv := map[string]any{
		"source_evidence": map[string]any{
			"sbom": []map[string]any{
				{
					"format": "spdx",
					"report": map[string]any{
						"path":   path,
						"hashes": map[string]string{"sha256": sha256},
						"size":   size,
					},
				},
			},
		},
	}
	data, _ := json.Marshal(inv)
	return data
}

// newTestLoader creates a Loader wired to a fakeS3 with no AWS dependency.
func newTestLoader(fake *fakeS3, verifier BlobVerifier) *Loader {
	return &Loader{
		opts: LoaderOptions{
			Logger:    log.Nop(),
			Bucket:    testBucket,
			Prefix:    testPrefix,
			ReleaseID: testReleaseID,
			S3Client:  fake,
			Verifier:  verifier,
		},
		s3Client: fake,
		logger:   log.Nop(),
	}
}

// populateFakeS3 sets up a fully valid S3 state (release + sigstore bundle +
// inventory) so Load() can succeed end-to-end. Returns the raw release bytes.
func populateFakeS3(fake *fakeS3) []byte {
	prefix := testReleasePrefix()

	invData := emptyInventoryJSON()
	invHash := cryptoutil.SHA256Hex(invData)
	fake.put(prefix+"inventory.json", invData)

	rel := validReleaseManifest(invHash)
	releaseRaw := fake.putJSON(prefix+"release.json", rel)

	// sigstore bundle must exist (Load always fetches it)
	fake.put(prefix+"release.json.bundle.sigstore.json", []byte(`{"mock":"sigstore-bundle"}`))

	return releaseRaw
}

// populateWithEvidence sets up S3 with a valid chain that includes one
// hash-verified evidence file.
func populateWithEvidence(fake *fakeS3) {
	prefix := testReleasePrefix()

	evidenceBody := []byte(`{"sbom":"test-data"}`)
	evidenceHash := cryptoutil.SHA256Hex(evidenceBody)
	fake.put(prefix+"source/sbom.json", evidenceBody)

	invData := inventoryWithFile("source/sbom.json", evidenceHash, int64(len(evidenceBody)))
	invHash := cryptoutil.SHA256Hex(invData)
	fake.put(prefix+"inventory.json", invData)

	rel := validReleaseManifest(invHash)
	fake.putJSON(prefix+"release.json", rel)
	fake.put(prefix+"release.json.bundle.sigstore.json", []byte(`{"mock":"sigstore"}`))
}

// NewLoader - additional coverage

func TestNewLoader_NilLoggerDefaultsToNop(t *testing.T) {
	l := newTestLoader(newFakeS3(), nil)
	if l.logger == nil {
		t.Fatal("logger should never be nil")
	}
}

func TestNewLoader_InjectedS3Client(t *testing.T) {
	fake := newFakeS3()
	l := newTestLoader(fake, nil)
	if l.s3Client != fake {
		t.Fatal("expected injected S3 client")
	}
}

// Load() - release.json error paths

func TestLoad_FetchReleaseJSON_Fails(t *testing.T) {
	fake := newFakeS3()
	fake.failOn(testReleasePrefix()+"release.json", fmt.Errorf("access denied"))

	l := newTestLoader(fake, passVerifier())
	_, err := l.Load(t.Context())

	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "release.json") {
		t.Fatalf("error should mention release.json: %v", err)
	}
}

func TestLoad_ReleaseJSON_InvalidJSON(t *testing.T) {
	fake := newFakeS3()
	fake.put(testReleasePrefix()+"release.json", []byte(`{not valid json`))

	l := newTestLoader(fake, passVerifier())
	_, err := l.Load(t.Context())

	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "parse release.json") {
		t.Fatalf("error should mention parsing: %v", err)
	}
}

func TestLoad_ReleaseID_Mismatch(t *testing.T) {
	fake := newFakeS3()
	rel := validReleaseManifest("fakehash")
	rel.ReleaseID = "rel-WRONG-ID"
	fake.putJSON(testReleasePrefix()+"release.json", rel)

	l := newTestLoader(fake, passVerifier())
	_, err := l.Load(t.Context())

	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("error should mention mismatch: %v", err)
	}
	if !strings.Contains(err.Error(), testReleaseID) {
		t.Fatalf("error should contain expected release_id: %v", err)
	}
}

// Load() - sigstore error paths

func TestLoad_SigstoreBundle_FetchFails(t *testing.T) {
	fake := newFakeS3()
	prefix := testReleasePrefix()

	invData := emptyInventoryJSON()
	invHash := cryptoutil.SHA256Hex(invData)
	fake.put(prefix+"inventory.json", invData)
	fake.putJSON(prefix+"release.json", validReleaseManifest(invHash))
	fake.failOn(prefix+"release.json.bundle.sigstore.json", fmt.Errorf("network timeout"))

	l := newTestLoader(fake, passVerifier())
	_, err := l.Load(t.Context())

	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "sigstore") {
		t.Fatalf("error should mention sigstore: %v", err)
	}
}

func TestLoad_SigstoreBundle_NotInS3(t *testing.T) {
	fake := newFakeS3()
	prefix := testReleasePrefix()

	invData := emptyInventoryJSON()
	invHash := cryptoutil.SHA256Hex(invData)
	fake.put(prefix+"inventory.json", invData)
	fake.putJSON(prefix+"release.json", validReleaseManifest(invHash))
	// sigstore bundle key not in S3 at all

	l := newTestLoader(fake, passVerifier())
	_, err := l.Load(t.Context())

	if err == nil {
		t.Fatal("expected error: sigstore bundle fetch is mandatory")
	}
	if !strings.Contains(err.Error(), "sigstore") {
		t.Fatalf("error should mention sigstore: %v", err)
	}
}

func TestLoad_SigstoreVerification_Fails(t *testing.T) {
	fake := newFakeS3()
	populateFakeS3(fake)

	l := newTestLoader(fake, failVerifier("signature invalid: wrong key"))
	_, err := l.Load(t.Context())

	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "signature verification failed") {
		t.Fatalf("error should mention verification failure: %v", err)
	}
}

func TestLoad_SigstoreVerification_ReceivesCorrectArgs(t *testing.T) {
	fake := newFakeS3()
	releaseRaw := populateFakeS3(fake)
	prefix := testReleasePrefix()
	sigstoreData := fake.objects[prefix+"release.json.bundle.sigstore.json"]

	v := passVerifier()
	l := newTestLoader(fake, v)
	_, err := l.Load(t.Context())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if !bytes.Equal(v.gotBundle, sigstoreData) {
		t.Fatal("verifier should receive the sigstore bundle bytes")
	}
	if !bytes.Equal(v.gotArtifact, releaseRaw) {
		t.Fatal("verifier should receive the release.json bytes")
	}
}

func TestLoad_NilVerifier_SkipsVerification(t *testing.T) {
	fake := newFakeS3()
	populateFakeS3(fake)

	// nil verifier - verification should be skipped, not panic
	l := newTestLoader(fake, nil)
	bundle, err := l.Load(t.Context())

	if err != nil {
		t.Fatalf("Load with nil verifier: %v", err)
	}
	if bundle == nil {
		t.Fatal("expected non-nil bundle")
	}
}

// Load() - inventory error paths

func TestLoad_NoInventoryEntry(t *testing.T) {
	fake := newFakeS3()
	prefix := testReleasePrefix()

	rel := ReleaseManifest{
		ReleaseID: testReleaseID,
		Version:   "1.0.0",
		Files:     map[string]FileRef{},
	}
	fake.putJSON(prefix+"release.json", rel)
	fake.put(prefix+"release.json.bundle.sigstore.json", []byte(`{}`))

	l := newTestLoader(fake, passVerifier())
	_, err := l.Load(t.Context())

	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "no files.inventory entry") {
		t.Fatalf("error should mention missing inventory: %v", err)
	}
}

func TestLoad_InventoryEntry_NoSHA256(t *testing.T) {
	fake := newFakeS3()
	prefix := testReleasePrefix()

	rel := ReleaseManifest{
		ReleaseID: testReleaseID,
		Version:   "1.0.0",
		Files: map[string]FileRef{
			"inventory": {Path: "inventory.json", Hashes: map[string]string{"md5": "abc"}},
		},
	}
	fake.putJSON(prefix+"release.json", rel)
	fake.put(prefix+"release.json.bundle.sigstore.json", []byte(`{}`))

	l := newTestLoader(fake, passVerifier())
	_, err := l.Load(t.Context())

	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "no sha256 hash") {
		t.Fatalf("error should mention missing sha256: %v", err)
	}
}

func TestLoad_FetchInventory_Fails(t *testing.T) {
	fake := newFakeS3()
	prefix := testReleasePrefix()

	fake.putJSON(prefix+"release.json", validReleaseManifest("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"))
	fake.put(prefix+"release.json.bundle.sigstore.json", []byte(`{}`))
	fake.failOn(prefix+"inventory.json", fmt.Errorf("throttled"))

	l := newTestLoader(fake, passVerifier())
	_, err := l.Load(t.Context())

	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "fetch inventory.json") {
		t.Fatalf("error should mention inventory fetch: %v", err)
	}
}

func TestLoad_InventoryHashMismatch(t *testing.T) {
	fake := newFakeS3()
	prefix := testReleasePrefix()

	fake.put(prefix+"inventory.json", emptyInventoryJSON())
	fake.putJSON(prefix+"release.json", validReleaseManifest(
		"0000000000000000000000000000000000000000000000000000000000000000",
	))
	fake.put(prefix+"release.json.bundle.sigstore.json", []byte(`{}`))

	l := newTestLoader(fake, passVerifier())
	_, err := l.Load(t.Context())

	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "hash mismatch") {
		t.Fatalf("error should mention hash mismatch: %v", err)
	}
}

func TestLoad_InventoryJSON_Invalid(t *testing.T) {
	fake := newFakeS3()
	prefix := testReleasePrefix()

	invData := []byte(`{not valid inventory`)
	invHash := cryptoutil.SHA256Hex(invData)
	fake.put(prefix+"inventory.json", invData)
	fake.putJSON(prefix+"release.json", validReleaseManifest(invHash))
	fake.put(prefix+"release.json.bundle.sigstore.json", []byte(`{}`))

	l := newTestLoader(fake, passVerifier())
	_, err := l.Load(t.Context())

	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "build file index") {
		t.Fatalf("error should mention file index: %v", err)
	}
}

// Load() - success paths

func TestLoad_Success_MinimalBundle(t *testing.T) {
	fake := newFakeS3()
	populateFakeS3(fake)

	l := newTestLoader(fake, passVerifier())
	bundle, err := l.Load(t.Context())

	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if bundle == nil {
		t.Fatal("expected non-nil bundle")
	}
	if bundle.Release.ReleaseID != testReleaseID {
		t.Fatalf("ReleaseID = %q, want %q", bundle.Release.ReleaseID, testReleaseID)
	}
	if bundle.Release.Version != "1.0.0" {
		t.Fatalf("Version = %q", bundle.Release.Version)
	}
	if bundle.Bucket != testBucket {
		t.Fatalf("Bucket = %q", bundle.Bucket)
	}
	if bundle.ReleasePrefix != testReleasePrefix() {
		t.Fatalf("ReleasePrefix = %q", bundle.ReleasePrefix)
	}
	if bundle.ReleaseRaw == nil {
		t.Fatal("ReleaseRaw should be populated")
	}
	if bundle.InventoryRaw == nil {
		t.Fatal("InventoryRaw should be populated")
	}
	if bundle.InventoryHash == "" {
		t.Fatal("InventoryHash should be set")
	}
	if bundle.FetchedAt.IsZero() {
		t.Fatal("FetchedAt should be set")
	}
}

func TestLoad_Success_SigstoreBundlePreserved(t *testing.T) {
	fake := newFakeS3()
	populateFakeS3(fake)

	l := newTestLoader(fake, passVerifier())
	bundle, err := l.Load(t.Context())

	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if bundle.ReleaseSigstoreBundle == nil {
		t.Fatal("ReleaseSigstoreBundle should be preserved")
	}
	if !bytes.Contains(bundle.ReleaseSigstoreBundle, []byte("sigstore")) {
		t.Fatal("sigstore bundle content should be preserved")
	}
}

func TestLoad_Success_WithEvidenceFiles(t *testing.T) {
	fake := newFakeS3()
	populateWithEvidence(fake)

	l := newTestLoader(fake, passVerifier())
	bundle, err := l.Load(t.Context())

	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(bundle.FileIndex) == 0 {
		t.Fatal("expected non-empty file index")
	}
	if len(bundle.Files) == 0 {
		t.Fatal("expected non-empty files map")
	}
	f, ok := bundle.File("source/sbom.json")
	if !ok {
		t.Fatal("expected source/sbom.json in fetched files")
	}
	if !strings.Contains(string(f.Data), "sbom") {
		t.Fatal("evidence file content mismatch")
	}
}

func TestLoad_Success_ReleaseRawPreserved(t *testing.T) {
	fake := newFakeS3()
	releaseRaw := populateFakeS3(fake)

	l := newTestLoader(fake, passVerifier())
	bundle, err := l.Load(t.Context())

	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !bytes.Equal(bundle.ReleaseRaw, releaseRaw) {
		t.Fatal("ReleaseRaw should be the exact bytes from S3")
	}
}

func TestLoad_Success_InventoryHashVerified(t *testing.T) {
	fake := newFakeS3()
	prefix := testReleasePrefix()

	invData := emptyInventoryJSON()
	invHash := cryptoutil.SHA256Hex(invData)
	fake.put(prefix+"inventory.json", invData)
	fake.putJSON(prefix+"release.json", validReleaseManifest(invHash))
	fake.put(prefix+"release.json.bundle.sigstore.json", []byte(`{}`))

	l := newTestLoader(fake, passVerifier())
	bundle, err := l.Load(t.Context())

	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if bundle.InventoryHash != invHash {
		t.Fatalf("InventoryHash = %q, want %q", bundle.InventoryHash, invHash)
	}
}

// fetchAllFiles - error paths (non-fatal: files skipped, Load succeeds)

func TestLoad_EvidenceFile_FetchFails_Skipped(t *testing.T) {
	fake := newFakeS3()
	prefix := testReleasePrefix()

	evidenceBody := []byte(`{"sbom":"data"}`)
	evidenceHash := cryptoutil.SHA256Hex(evidenceBody)
	invData := inventoryWithFile("source/sbom.json", evidenceHash, int64(len(evidenceBody)))
	invHash := cryptoutil.SHA256Hex(invData)

	fake.put(prefix+"inventory.json", invData)
	fake.putJSON(prefix+"release.json", validReleaseManifest(invHash))
	fake.put(prefix+"release.json.bundle.sigstore.json", []byte(`{}`))
	fake.failOn(prefix+"source/sbom.json", fmt.Errorf("S3 throttle"))

	l := newTestLoader(fake, passVerifier())
	bundle, err := l.Load(t.Context())

	if err != nil {
		t.Fatalf("Load should succeed with skipped files: %v", err)
	}
	if _, ok := bundle.FileIndex["source/sbom.json"]; !ok {
		t.Fatal("file should be in FileIndex")
	}
	if _, ok := bundle.Files["source/sbom.json"]; ok {
		t.Fatal("file should NOT be in Files (fetch failed)")
	}
}

func TestLoad_EvidenceFile_HashMismatch_Skipped(t *testing.T) {
	fake := newFakeS3()
	prefix := testReleasePrefix()

	invData := inventoryWithFile("source/sbom.json",
		"0000000000000000000000000000000000000000000000000000000000000000", 100)
	invHash := cryptoutil.SHA256Hex(invData)

	fake.put(prefix+"inventory.json", invData)
	fake.putJSON(prefix+"release.json", validReleaseManifest(invHash))
	fake.put(prefix+"release.json.bundle.sigstore.json", []byte(`{}`))
	fake.put(prefix+"source/sbom.json", []byte(`{"tampered":"data"}`))

	l := newTestLoader(fake, passVerifier())
	bundle, err := l.Load(t.Context())

	if err != nil {
		t.Fatalf("Load should succeed with skipped files: %v", err)
	}
	if _, ok := bundle.FileIndex["source/sbom.json"]; !ok {
		t.Fatal("file should be in FileIndex")
	}
	if _, ok := bundle.Files["source/sbom.json"]; ok {
		t.Fatal("file should NOT be in Files (hash mismatch)")
	}
}

func TestLoad_EvidenceFile_EmptyHash_SkipsVerification(t *testing.T) {
	fake := newFakeS3()
	prefix := testReleasePrefix()

	invData := inventoryWithFile("source/sbom.json", "", 100)
	invHash := cryptoutil.SHA256Hex(invData)

	fake.put(prefix+"inventory.json", invData)
	fake.putJSON(prefix+"release.json", validReleaseManifest(invHash))
	fake.put(prefix+"release.json.bundle.sigstore.json", []byte(`{}`))
	fake.put(prefix+"source/sbom.json", []byte(`{"any":"content"}`))

	l := newTestLoader(fake, passVerifier())
	bundle, err := l.Load(t.Context())

	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, ok := bundle.Files["source/sbom.json"]; !ok {
		t.Fatal("file should be in Files when hash is empty (verification skipped)")
	}
}

// fetchS3 - edge cases

func TestFetchS3_SizeLimitExceeded(t *testing.T) {
	fake := newFakeS3()
	bigData := make([]byte, MaxManifestSize+1)
	fake.put("big.json", bigData)

	l := newTestLoader(fake, nil)
	_, err := l.fetchS3(t.Context(), "big.json", MaxManifestSize)

	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "exceeds size limit") {
		t.Fatalf("error should mention size limit: %v", err)
	}
}

func TestFetchS3_ExactlyAtLimit(t *testing.T) {
	fake := newFakeS3()
	data := make([]byte, MaxManifestSize)
	fake.put("exact.json", data)

	l := newTestLoader(fake, nil)
	got, err := l.fetchS3(t.Context(), "exact.json", MaxManifestSize)

	if err != nil {
		t.Fatalf("fetchS3: %v", err)
	}
	if int64(len(got)) != MaxManifestSize {
		t.Fatalf("size = %d, want %d", len(got), MaxManifestSize)
	}
}

func TestFetchS3_NotFound(t *testing.T) {
	l := newTestLoader(newFakeS3(), nil)
	_, err := l.fetchS3(t.Context(), "nonexistent.json", MaxManifestSize)
	if err == nil {
		t.Fatal("expected error for missing key")
	}
}

func TestFetchS3_ForcedError(t *testing.T) {
	fake := newFakeS3()
	fake.failOn("bad", fmt.Errorf("access denied"))
	l := newTestLoader(fake, nil)

	_, err := l.fetchS3(t.Context(), "bad", MaxManifestSize)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "access denied") {
		t.Fatalf("error should propagate: %v", err)
	}
}

func TestFetchS3_EmptyObject(t *testing.T) {
	fake := newFakeS3()
	fake.put("empty.json", []byte{})
	l := newTestLoader(fake, nil)

	got, err := l.fetchS3(t.Context(), "empty.json", MaxManifestSize)
	if err != nil {
		t.Fatalf("fetchS3: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty, got %d bytes", len(got))
	}
}

// NewLoader - validation

func TestNewLoader_MissingS3Client(t *testing.T) {
	_, err := NewLoader(t.Context(), LoaderOptions{
		Bucket:    testBucket,
		ReleaseID: testReleaseID,
		// S3Client omitted
	})
	if err == nil {
		t.Fatal("expected error for missing S3Client")
	}
	if !strings.Contains(err.Error(), "S3Client") {
		t.Fatalf("error should mention S3Client: %v", err)
	}
}

func TestNewLoader_MissingBucket(t *testing.T) {
	_, err := NewLoader(t.Context(), LoaderOptions{
		ReleaseID: testReleaseID,
		S3Client:  newFakeS3(),
		// Bucket omitted
	})
	if err == nil {
		t.Fatal("expected error for missing Bucket")
	}
	if !strings.Contains(err.Error(), "Bucket") {
		t.Fatalf("error should mention Bucket: %v", err)
	}
}

func TestNewLoader_MissingReleaseID(t *testing.T) {
	_, err := NewLoader(t.Context(), LoaderOptions{
		Bucket:   testBucket,
		S3Client: newFakeS3(),
		// ReleaseID omitted
	})
	if err == nil {
		t.Fatal("expected error for missing ReleaseID")
	}
	if !strings.Contains(err.Error(), "ReleaseID") {
		t.Fatalf("error should mention ReleaseID: %v", err)
	}
}

func TestNewLoader_Success(t *testing.T) {
	l, err := NewLoader(t.Context(), LoaderOptions{
		Logger:    log.Nop(),
		Bucket:    testBucket,
		Prefix:    testPrefix,
		ReleaseID: testReleaseID,
		S3Client:  newFakeS3(),
	})
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}
	if l == nil {
		t.Fatal("expected non-nil loader")
	}
}

func TestNewLoader_NilLoggerDefaultsToNop_ViaConstructor(t *testing.T) {
	l, err := NewLoader(t.Context(), LoaderOptions{
		Bucket:    testBucket,
		ReleaseID: testReleaseID,
		S3Client:  newFakeS3(),
		// Logger omitted
	})
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}
	if l == nil {
		t.Fatal("expected non-nil loader")
	}
}

// NewLoader - field wiring

func TestNewLoader_FieldsWired_LoadWorks(t *testing.T) {
	fake := newFakeS3()
	populateFakeS3(fake)

	l, err := NewLoader(t.Context(), LoaderOptions{
		Logger:    log.Nop(),
		Bucket:    testBucket,
		Prefix:    testPrefix,
		ReleaseID: testReleaseID,
		S3Client:  fake,
		Verifier:  passVerifier(),
	})
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}

	// If NewLoader doesn't wire s3Client/logger from opts, this panics.
	bundle, err := l.Load(t.Context())
	if err != nil {
		t.Fatalf("Load through NewLoader: %v", err)
	}
	if bundle == nil {
		t.Fatal("expected non-nil bundle")
	}
	if bundle.Release.ReleaseID != testReleaseID {
		t.Fatalf("ReleaseID = %q, want %q", bundle.Release.ReleaseID, testReleaseID)
	}
}

func TestNewLoader_FieldsWired_FetchS3Works(t *testing.T) {
	fake := newFakeS3()
	fake.put("test-key", []byte("hello"))

	l, err := NewLoader(t.Context(), LoaderOptions{
		Logger:    log.Nop(),
		Bucket:    testBucket,
		ReleaseID: testReleaseID,
		S3Client:  fake,
	})
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}

	// If s3Client isn't wired, this panics.
	data, err := l.fetchS3(t.Context(), "test-key", MaxManifestSize)
	if err != nil {
		t.Fatalf("fetchS3 through NewLoader: %v", err)
	}
	if string(data) != "hello" {
		t.Fatalf("data = %q, want hello", data)
	}
}

// releasePrefix - edge cases

func TestReleasePrefix_WithPrefix(t *testing.T) {
	l := newTestLoader(newFakeS3(), nil)
	// newTestLoader sets Prefix = testPrefix ("apps/web")
	got := l.releasePrefix()
	want := testPrefix + "/" + testReleaseID + "/"
	if got != want {
		t.Fatalf("releasePrefix() = %q, want %q", got, want)
	}
}

func TestReleasePrefix_NoPrefix(t *testing.T) {
	l := &Loader{
		opts: LoaderOptions{
			ReleaseID: testReleaseID,
		},
		logger: log.Nop(),
	}
	got := l.releasePrefix()
	want := testReleaseID + "/"
	if got != want {
		t.Fatalf("releasePrefix() = %q, want %q", got, want)
	}
}

func TestReleasePrefix_TrailingSlashInPrefix(t *testing.T) {
	l := &Loader{
		opts: LoaderOptions{
			Prefix:    "apps/web/",
			ReleaseID: testReleaseID,
		},
		logger: log.Nop(),
	}
	got := l.releasePrefix()
	// TrimSuffix should remove the trailing slash before joining
	want := "apps/web/" + testReleaseID + "/"
	if got != want {
		t.Fatalf("releasePrefix() = %q, want %q", got, want)
	}
}
