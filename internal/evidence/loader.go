package evidence

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/keithlinneman/linnemanlabs-web/internal/cryptoutil"
	"github.com/keithlinneman/linnemanlabs-web/internal/log"
	"github.com/keithlinneman/linnemanlabs-web/internal/xerrors"
)

const (
	// maximum size of release.json or inventory.json (bytes)
	MaxManifestSize = 2 * 1024 * 1024

	// maximum size of a single evidence file (bytes)
	MaxEvidenceFileSize = 5 * 1024 * 1024

	// max number of artifacts to fetch per release
	MaxArtifacts = 150

	// fetchWorkers is the number of parallel S3 fetches for evidence files
	fetchWorkers = 10
)

// s3Getter is the subset of the S3 API the loader needs.
// Extracted as an interface to enable unit testing without live AWS credentials.
type s3Getter interface {
	GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error)
}

// BlobVerifier verifies a sigstore bundle against artifact bytes.
// The evidence loader uses this to verify release.json signatures without
// being coupled to a specific KMS implementation.
type BlobVerifier interface {
	VerifyBlob(ctx context.Context, bundleJSON, artifact []byte) error
}

// LoaderOptions configures the evidence loader.
type LoaderOptions struct {
	Logger log.Logger

	// s3 bucket containing evidence artifacts
	Bucket string

	// s3 key prefix where artifacts are stored {Prefix}/{ReleaseID}/<name>.json
	Prefix string

	// ReleaseID to fetch evidence for (compiled into the binary via ldflags)
	ReleaseID string

	// ReleaseVerifier verifies the sigstore bundle for release.json
	Verifier BlobVerifier

	// RequireSignature makes signature verification mandatory. When true,
	// NewLoader validates that Verifier is non-nil, and Load fails if the
	// sigstore bundle is missing. This makes the trust model explicit rather
	// than relying on the implicit nil-check conditional.
	RequireSignature bool

	// S3Client allows injecting a custom S3 implementation for testing
	// If nil, a real client is created from AWSConfig.
	S3Client s3Getter
}

// Loader discovers and fetches evidence artifacts currently from S3 possibly OCI soon
type Loader struct {
	opts     LoaderOptions
	s3Client s3Getter
	logger   log.Logger
}

// workItem pairs an inventory path with its file reference for fetch workers.
type workItem struct {
	path string
	ref  *EvidenceFileRef
}

// fetchResult holds the result of a single file fetch.
type fetchResult struct {
	path string
	file *EvidenceFile
	err  string // empty on success
}

// NewLoader creates a new evidence loader that will fetch artifacts
func NewLoader(ctx context.Context, opts LoaderOptions) (*Loader, error) {
	if opts.S3Client == nil {
		return nil, xerrors.New("evidence: S3Client is required")
	}
	if opts.Bucket == "" {
		return nil, xerrors.New("evidence: Bucket is required")
	}
	if opts.ReleaseID == "" {
		return nil, xerrors.New("evidence: ReleaseID is required")
	}
	if opts.RequireSignature && opts.Verifier == nil {
		return nil, xerrors.New("evidence: Verifier is required when RequireSignature is true")
	}
	if opts.Logger == nil {
		opts.Logger = log.Nop()
	}

	return &Loader{
		opts:     opts,
		s3Client: opts.S3Client,
		logger:   opts.Logger,
	}, nil
}

// releasePrefix returns the full S3 key prefix for listing evidence objects
func (l *Loader) releasePrefix() string {
	parts := []string{}
	if l.opts.Prefix != "" {
		parts = append(parts, strings.TrimSuffix(l.opts.Prefix, "/"))
	}
	parts = append(parts, l.opts.ReleaseID)
	return strings.Join(parts, "/") + "/"
}

// Load discovers and fetches all evidence artifacts for the configured release
func (l *Loader) Load(ctx context.Context) (*Bundle, error) {
	prefix := l.releasePrefix()
	start := time.Now()

	releaseKey := prefix + "release.json"
	l.logger.Info(ctx, "discovering evidence artifacts",
		"bucket", l.opts.Bucket,
		"prefix", prefix,
		"release_id", l.opts.ReleaseID,
		"key", releaseKey,
	)

	releaseRaw, err := l.fetchS3(ctx, releaseKey, MaxManifestSize)
	if err != nil {
		return nil, xerrors.Wrap(err, "evidence fetch release.json")
	}

	var release ReleaseManifest
	if err := json.Unmarshal(releaseRaw, &release); err != nil {
		return nil, xerrors.Wrap(err, "parse release.json")
	}

	// ensure release.json release_id matches what we were told to fetch
	if release.ReleaseID != l.opts.ReleaseID {
		return nil, xerrors.Newf(
			"release.json release_id mismatch: expected %s, got %s",
			l.opts.ReleaseID, release.ReleaseID)
	}

	l.logger.Info(ctx, "parsed release manifest",
		"release_id", release.ReleaseID,
		"version", release.Version,
		"component", release.Component,
	)

	// attempt to fetch release.json sigstore bundle
	sigstoreBundleKey := prefix + "release.json.bundle.sigstore.json"
	sigstoreBundleRaw, err := l.fetchS3(ctx, sigstoreBundleKey, MaxManifestSize)
	if err != nil {
		return nil, xerrors.Wrap(err, "failed to fetch release.json.bundle.sigstore.json")
	}

	// fail-closed: if signature is required but bundle is missing, reject
	if sigstoreBundleRaw == nil && l.opts.RequireSignature {
		return nil, xerrors.New("release.json sigstore bundle is missing but RequireSignature is true")
	}

	// verify bundle against release.json if a verifier is configured
	if sigstoreBundleRaw != nil && l.opts.Verifier != nil {
		if err := l.opts.Verifier.VerifyBlob(ctx, sigstoreBundleRaw, releaseRaw); err != nil {
			return nil, xerrors.Wrap(err, "release.json signature verification failed")
		}
		l.logger.Info(ctx, "release.json signature verified")
	}

	// fetch and verify inventory.json
	invRef, ok := release.Files["inventory"]
	if !ok {
		return nil, xerrors.New("release.json has no files.inventory entry")
	}
	expectedInvHash := invRef.Hashes["sha256"]
	if expectedInvHash == "" {
		return nil, xerrors.New("release.json inventory entry has no sha256 hash")
	}

	invKey := prefix + invRef.Path

	l.logger.Info(ctx, "fetching inventory",
		"bucket", l.opts.Bucket,
		"key", invKey,
		"expected_hash", expectedInvHash,
	)

	inventoryRaw, err := l.fetchS3(ctx, invKey, MaxManifestSize)
	if err != nil {
		return nil, xerrors.Wrap(err, "fetch inventory.json")
	}

	actualInvHash := cryptoutil.SHA256Hex(inventoryRaw)
	if !cryptoutil.HashEqual(actualInvHash, expectedInvHash) {
		return nil, xerrors.Newf("inventory.json hash mismatch: expected %s, got %s",
			expectedInvHash, actualInvHash)
	}

	l.logger.Info(ctx, "inventory hash verified",
		"hash", actualInvHash[:12],
		"size", len(inventoryRaw),
	)

	// build file index from inventory
	fileIndex, err := BuildFileIndex(inventoryRaw)
	if err != nil {
		return nil, xerrors.Wrap(err, "build file index from inventory")
	}

	l.logger.Info(ctx, "built evidence file index",
		"total_files", len(fileIndex),
	)

	// fetch all evidence files in parallel
	files, fetched, totalBytes, err := l.fetchAllFiles(ctx, prefix, fileIndex)
	if err != nil {
		return nil, xerrors.Wrap(err, "fetch evidence files")
	}

	elapsed := time.Since(start)

	l.logger.Info(ctx, "evidence loading complete",
		"fetched", fetched,
		"total_bytes", totalBytes,
		"duration", elapsed.String(),
	)

	return &Bundle{
		Release:               &release,
		ReleaseRaw:            releaseRaw,
		ReleaseSigstoreBundle: sigstoreBundleRaw,
		InventoryRaw:          inventoryRaw,
		InventoryHash:         actualInvHash,
		FileIndex:             fileIndex,
		Files:                 files,
		Bucket:                l.opts.Bucket,
		ReleasePrefix:         prefix,
		FetchedAt:             time.Now().UTC(),
	}, nil
}

// fetchAllFiles downloads all evidence files using a bounded worker pool.
// Files that fail on the first attempt are retried once before the operation
// fails (fail-closed). AWS SDK v2 retries transient errors internally before
// surfacing them here, so this retry covers failures beyond the SDK's budget.
func (l *Loader) fetchAllFiles(ctx context.Context, prefix string, index map[string]*EvidenceFileRef) (
	files map[string]*EvidenceFile, fetched int, totalBytes int64, err error,
) {
	files = make(map[string]*EvidenceFile, len(index))

	// build work queue
	work := make([]workItem, 0, len(index))
	for path, ref := range index {
		work = append(work, workItem{path: path, ref: ref})
	}

	sem := make(chan struct{}, fetchWorkers)

	// first pass
	results := l.fetchWorkerBatch(ctx, prefix, work, sem)

	var failed []workItem
	for _, r := range results {
		if r.err != "" {
			for _, w := range work {
				if w.path == r.path {
					failed = append(failed, w)
					break
				}
			}
			continue
		}
		files[r.path] = r.file
		fetched++
		totalBytes += int64(len(r.file.Data))
	}

	// retry failed files once
	if len(failed) > 0 {
		l.logger.Warn(ctx, "retrying failed evidence files",
			"failed_count", len(failed),
			"total_files", len(index),
		)

		retryResults := l.fetchWorkerBatch(ctx, prefix, failed, sem)

		var errs []string
		for _, r := range retryResults {
			if r.err != "" {
				errs = append(errs, fmt.Sprintf("%s: %s", r.path, r.err))
				continue
			}
			files[r.path] = r.file
			fetched++
			totalBytes += int64(len(r.file.Data))
		}

		if len(errs) > 0 {
			return nil, 0, 0, xerrors.Newf(
				"failed to fetch %d evidence file(s) after retry: %s",
				len(errs), strings.Join(errs, "; "))
		}
	}

	return files, fetched, totalBytes, nil
}

// fetchWorkerBatch fans out fetch work across goroutines bounded by sem and
// returns all results (both successes and failures).
func (l *Loader) fetchWorkerBatch(ctx context.Context, prefix string,
	items []workItem, sem chan struct{}) []fetchResult {

	results := make(chan fetchResult, len(items))
	var wg sync.WaitGroup

	for _, w := range items {
		wg.Add(1)
		go func(wi workItem) {
			defer wg.Done()

			// Acquire semaphore slot
			sem <- struct{}{}
			defer func() { <-sem }()

			data, err := l.fetchS3(ctx, prefix+wi.path, MaxEvidenceFileSize)
			if err != nil {
				results <- fetchResult{path: wi.path, err: err.Error()}
				return
			}

			// require hash on all evidence files
			if wi.ref.SHA256 == "" {
				results <- fetchResult{
					path: wi.path,
					err:  "evidence file missing required sha256 hash in inventory",
				}
				return
			}

			actual := cryptoutil.SHA256Hex(data)
			if !cryptoutil.HashEqual(actual, wi.ref.SHA256) {
				results <- fetchResult{
					path: wi.path,
					err:  fmt.Sprintf("hash mismatch: expected %s, got %s", wi.ref.SHA256, actual),
				}
				return
			}

			results <- fetchResult{
				path: wi.path,
				file: &EvidenceFile{Ref: wi.ref, Data: data},
			}
		}(w)
	}

	// close results channel after all workers finish
	go func() {
		wg.Wait()
		close(results)
	}()

	// collect results
	out := make([]fetchResult, 0, len(items))
	for r := range results {
		out = append(out, r)
	}
	return out
}

// fetchS3 downloads an S3 object with a size limit
func (l *Loader) fetchS3(ctx context.Context, key string, maxSize int64) ([]byte, error) {
	out, err := l.s3Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(l.opts.Bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, xerrors.Wrapf(err, "get s3://%s/%s", l.opts.Bucket, key)
	}
	defer out.Body.Close()

	lr := io.LimitReader(out.Body, maxSize+1)
	data, err := io.ReadAll(lr)
	if err != nil {
		return nil, xerrors.Wrapf(err, "read s3://%s/%s", l.opts.Bucket, key)
	}
	if int64(len(data)) > maxSize {
		return nil, xerrors.Newf("s3://%s/%s exceeds size limit (%d bytes, max %d)",
			l.opts.Bucket, key, len(data), maxSize)
	}

	return data, nil
}

// LoadSummary returns a one-line summary for logging
func (b *Bundle) LoadSummary() string {
	if b == nil {
		return "no evidence loaded"
	}
	return fmt.Sprintf("release=%s version=%s files=%d/%d",
		b.Release.ReleaseID, b.Release.Version,
		len(b.Files), len(b.FileIndex))
}
