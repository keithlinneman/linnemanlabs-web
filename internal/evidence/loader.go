package evidence

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"

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

// LoaderOptions configures the evidence loader.
type LoaderOptions struct {
	Logger log.Logger

	// s3 bucket containing evidence artifacts
	Bucket string

	// s3 key prefix where artifacts are stored {Prefix}/{ReleaseID}/<name>.json
	Prefix string

	// ReleaseID to fetch evidence for (compiled into the binary via ldflags)
	ReleaseID string

	// AWS config (default if nil)
	AWSConfig *aws.Config
}

// Loader discovers and fetches evidence artifacts currently from S3 possibly OCI soon
type Loader struct {
	opts     LoaderOptions
	s3Client *s3.Client
	logger   log.Logger
}

// NewLoader creates a new evidence loader that will fetch artifacts
func NewLoader(ctx context.Context, opts LoaderOptions) (*Loader, error) {
	if opts.Bucket == "" {
		return nil, xerrors.New("evidence: Bucket is required")
	}
	if opts.ReleaseID == "" {
		return nil, xerrors.New("evidence: ReleaseID is required")
	}
	if opts.Logger == nil {
		opts.Logger = log.Nop()
	}

	var awsCfg aws.Config
	var err error
	if opts.AWSConfig != nil {
		awsCfg = *opts.AWSConfig
	} else {
		awsCfg, err = config.LoadDefaultConfig(ctx)
		if err != nil {
			return nil, xerrors.Wrap(err, "evidence: load AWS config")
		}
	}

	return &Loader{
		opts:     opts,
		s3Client: s3.NewFromConfig(awsCfg),
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
		"expected_hash", expectedInvHash[:12],
	)

	inventoryRaw, err := l.fetchS3(ctx, invKey, MaxManifestSize)
	if err != nil {
		return nil, xerrors.Wrap(err, "fetch inventory.json")
	}

	actualInvHash := sha256hex(inventoryRaw)
	if actualInvHash != expectedInvHash {
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
	files, fetched, skipped, totalBytes := l.fetchAllFiles(ctx, prefix, fileIndex)

	elapsed := time.Since(start)

	l.logger.Info(ctx, "evidence loading complete",
		"fetched", fetched,
		"skipped", skipped,
		"total_bytes", totalBytes,
		"duration", elapsed.String(),
	)

	return &Bundle{
		Release:       &release,
		ReleaseRaw:    releaseRaw,
		InventoryRaw:  inventoryRaw,
		InventoryHash: actualInvHash,
		FileIndex:     fileIndex,
		Files:         files,
		Bucket:        l.opts.Bucket,
		ReleasePrefix: prefix,
		FetchedAt:     time.Now().UTC(),
	}, nil
}

// fetchResult holds the result of a single file fetch.
type fetchResult struct {
	path string
	file *EvidenceFile
	err  string // empty on success
}

// fetchAllFiles downloads all evidence files using a bounded worker pool.
func (l *Loader) fetchAllFiles(ctx context.Context, prefix string, index map[string]*EvidenceFileRef) (
	files map[string]*EvidenceFile, fetched, skipped int, totalBytes int64,
) {
	files = make(map[string]*EvidenceFile, len(index))

	// build work queue
	type workItem struct {
		path string
		ref  *EvidenceFileRef
	}
	work := make([]workItem, 0, len(index))
	for path, ref := range index {
		work = append(work, workItem{path: path, ref: ref})
	}

	// Fan out to workers, collect results
	results := make(chan fetchResult, len(work))
	var wg sync.WaitGroup

	// channel limits concurrent S3 requests
	sem := make(chan struct{}, fetchWorkers)

	for _, w := range work {
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

			// verify hash
			if wi.ref.SHA256 != "" {
				actual := sha256hex(data)
				if actual != wi.ref.SHA256 {
					results <- fetchResult{
						path: wi.path,
						err:  fmt.Sprintf("hash mismatch: expected %s, got %s", wi.ref.SHA256[:12], actual[:12]),
					}
					return
				}
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

	// collect results (runs on caller goroutine, no mutex needed)
	for r := range results {
		if r.err != "" {
			l.logger.Warn(ctx, "failed to fetch evidence file, skipping",
				"path", r.path,
				"error", r.err,
			)
			skipped++
			continue
		}
		files[r.path] = r.file
		fetched++
		totalBytes += int64(len(r.file.Data))
	}

	return files, fetched, skipped, totalBytes
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

func sha256hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
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
