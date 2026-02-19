// internal/content/loader.go
package content

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/ssm"

	"github.com/keithlinneman/linnemanlabs-web/internal/cryptoutil"
	"github.com/keithlinneman/linnemanlabs-web/internal/log"
	"github.com/keithlinneman/linnemanlabs-web/internal/xerrors"
)

// maxSigBundleSize is the maximum size of a sigstore bundle JSON file
const maxSigBundleSize int64 = 1 * 1024 * 1024 // 1MB

type LoaderOptions struct {
	Logger log.Logger

	// SSM parameter containing the bundle algorithm and hash
	SSMParam string

	// S3 location for bundles: s3://{bucket}/{prefix}/{hash}.tar.gz
	S3Bucket string
	S3Prefix string

	// Verifier for bundle hash signatures
	Verifier BlobVerifier

	// S3Client allows injecting a custom S3 implementation for testing.
	// If nil, a real client is created from AWSConfig.
	S3Client s3Getter

	// SSMClient allows injecting a custom SSM implementation for testing.
	// If nil, a real client is created from AWSConfig.
	SSMClient ssmGetter
}

type Loader struct {
	opts      LoaderOptions
	ssmClient ssmGetter
	s3Client  s3Getter
	logger    log.Logger
}

// s3Getter is the subset of the S3 API the loader needs.
// Extracted as an interface to enable unit testing without live AWS credentials.
type s3Getter interface {
	GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error)
}

// ssmGetter is the subset of the SSM API the loader needs.
// Extracted as an interface to enable unit testing without live AWS credentials.
type ssmGetter interface {
	GetParameter(ctx context.Context, params *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error)
}

// BlobVerifier verifies a sigstore bundle against artifact bytes.
// The evidence loader uses this to verify release.json signatures without
// being coupled to a specific KMS implementation.
type BlobVerifier interface {
	VerifyBlob(ctx context.Context, bundleJSON, artifact []byte) error
}

// NewLoader creates a new content Loader with the given options
func NewLoader(ctx context.Context, opts LoaderOptions) (*Loader, error) {
	if opts.S3Client == nil {
		return nil, xerrors.New("evidence: S3Client is required")
	}
	if opts.SSMClient == nil {
		return nil, xerrors.New("evidence: SSMClient is required")
	}
	if opts.SSMParam == "" {
		return nil, xerrors.New("SSMParam is required")
	}
	if opts.S3Bucket == "" {
		return nil, xerrors.New("S3Bucket is required")
	}
	if opts.Logger == nil {
		opts.Logger = log.Nop()
	}

	return &Loader{
		opts:      opts,
		s3Client:  opts.S3Client,
		ssmClient: opts.SSMClient,
		logger:    opts.Logger,
	}, nil
}

// FetchCurrentBundleHash gets the current bundle hash from SSM
// returns the hash algorithm, hash value, and error if any
func (l *Loader) FetchCurrentBundleHash(ctx context.Context) (string, string, error) {
	out, err := l.ssmClient.GetParameter(ctx, &ssm.GetParameterInput{
		Name:           aws.String(l.opts.SSMParam),
		WithDecryption: aws.Bool(true),
	})
	if err != nil {
		return "", "", xerrors.Wrapf(err, "get SSM parameter %s", l.opts.SSMParam)
	}
	if out.Parameter == nil || out.Parameter.Value == nil {
		return "", "", xerrors.Newf("SSM parameter %s has no value", l.opts.SSMParam)
	}

	raw := strings.TrimSpace(*out.Parameter.Value)
	if raw == "" {
		return "", "", xerrors.Newf("SSM parameter %s is empty", l.opts.SSMParam)
	}

	algorithm, hash, ok := strings.Cut(raw, ":")
	if !ok {
		return "", "", xerrors.Newf("SSM parameter %s missing algorithm prefix (expected algo:hex)", l.opts.SSMParam)
	}

	return algorithm, hash, nil
}

// s3Key returns the S3 object key for a given hash
func (l *Loader) s3Key(algorithm, hash string) string {
	if l.opts.S3Prefix != "" {
		return fmt.Sprintf("%s/%s/%s.tar.gz", l.opts.S3Prefix, algorithm, hash)
	}
	return fmt.Sprintf("%s/%s.tar.gz", algorithm, hash)
}

// sigBundleKey returns the S3 object key for the sigstore bundle
// for a given content bundle hash.
func (l *Loader) sigBundleKey(algorithm, hash string) string {
	return l.s3Key(algorithm, hash) + ".sigstore.json"
}

// fetchS3 fetches an S3 object and returns its contents, limited to maxSize.
func (l *Loader) fetchS3(ctx context.Context, key string, maxSize int64) ([]byte, error) {
	out, err := l.s3Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(l.opts.S3Bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, xerrors.Wrapf(err, "get S3 object s3://%s/%s", l.opts.S3Bucket, key)
	}
	defer out.Body.Close()

	lr := io.LimitReader(out.Body, maxSize+1)
	data, err := io.ReadAll(lr)
	if err != nil {
		return nil, xerrors.Wrapf(err, "read S3 object s3://%s/%s", l.opts.S3Bucket, key)
	}
	if int64(len(data)) > maxSize {
		return nil, xerrors.Newf("S3 object s3://%s/%s exceeds max size (%d bytes)", l.opts.S3Bucket, key, maxSize)
	}

	return data, nil
}

// Load fetches the current release and returns a Snapshot
func (l *Loader) Load(ctx context.Context) (*Snapshot, error) {
	algorithm, hash, err := l.FetchCurrentBundleHash(ctx)
	if err != nil {
		return nil, err
	}

	return l.LoadHash(ctx, algorithm, hash)
}

// LoadHash fetches a specific bundle by hash, verifies the hash signature
// against a trusted key, downloads the bundle, verifies its SHA-384 integrity,
// extracts to an in-memory filesystem, and returns a Snapshot. No files are
// written to disk - the bundle is served directly from memory, eliminating
// disk tampering threat surface entirely and improving performance.
func (l *Loader) LoadHash(ctx context.Context, algorithm, hash string) (*Snapshot, error) {
	loadedAt := time.Now().UTC()

	// verify the hash is signed by a trusted key before downloading the bundle
	if err := l.verifyHashSignature(ctx, algorithm, hash); err != nil {
		return nil, err
	}

	// download the bundle
	key := l.s3Key(algorithm, hash)
	l.logger.Info(ctx, "fetching content bundle",
		"bucket", l.opts.S3Bucket,
		"key", key,
		"expected_hash", hash,
	)

	out, err := l.s3Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(l.opts.S3Bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, xerrors.Wrapf(err, "get S3 object s3://%s/%s", l.opts.S3Bucket, key)
	}
	defer out.Body.Close()

	// read and hash in one pass - no temp files
	data, actualHash, err := readWithHash(out.Body, maxBundleSize, algorithm)
	if err != nil {
		return nil, xerrors.Wrap(err, "read content bundle")
	}

	l.logger.Info(ctx, "downloaded content bundle",
		"bytes", len(data),
		"actual_hash", actualHash,
		"algorithm", algorithm,
	)

	// verify hash of downloaded bundle matches the signed hash
	if !cryptoutil.HashEqual(actualHash, hash) {
		return nil, xerrors.Newf("checksum mismatch: expected %s, got %s", hash, actualHash)
	}

	// extract to in-memory filesystem
	contentFS, err := extractTarGzToMem(data)
	if err != nil {
		return nil, xerrors.Wrap(err, "extract bundle")
	}

	l.logger.Info(ctx, "extracted content bundle to memory",
		"hash", hash,
	)

	// load provenance from the in-memory FS
	var provenance *Provenance
	prov, err := LoadProvenance(contentFS)
	if err != nil {
		l.logger.Warn(ctx, "failed to load provenance.json, continuing without provenance data",
			"hash", hash,
			"error", err,
		)
	} else {
		provenance = prov
		l.logger.Info(ctx, "loaded content provenance",
			"version", provenance.Version,
			"total_files", provenance.Summary.TotalFiles,
			"commit", provenance.Source.CommitShort,
		)
	}

	return &Snapshot{
		FS: contentFS,
		Meta: Meta{
			Hash:          hash,
			HashAlgorithm: algorithm,
			Source:        SourceS3,
			VerifiedAt:    time.Now().UTC(),
			Version:       provenanceVersion(provenance),
		},
		Provenance: provenance,
		LoadedAt:   loadedAt,
	}, nil
}

// verifyHashSignature fetches the sigstore bundle for the content bundle hash
// and verifies the hash is signed by a trusted key. If no verifier is
// configured, this is a no-op (dev/local builds).
func (l *Loader) verifyHashSignature(ctx context.Context, algorithm, hash string) error {
	if l.opts.Verifier == nil {
		l.logger.Info(ctx, "no content verifier configured, skipping hash signature verification")
		return nil
	}

	sigKey := l.sigBundleKey(algorithm, hash)
	l.logger.Info(ctx, "fetching content bundle signature",
		"bucket", l.opts.S3Bucket,
		"key", sigKey,
	)

	bundleJSON, err := l.fetchS3(ctx, sigKey, maxSigBundleSize)
	if err != nil {
		return xerrors.Wrap(err, "fetch content bundle sigstore bundle")
	}

	// the signed artifact is the hash string itself (hex-encoded)
	if err := l.opts.Verifier.VerifyBlob(ctx, bundleJSON, []byte(hash)); err != nil {
		return xerrors.Wrap(err, "content bundle hash signature verification failed")
	}

	l.logger.Info(ctx, "content bundle hash signature verified",
		"hash", hash,
	)

	return nil
}

// provenanceVersion extracts version from provenance or returns empty string
func provenanceVersion(p *Provenance) string {
	if p == nil {
		return ""
	}
	return p.Version
}

// LoadIntoManager fetches the current release and updates the content manager
func (l *Loader) LoadIntoManager(ctx context.Context, mgr *Manager) error {
	snap, err := l.Load(ctx)
	if err != nil {
		return err
	}
	mgr.Set(*snap)
	return nil
}
