// internal/content/loader.go
package content

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/ssm"

	"github.com/keithlinneman/linnemanlabs-web/internal/cryptoutil"
	"github.com/keithlinneman/linnemanlabs-web/internal/log"
	"github.com/keithlinneman/linnemanlabs-web/internal/xerrors"
)

type LoaderOptions struct {
	Logger log.Logger

	// SSM parameter containing the bundle SHA256 hash
	SSMParam string

	// S3 location for bundles: s3://{bucket}/{prefix}/{hash}.tar.gz
	S3Bucket string
	S3Prefix string

	// Local directory for extracted content
	ExtractDir string

	// AWS config (uses default if nil)
	AWSConfig *aws.Config

	// Verifier for bundle signatures
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
	if opts.ExtractDir == "" {
		// use temp dir if not specified
		var err error
		opts.ExtractDir, err = os.MkdirTemp("", "content-site-*")
		if err != nil {
			return nil, xerrors.Wrap(err, "create temp extract dir")
		}
	}
	if opts.ExtractDir != "" {
		// ensure extract dir exists
		if err := os.MkdirAll(opts.ExtractDir, 0750); err != nil {
			return nil, xerrors.Wrapf(err, "create extract dir %s", opts.ExtractDir)
		}
	}

	return &Loader{
		opts: opts,
	}, nil
}

// FetchCurrentBundleHash gets the current bundle hash from SSM
func (l *Loader) FetchCurrentBundleHash(ctx context.Context) (string, error) {
	out, err := l.ssmClient.GetParameter(ctx, &ssm.GetParameterInput{
		Name:           aws.String(l.opts.SSMParam),
		WithDecryption: aws.Bool(true),
	})
	if err != nil {
		return "", xerrors.Wrapf(err, "get SSM parameter %s", l.opts.SSMParam)
	}
	if out.Parameter == nil || out.Parameter.Value == nil {
		return "", xerrors.Newf("SSM parameter %s has no value", l.opts.SSMParam)
	}

	hash := strings.TrimSpace(*out.Parameter.Value)
	if hash == "" {
		return "", xerrors.Newf("SSM parameter %s is empty", l.opts.SSMParam)
	}

	return hash, nil
}

// s3Key returns the S3 object key for a given hash
func (l *Loader) s3Key(hash string) string {
	if l.opts.S3Prefix != "" {
		return fmt.Sprintf("%s/%s.tar.gz", l.opts.S3Prefix, hash)
	}
	return fmt.Sprintf("%s.tar.gz", hash)
}

// Download fetches and verifies a bundle from S3
func (l *Loader) Download(ctx context.Context, hash string) (string, error) {
	key := l.s3Key(hash)

	l.logger.Info(ctx, "downloading content bundle",
		"bucket", l.opts.S3Bucket,
		"key", key,
		"expected_hash", hash,
	)

	out, err := l.s3Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(l.opts.S3Bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return "", xerrors.Wrapf(err, "get S3 object s3://%s/%s", l.opts.S3Bucket, key)
	}
	defer out.Body.Close()

	// create temp file for the download
	tmpFile, err := os.CreateTemp("", "content-bundle-*.tar.gz")
	if err != nil {
		return "", xerrors.Wrap(err, "create temp file")
	}
	tmpPath := tmpFile.Name()

	// copy and compute hash
	written, actualHash, err := copyWithHash(tmpFile, out.Body)
	tmpFile.Close()
	if err != nil {
		os.Remove(tmpPath)
		return "", xerrors.Wrap(err, "download bundle")
	}

	l.logger.Info(ctx, "downloaded content bundle",
		"bytes", written,
		"actual_hash", actualHash,
	)

	// our policy is to always use cryptoutil/hashEqual for comparing hashes, even though
	// this is not user-supplied or a secret value so timing attacks are not a concern here.
	if !cryptoutil.HashEqual(actualHash, hash) {
		os.Remove(tmpPath)
		return "", xerrors.Newf("checksum mismatch: expected %s, got %s", hash, actualHash)
	}

	return tmpPath, nil
}

// Load fetches the current release and returns a Snapshot
func (l *Loader) Load(ctx context.Context) (*Snapshot, error) {
	hash, err := l.FetchCurrentBundleHash(ctx)
	if err != nil {
		return nil, err
	}

	return l.LoadHash(ctx, hash)
}

// LoadHash fetches a specific bundle by hash and returns a Snapshot
func (l *Loader) LoadHash(ctx context.Context, hash string) (*Snapshot, error) {
	loadedAt := time.Now().UTC()

	// Download the bundle
	bundlePath, err := l.Download(ctx, hash)
	if err != nil {
		return nil, err
	}
	defer os.Remove(bundlePath)

	// determine extraction directory
	extractDir := l.opts.ExtractDir
	if extractDir == "" {
		extractDir, err = os.MkdirTemp("", "content-site-*")
		if err != nil {
			return nil, xerrors.Wrap(err, "create extract dir")
		}
	} else {
		// use hash subdirectory to allow atomic swaps
		extractDir = filepath.Join(extractDir, hash)
		if err := os.MkdirAll(extractDir, 0755); err != nil {
			return nil, xerrors.Wrapf(err, "create extract dir %s", extractDir)
		}
	}

	l.logger.Info(ctx, "extracting content bundle",
		"hash", hash,
		"dest", extractDir,
	)

	if err := extractTarGz(bundlePath, extractDir); err != nil {
		os.RemoveAll(extractDir)
		return nil, xerrors.Wrap(err, "extract bundle")
	}

	l.logger.Info(ctx, "extracted content bundle",
		"hash", hash,
		"dest", extractDir,
	)

	// Create the filesystem for the extracted content
	contentFS := os.DirFS(extractDir)

	// Attempt to load provenance.json
	var provenance *Provenance
	prov, err := LoadProvenance(contentFS)
	if err != nil {
		// Log warning but dont fail for now - in future will have this mean we fallback to previous snapshot
		l.logger.Warn(ctx, "failed to load provenance.json, continuing without provenance data",
			"hash", hash,
			"error", err,
		)
	} else {
		provenance = prov
		l.logger.Info(ctx, "loaded content provenance",
			"version", provenance.Version,
			"content_hash", provenance.ContentHash,
			"total_files", provenance.Summary.TotalFiles,
			"commit", provenance.Source.CommitShort,
		)
	}

	return &Snapshot{
		FS: contentFS,
		Meta: Meta{
			SHA256:     hash,
			Source:     SourceS3,
			VerifiedAt: time.Now().UTC(),
			Version:    provenanceVersion(provenance),
		},
		Provenance: provenance,
		LoadedAt:   loadedAt,
	}, nil
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
