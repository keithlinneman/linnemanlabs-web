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
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/ssm"

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
}

type Loader struct {
	opts      LoaderOptions
	ssmClient *ssm.Client
	s3Client  *s3.Client
	logger    log.Logger
}

// NewLoader creates a new content Loader with the given options
func NewLoader(ctx context.Context, opts LoaderOptions) (*Loader, error) {
	if opts.SSMParam == "" {
		return nil, xerrors.New("SSMParam is required")
	}
	if opts.S3Bucket == "" {
		return nil, xerrors.New("S3Bucket is required")
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
			return nil, xerrors.Wrap(err, "load AWS config")
		}
	}

	return &Loader{
		opts:      opts,
		ssmClient: ssm.NewFromConfig(awsCfg),
		s3Client:  s3.NewFromConfig(awsCfg),
		logger:    opts.Logger,
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

	// verify checksum
	if actualHash != hash {
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

	return &Snapshot{
		FS: os.DirFS(extractDir),
		Meta: Meta{
			SHA256:     hash,
			Source:     SourceS3,
			VerifiedAt: time.Now(),
		},
	}, nil
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
