package evidence

import (
	"context"
	"io"
	"path"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/keithlinneman/linnemanlabs-web/internal/log"
	"github.com/keithlinneman/linnemanlabs-web/internal/xerrors"
)

const (
	// max size of a single evidence file (bytes)
	MaxArtifactSize = 5 * 1024 * 1024

	// max number of artifacts to fetch per release
	MaxArtifacts = 50
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

// s3Prefix returns the full S3 key prefix for listing evidence objects
func (l *Loader) s3Prefix() string {
	parts := []string{}
	if l.opts.Prefix != "" {
		parts = append(parts, strings.TrimSuffix(l.opts.Prefix, "/"))
	}
	parts = append(parts, l.opts.ReleaseID)
	return strings.Join(parts, "/") + "/"
}

// Load discovers and fetches all evidence artifacts for the configured release
func (l *Loader) Load(ctx context.Context) (*Bundle, error) {
	prefix := l.s3Prefix()

	l.logger.Info(ctx, "discovering evidence artifacts",
		"bucket", l.opts.Bucket,
		"prefix", prefix,
		"release_id", l.opts.ReleaseID,
	)

	// list objects under the release prefix
	keys, err := l.listKeys(ctx, prefix)
	if err != nil {
		return nil, err
	}

	if len(keys) == 0 {
		l.logger.Info(ctx, "no evidence artifacts found",
			"bucket", l.opts.Bucket,
			"prefix", prefix,
		)
		return &Bundle{
			ReleaseID: l.opts.ReleaseID,
			Bucket:    l.opts.Bucket,
			Prefix:    prefix,
			Artifacts: nil,
			FetchedAt: time.Now().UTC(),
		}, nil
	}

	if len(keys) > MaxArtifacts {
		l.logger.Warn(ctx, "too many evidence artifacts, truncating",
			"found", len(keys),
			"max", MaxArtifacts,
		)
		keys = keys[:MaxArtifacts]
	}

	l.logger.Info(ctx, "fetching evidence artifacts",
		"count", len(keys),
		"bucket", l.opts.Bucket,
	)

	// fetch each artifact individually; failures are warned but don't block others
	var artifacts []Artifact
	for _, key := range keys {
		art, err := l.fetchArtifact(ctx, key, prefix)
		if err != nil {
			l.logger.Warn(ctx, "failed to fetch evidence artifact, skipping",
				"key", key,
				"error", err,
			)
			continue
		}
		artifacts = append(artifacts, *art)
	}

	bundle := &Bundle{
		ReleaseID: l.opts.ReleaseID,
		Bucket:    l.opts.Bucket,
		Prefix:    prefix,
		Artifacts: artifacts,
		FetchedAt: time.Now().UTC(),
	}
	bundle.buildIndex()

	l.logger.Info(ctx, "loaded evidence bundle",
		"release_id", l.opts.ReleaseID,
		"artifact_count", len(artifacts),
		"artifact_names", bundle.Names(),
	)

	return bundle, nil
}

// listKeys lists all object keys under the given S3 prefix
func (l *Loader) listKeys(ctx context.Context, prefix string) ([]string, error) {
	var keys []string

	paginator := s3.NewListObjectsV2Paginator(l.s3Client, &s3.ListObjectsV2Input{
		Bucket: aws.String(l.opts.Bucket),
		Prefix: aws.String(prefix),
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, xerrors.Wrapf(err, "list s3://%s/%s", l.opts.Bucket, prefix)
		}
		for _, obj := range page.Contents {
			if obj.Key == nil {
				continue
			}
			key := *obj.Key
			// skip directories
			if strings.HasSuffix(key, "/") {
				continue
			}
			keys = append(keys, key)
		}

		// safety cap
		if len(keys) > MaxArtifacts {
			break
		}
	}

	return keys, nil
}

// fetchArtifact downloads a single evidence file from S3
func (l *Loader) fetchArtifact(ctx context.Context, key, prefix string) (*Artifact, error) {
	out, err := l.s3Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(l.opts.Bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, xerrors.Wrapf(err, "get s3://%s/%s", l.opts.Bucket, key)
	}
	defer out.Body.Close()

	// read with size limit for safety
	lr := io.LimitReader(out.Body, MaxArtifactSize+1)
	data, err := io.ReadAll(lr)
	if err != nil {
		return nil, xerrors.Wrapf(err, "read s3://%s/%s", l.opts.Bucket, key)
	}
	if int64(len(data)) > MaxArtifactSize {
		return nil, xerrors.Newf("artifact too large: s3://%s/%s (%d bytes, max %d)",
			l.opts.Bucket, key, len(data), MaxArtifactSize)
	}

	// derive artifact name by stripping the release prefix
	// e.g. "apps/.../attestations/rel-123/sbom.spdx.json" -> "sbom.spdx.json"
	name := strings.TrimPrefix(key, prefix)
	if name == "" {
		name = path.Base(key)
	}

	var contentType string
	if out.ContentType != nil {
		contentType = *out.ContentType
	}

	return &Artifact{
		Name:        name,
		S3Key:       key,
		RawJSON:     data,
		Size:        int64(len(data)),
		ContentType: contentType,
		FetchedAt:   time.Now().UTC(),
	}, nil
}
