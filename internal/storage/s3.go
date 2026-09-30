package storage

import (
	"context"
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// S3Config configures an S3-compatible storage backend. The same
// settings work with AWS S3, MinIO, Cloudflare R2, Backblaze B2 and
// DigitalOcean Spaces; only the endpoint differs.
type S3Config struct {
	Bucket    string
	Region    string
	Endpoint  string
	Prefix    string
	PathStyle bool
}

// S3Storage stores objects in an S3-compatible bucket. Uploads use
// multipart transfers for large backups, so a failed part can be
// retried without restarting the whole upload.
type S3Storage struct {
	client   *s3.Client
	uploader *manager.Uploader
	bucket   string
	prefix   string
}

var _ Storage = (*S3Storage)(nil)

// NewS3Storage builds an S3 backend. Credentials come from the
// standard AWS chain (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY,
// AWS_PROFILE, instance roles, ...).
func NewS3Storage(ctx context.Context, cfg S3Config) (*S3Storage, error) {
	if cfg.Bucket == "" {
		return nil, fmt.Errorf("s3 bucket is required")
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(
		ctx,
		awsconfig.WithRegion(cfg.Region),
	)
	if err != nil {
		return nil, fmt.Errorf("load aws configuration: %w", err)
	}

	client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		if cfg.Endpoint != "" {
			o.BaseEndpoint = aws.String(cfg.Endpoint)
			o.UsePathStyle = cfg.PathStyle
		}
	})

	uploader := manager.NewUploader(client, func(u *manager.Uploader) {
		u.PartSize = 8 << 20
		u.Concurrency = 4
	})

	return &S3Storage{
		client:   client,
		uploader: uploader,
		bucket:   cfg.Bucket,
		prefix:   strings.Trim(cfg.Prefix, "/"),
	}, nil
}

func (s *S3Storage) fullKey(key string) string {
	if s.prefix == "" {
		return key
	}
	return path.Join(s.prefix, key)
}

// Put streams reader into the bucket as key.
func (s *S3Storage) Put(
	ctx context.Context,
	key string,
	reader io.Reader,
) error {
	_, err := s.uploader.Upload(ctx, &s3.PutObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(s.fullKey(key)),
		Body:   reader,
	})
	if err != nil {
		return fmt.Errorf("s3 put %s: %w", key, err)
	}
	return nil
}

// Get opens the object stored under key.
func (s *S3Storage) Get(
	ctx context.Context,
	key string,
) (io.ReadCloser, error) {
	out, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(s.fullKey(key)),
	})
	if err != nil {
		return nil, fmt.Errorf("s3 get %s: %w", key, err)
	}
	return out.Body, nil
}

// Delete removes the object stored under key.
func (s *S3Storage) Delete(ctx context.Context, key string) error {
	_, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(s.fullKey(key)),
	})
	if err != nil {
		return fmt.Errorf("s3 delete %s: %w", key, err)
	}
	return nil
}

// List returns every object below prefix.
func (s *S3Storage) List(
	ctx context.Context,
	prefix string,
) ([]Object, error) {
	paginator := s3.NewListObjectsV2Paginator(
		s.client,
		&s3.ListObjectsV2Input{
			Bucket: aws.String(s.bucket),
			Prefix: aws.String(s.fullKey(prefix)),
		},
	)

	strip := ""
	if s.prefix != "" {
		strip = s.prefix + "/"
	}

	var objects []Object
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("s3 list %s: %w", prefix, err)
		}
		for _, object := range page.Contents {
			objects = append(objects, Object{
				Key:  strings.TrimPrefix(aws.ToString(object.Key), strip),
				Size: aws.ToInt64(object.Size),
			})
		}
	}
	return objects, nil
}
