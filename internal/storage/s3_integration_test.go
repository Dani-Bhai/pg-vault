//go:build integration

package storage

import (
	"context"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// TestS3StorageIntegration exercises the S3 backend against a real
// S3-compatible endpoint (MinIO works). Configure it with:
//
//	PGVAULT_TEST_S3_ENDPOINT=http://127.0.0.1:9000
//	PGVAULT_TEST_S3_BUCKET=pgvault-test
//	AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY
func TestS3StorageIntegration(t *testing.T) {
	endpoint := os.Getenv("PGVAULT_TEST_S3_ENDPOINT")
	if endpoint == "" {
		t.Skip("PGVAULT_TEST_S3_ENDPOINT is not set")
	}

	bucket := os.Getenv("PGVAULT_TEST_S3_BUCKET")
	if bucket == "" {
		bucket = "pgvault-test"
	}
	region := os.Getenv("PGVAULT_TEST_S3_REGION")
	if region == "" {
		region = "us-east-1"
	}

	ctx := context.Background()

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		t.Fatalf("load aws config: %v", err)
	}
	client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(endpoint)
		o.UsePathStyle = true
	})

	if _, err := client.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: aws.String(bucket),
	}); err != nil {
		t.Logf("create bucket (may already exist): %v", err)
	}

	store, err := NewS3Storage(ctx, S3Config{
		Bucket:    bucket,
		Region:    region,
		Endpoint:  endpoint,
		Prefix:    "pgvault-test",
		PathStyle: true,
	})
	if err != nil {
		t.Fatalf("new s3 storage: %v", err)
	}

	key := "production/test-object.pgv"
	payload := strings.Repeat("pgvault-s3-data-", 4096)

	if err := store.Put(ctx, key, strings.NewReader(payload)); err != nil {
		t.Fatalf("put: %v", err)
	}

	reader, err := store.Get(ctx, key)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	got, err := io.ReadAll(reader)
	reader.Close()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != payload {
		t.Fatalf("round trip mismatch: got %d bytes", len(got))
	}

	objects, err := store.List(ctx, "production")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	found := false
	for _, object := range objects {
		if object.Key == key {
			found = true
			if object.Size != int64(len(payload)) {
				t.Fatalf("unexpected size: %d", object.Size)
			}
		}
	}
	if !found {
		t.Fatalf("object %s not listed: %+v", key, objects)
	}

	if err := store.Delete(ctx, key); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := store.Get(ctx, key); err == nil {
		t.Fatal("expected get after delete to fail")
	}
}
