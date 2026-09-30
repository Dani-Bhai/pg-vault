package storage

import (
	"context"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/johannesboyne/gofakes3"
	"github.com/johannesboyne/gofakes3/backend/s3mem"
)

func TestS3StorageRoundTrip(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "pgvault-test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "pgvault-test")
	t.Setenv("AWS_SESSION_TOKEN", "")
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("AWS_REGION", "us-east-1")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")

	backend := s3mem.New()
	server := httptest.NewServer(
		gofakes3.New(backend, gofakes3.WithAutoBucket(true)).Server(),
	)
	defer server.Close()

	ctx := context.Background()

	store, err := NewS3Storage(ctx, S3Config{
		Bucket:    "pgvault-test",
		Region:    "us-east-1",
		Endpoint:  server.URL,
		Prefix:    "pgvault",
		PathStyle: true,
	})
	if err != nil {
		t.Fatalf("new s3 storage: %v", err)
	}

	key := "production/backup.pgv"
	payload := strings.Repeat("pgvault-s3-data-", 1000)

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
		t.Fatalf("round trip mismatch: got %d bytes, want %d", len(got), len(payload))
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
