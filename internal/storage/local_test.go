package storage

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLocalStorageRoundTrip(t *testing.T) {
	store := NewLocalStorage(t.TempDir())
	ctx := context.Background()

	if err := store.Put(ctx, "production/backup.pgv", strings.NewReader("hello")); err != nil {
		t.Fatalf("put: %v", err)
	}

	reader, err := store.Get(ctx, "production/backup.pgv")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	got, err := io.ReadAll(reader)
	reader.Close()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("unexpected content: %q", got)
	}

	objects, err := store.List(ctx, "production")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(objects) != 1 || objects[0].Key != "production/backup.pgv" || objects[0].Size != 5 {
		t.Fatalf("unexpected objects: %+v", objects)
	}

	if err := store.Delete(ctx, "production/backup.pgv"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	objects, err = store.List(ctx, "production")
	if err != nil || len(objects) != 0 {
		t.Fatalf("expected empty listing, got %v (%v)", objects, err)
	}
}

func TestLocalStorageListMissingPrefix(t *testing.T) {
	store := NewLocalStorage(t.TempDir())

	objects, err := store.List(context.Background(), "nothing/here")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(objects) != 0 {
		t.Fatalf("expected no objects, got %+v", objects)
	}
}

func TestLocalStorageFailedPutLeavesNothing(t *testing.T) {
	store := NewLocalStorage(t.TempDir())

	err := store.Put(context.Background(), "db/x.pgv", failingReader{})
	if err == nil {
		t.Fatal("expected put to fail")
	}

	for _, name := range []string{"db/x.pgv", "db/x.pgv.tmp"} {
		_, err := os.Stat(filepath.Join(store.BaseDir, name))
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("expected %s to be removed, stat: %v", name, err)
		}
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) {
	return 0, errors.New("boom")
}
