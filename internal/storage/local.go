package storage

import (
	"context"
	"io"
	"os"
	"path/filepath"
)

// LocalStorage stores objects as files below BaseDir. Keys map directly
// to relative file paths.
type LocalStorage struct {
	BaseDir string
}

var _ Storage = (*LocalStorage)(nil)

func NewLocalStorage(baseDir string) *LocalStorage {
	return &LocalStorage{
		BaseDir: baseDir,
	}
}

// Put writes reader to key. Data goes to a temporary file first and is
// renamed into place only after a successful write and fsync, so an
// interrupted backup never leaves behind a file that looks complete.
func (s *LocalStorage) Put(
	ctx context.Context,
	key string,
	reader io.Reader,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	path := filepath.Join(s.BaseDir, key)

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	tmp := path + ".tmp"

	file, err := os.Create(tmp)
	if err != nil {
		return err
	}

	// After a successful rename the temp file no longer exists and
	// os.Remove is a harmless no-op.
	defer func() {
		file.Close()
		os.Remove(tmp)
	}()

	if _, err := io.Copy(file, reader); err != nil {
		return err
	}

	if err := file.Sync(); err != nil {
		return err
	}

	if err := file.Close(); err != nil {
		return err
	}

	return os.Rename(tmp, path)
}

// Get opens the object stored under key.
func (s *LocalStorage) Get(
	ctx context.Context,
	key string,
) (io.ReadCloser, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	return os.Open(filepath.Join(s.BaseDir, key))
}

// Delete removes the object stored under key.
func (s *LocalStorage) Delete(
	ctx context.Context,
	key string,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	return os.Remove(filepath.Join(s.BaseDir, key))
}

// List returns every file below prefix.
func (s *LocalStorage) List(
	ctx context.Context,
	prefix string,
) ([]Object, error) {

	root := filepath.Join(s.BaseDir, prefix)

	var objects []Object

	err := filepath.Walk(root, func(
		path string,
		info os.FileInfo,
		err error,
	) error {

		if err != nil {
			// A missing root simply means nothing was stored yet.
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}

		if err := ctx.Err(); err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		relative, err := filepath.Rel(s.BaseDir, path)
		if err != nil {
			return err
		}

		objects = append(objects, Object{
			Key:  relative,
			Size: info.Size(),
		})

		return nil
	})

	return objects, err
}
