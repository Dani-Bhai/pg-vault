package storage

import (
	"context"
	"io"
)

type Object struct {
	Key  string
	Size int64
}

type Storage interface {
	Put(
		ctx context.Context,
		key string,
		reader io.Reader,
	) error

	Get(
		ctx context.Context,
		key string,
	) (io.ReadCloser, error)

	Delete(
		ctx context.Context,
		key string,
	) error

	List(
		ctx context.Context,
		prefix string,
	) ([]Object, error)
}
