// Package compression wraps zstd, the compression codec used for
// pgvault backup payloads.
package compression

import (
	"io"

	"github.com/klauspost/compress/zstd"
)

// Name identifies the zstd codec in backup headers and metadata.
const Name = "zstd"

// NewWriter returns a zstd encoder writing to w. Close must be called
// to flush the final frame.
func NewWriter(w io.Writer) (io.WriteCloser, error) {
	return zstd.NewWriter(w, zstd.WithEncoderLevel(zstd.SpeedDefault))
}

// NewReader returns a zstd decoder reading from r.
func NewReader(r io.Reader) (io.ReadCloser, error) {
	decoder, err := zstd.NewReader(r, zstd.WithDecoderConcurrency(1))
	if err != nil {
		return nil, err
	}
	return decoderCloser{decoder}, nil
}

// decoderCloser adapts zstd.Decoder, whose Close does not return an
// error, to io.ReadCloser.
type decoderCloser struct {
	*zstd.Decoder
}

func (d decoderCloser) Close() error {
	d.Decoder.Close()
	return nil
}
