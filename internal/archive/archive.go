// Package archive implements the pgvault backup object format.
//
// Layout:
//
//	"PGVAULT"       magic (7 bytes)
//	version         uint8 (1 byte)
//	header length   uint32, big endian
//	header          JSON
//	payload         zstd stream, optionally chunked AES-256-GCM
//
// The header is passed as additional authenticated data to every
// encrypted chunk, so altering any header field makes decryption fail.
// Compression is layered inside encryption: pg_dump output is
// compressed first, then encrypted.
package archive

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/Dani-Bhai/pg-vault/internal/compression"
	"github.com/Dani-Bhai/pg-vault/internal/encryption"
)

const (
	// Version is the current backup object format version.
	Version = 1

	// TypeLogical marks backups produced by pg_dump.
	TypeLogical = "logical"

	// CompressionZstd and CompressionNone identify the payload codec.
	CompressionZstd = "zstd"
	CompressionNone = "none"

	magic         = "PGVAULT"
	maxHeaderSize = 1 << 20
)

// Header describes a backup object. It is stored in the clear so that
// pgvault can inspect an object without the encryption key; integrity
// is protected by the chunk authentication when encryption is on.
type Header struct {
	Version     int             `json:"version"`
	Type        string          `json:"type"`
	BackupID    string          `json:"backup_id"`
	Database    string          `json:"database,omitempty"`
	CreatedAt   time.Time       `json:"created_at"`
	Compression string          `json:"compression"`
	Encryption  *EncryptionInfo `json:"encryption,omitempty"`
}

// EncryptionInfo carries the parameters needed to derive the
// per-backup key and decrypt the payload. The master key itself is
// never stored.
type EncryptionInfo struct {
	Algorithm   string `json:"algorithm"`
	KeyVersion  int    `json:"key_version"`
	Salt        []byte `json:"salt"`
	NoncePrefix []byte `json:"nonce_prefix"`
	ChunkSize   int    `json:"chunk_size"`
}

// Options configures a Writer.
type Options struct {
	Header     Header
	Encrypt    bool
	Keyring    encryption.Keyring
	KeyVersion int
	ChunkSize  int
}

// Writer streams a backup object to dst.
type Writer struct {
	zw     io.WriteCloser
	raw    io.Writer
	enc    *encryption.Writer
	closed bool
}

// NewWriter writes the backup header to dst and returns a Writer for
// the payload. Close must be called to flush all layers.
func NewWriter(dst io.Writer, opts Options) (*Writer, error) {
	header := opts.Header
	if header.Version == 0 {
		header.Version = Version
	}
	if header.Type == "" {
		header.Type = TypeLogical
	}
	if header.CreatedAt.IsZero() {
		header.CreatedAt = time.Now().UTC()
	}
	if header.Compression == "" {
		header.Compression = CompressionZstd
	}
	switch header.Compression {
	case CompressionZstd, CompressionNone:
	default:
		return nil, fmt.Errorf(
			"unsupported compression %q",
			header.Compression,
		)
	}

	header.Encryption = nil

	var (
		derivedKey  []byte
		noncePrefix []byte
		chunkSize   int
	)

	if opts.Encrypt {
		masterKey, ok := opts.Keyring[opts.KeyVersion]
		if !ok {
			return nil, fmt.Errorf(
				"no master key configured for key version %d",
				opts.KeyVersion,
			)
		}

		salt, err := encryption.NewSalt()
		if err != nil {
			return nil, err
		}
		noncePrefix, err = encryption.NewNoncePrefix()
		if err != nil {
			return nil, err
		}
		chunkSize = opts.ChunkSize
		if chunkSize <= 0 {
			chunkSize = encryption.DefaultChunkSize
		}
		derivedKey, err = encryption.DeriveKey(masterKey, salt)
		if err != nil {
			return nil, err
		}

		header.Encryption = &EncryptionInfo{
			Algorithm:   encryption.AlgorithmAES256GCM,
			KeyVersion:  opts.KeyVersion,
			Salt:        salt,
			NoncePrefix: noncePrefix,
			ChunkSize:   chunkSize,
		}
	}

	prefix, err := encodeHeader(&header)
	if err != nil {
		return nil, err
	}
	if _, err := dst.Write(prefix); err != nil {
		return nil, fmt.Errorf("write backup header: %w", err)
	}

	var encWriter *encryption.Writer
	var payload io.Writer = dst

	if opts.Encrypt {
		encWriter, err = encryption.NewWriter(
			dst,
			derivedKey,
			noncePrefix,
			prefix,
			chunkSize,
		)
		if err != nil {
			return nil, err
		}
		payload = encWriter
	}

	if header.Compression == CompressionNone {
		return &Writer{raw: payload, enc: encWriter}, nil
	}

	zw, err := compression.NewWriter(payload)
	if err != nil {
		return nil, err
	}
	return &Writer{zw: zw, enc: encWriter}, nil
}

// Write implements io.Writer.
func (w *Writer) Write(p []byte) (int, error) {
	if w.closed {
		return 0, errors.New("archive writer is closed")
	}
	if w.zw != nil {
		return w.zw.Write(p)
	}
	return w.raw.Write(p)
}

// Close flushes the compression and encryption layers. It does not
// close the destination writer.
func (w *Writer) Close() error {
	if w.closed {
		return nil
	}
	w.closed = true

	if w.zw != nil {
		if err := w.zw.Close(); err != nil {
			return fmt.Errorf("flush compression: %w", err)
		}
	}
	if w.enc != nil {
		if err := w.enc.Close(); err != nil {
			return fmt.Errorf("flush encryption: %w", err)
		}
	}
	return nil
}

// Reader decodes a backup object produced by Writer.
type Reader struct {
	src     io.Reader
	closers []io.Closer
}

// NewReader parses the header from src and returns a Reader for the
// decompressed payload. If src implements io.Closer it is closed by
// Reader.Close.
func NewReader(
	src io.Reader,
	keyring encryption.Keyring,
) (*Reader, *Header, error) {
	header, prefix, err := readHeader(src)
	if err != nil {
		return nil, nil, err
	}

	reader := &Reader{}
	if closer, ok := src.(io.Closer); ok {
		reader.closers = append(reader.closers, closer)
	}

	var payload io.Reader = src

	if header.Encryption != nil {
		info := header.Encryption
		masterKey, ok := keyring[info.KeyVersion]
		if !ok {
			return nil, nil, fmt.Errorf(
				"no master key configured for key version %d",
				info.KeyVersion,
			)
		}
		derivedKey, err := encryption.DeriveKey(masterKey, info.Salt)
		if err != nil {
			return nil, nil, err
		}
		encReader, err := encryption.NewReader(
			src,
			derivedKey,
			info.NoncePrefix,
			prefix,
			info.ChunkSize,
		)
		if err != nil {
			return nil, nil, err
		}
		payload = encReader
	}

	switch header.Compression {
	case CompressionZstd:
		zr, err := compression.NewReader(payload)
		if err != nil {
			return nil, nil, err
		}
		reader.src = zr
		reader.closers = append(reader.closers, zr)
	case CompressionNone:
		reader.src = payload
	default:
		return nil, nil, fmt.Errorf(
			"unsupported compression %q",
			header.Compression,
		)
	}

	return reader, header, nil
}

// Read implements io.Reader.
func (r *Reader) Read(p []byte) (int, error) {
	return r.src.Read(p)
}

// Close closes the decoder layers and the underlying source.
func (r *Reader) Close() error {
	var first error
	for i := len(r.closers) - 1; i >= 0; i-- {
		if err := r.closers[i].Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// ReadHeader parses and validates a backup header without needing an
// encryption key, which is what "pgvault inspect" uses.
func ReadHeader(r io.Reader) (*Header, error) {
	header, _, err := readHeader(r)
	return header, err
}

func encodeHeader(h *Header) ([]byte, error) {
	payload, err := json.Marshal(h)
	if err != nil {
		return nil, fmt.Errorf("encode backup header: %w", err)
	}
	if len(payload) > maxHeaderSize {
		return nil, errors.New("backup header is too large")
	}

	var buf bytes.Buffer
	buf.WriteString(magic)
	buf.WriteByte(Version)

	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(payload)))
	buf.Write(length[:])
	buf.Write(payload)

	return buf.Bytes(), nil
}

// readHeader returns the parsed header and the exact bytes it was
// serialized from; those bytes are used as authenticated data.
func readHeader(r io.Reader) (*Header, []byte, error) {
	head := make([]byte, len(magic)+5)
	if _, err := io.ReadFull(r, head); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, nil, errors.New("not a pgvault backup object")
		}
		return nil, nil, fmt.Errorf("read backup header: %w", err)
	}
	if string(head[:len(magic)]) != magic {
		return nil, nil, errors.New("not a pgvault backup object")
	}
	if head[len(magic)] != Version {
		return nil, nil, fmt.Errorf(
			"unsupported backup format version %d",
			head[len(magic)],
		)
	}

	length := binary.BigEndian.Uint32(head[len(magic)+1:])
	if length == 0 || length > maxHeaderSize {
		return nil, nil, errors.New("invalid backup header size")
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, nil, fmt.Errorf("read backup header: %w", err)
	}

	header := &Header{}
	if err := json.Unmarshal(payload, header); err != nil {
		return nil, nil, fmt.Errorf("decode backup header: %w", err)
	}
	if err := validateHeader(header); err != nil {
		return nil, nil, err
	}

	prefix := make([]byte, 0, len(head)+len(payload))
	prefix = append(prefix, head...)
	prefix = append(prefix, payload...)

	return header, prefix, nil
}

func validateHeader(h *Header) error {
	if h.Version != Version {
		return fmt.Errorf(
			"unsupported backup format version %d",
			h.Version,
		)
	}
	if h.BackupID == "" {
		return errors.New("backup header is missing the backup ID")
	}
	switch h.Compression {
	case CompressionZstd, CompressionNone:
	default:
		return fmt.Errorf("unsupported compression %q", h.Compression)
	}

	if h.Encryption != nil {
		if h.Encryption.Algorithm != encryption.AlgorithmAES256GCM {
			return fmt.Errorf(
				"unsupported encryption algorithm %q",
				h.Encryption.Algorithm,
			)
		}
		if len(h.Encryption.Salt) == 0 {
			return errors.New("backup header is missing the encryption salt")
		}
		if len(h.Encryption.NoncePrefix) != encryption.NoncePrefixSize {
			return errors.New("backup header has an invalid nonce prefix")
		}
		if h.Encryption.ChunkSize <= 0 || h.Encryption.ChunkSize > 64<<20 {
			return errors.New("backup header has an invalid chunk size")
		}
	}
	return nil
}
