// Package encryption implements streaming authenticated encryption
// for pgvault backup objects: AES-256-GCM applied to fixed-size chunks
// so backups of any size can be processed without buffering them in
// memory.
//
// Each backup uses a key derived from a master key with HKDF-SHA256
// and a random per-object salt, so no two backup objects share a key.
// Master keys never leave the environment and are never written to the
// metadata database.
package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
)

const (
	// AlgorithmAES256GCM identifies the cipher used by this package.
	AlgorithmAES256GCM = "aes-256-gcm"

	// KeySize is the size of master and derived keys in bytes.
	KeySize = 32
	// NonceSize is the AES-GCM nonce size in bytes.
	NonceSize = 12
	// NoncePrefixSize is the size of the random per-object nonce
	// prefix. The remaining 4 nonce bytes are a chunk counter.
	NoncePrefixSize = 8
	// SaltSize is the size of the random HKDF salt per object.
	SaltSize = 16
	// DefaultChunkSize is the plaintext size of one encrypted chunk.
	DefaultChunkSize = 8 << 20

	keyInfo = "pgvault/encryption/v1"
)

// Keyring maps key versions to master keys. Only version 1 is used
// today; the map exists so keys can be rotated later without breaking
// backups that were written with older versions.
type Keyring map[int][]byte

// ParseMasterKey decodes a 32-byte master key encoded as hex or base64.
func ParseMasterKey(raw string) ([]byte, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, errors.New("master key is empty")
	}

	if decoded, err := hex.DecodeString(trimmed); err == nil && len(decoded) == KeySize {
		return decoded, nil
	}

	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	for _, encoding := range encodings {
		decoded, err := encoding.DecodeString(trimmed)
		if err == nil && len(decoded) == KeySize {
			return decoded, nil
		}
	}

	return nil, fmt.Errorf(
		"master key must be %d bytes encoded as hex or base64",
		KeySize,
	)
}

// DeriveKey derives a per-backup key from a master key and a random
// salt using HKDF-SHA256.
func DeriveKey(master, salt []byte) ([]byte, error) {
	if len(master) != KeySize {
		return nil, fmt.Errorf(
			"master key must be %d bytes, got %d",
			KeySize,
			len(master),
		)
	}
	if len(salt) == 0 {
		return nil, errors.New("salt must not be empty")
	}
	return hkdf.Key(sha256.New, master, salt, keyInfo, KeySize)
}

// NewSalt returns a random HKDF salt for one backup object.
func NewSalt() ([]byte, error) {
	return randomBytes(SaltSize)
}

// NewNoncePrefix returns a random nonce prefix for one backup object.
func NewNoncePrefix() ([]byte, error) {
	return randomBytes(NoncePrefixSize)
}

func randomBytes(n int) ([]byte, error) {
	buf := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return nil, fmt.Errorf("generate random bytes: %w", err)
	}
	return buf, nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf(
			"encryption key must be %d bytes, got %d",
			KeySize,
			len(key),
		)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Writer encrypts data in chunks. Every Write buffers into the current
// chunk; full chunks are sealed and written to the destination. Close
// flushes the final partial chunk.
type Writer struct {
	dst         io.Writer
	aead        cipher.AEAD
	aad         []byte
	noncePrefix []byte
	chunkSize   int
	buf         []byte
	counter     uint64
	closed      bool
}

// NewWriter returns a Writer that encrypts everything written to it
// and forwards the ciphertext to dst. aad is authenticated but not
// encrypted; the archive format passes the serialized backup header.
func NewWriter(
	dst io.Writer,
	key []byte,
	noncePrefix []byte,
	aad []byte,
	chunkSize int,
) (*Writer, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	if len(noncePrefix) != NoncePrefixSize {
		return nil, fmt.Errorf(
			"nonce prefix must be %d bytes, got %d",
			NoncePrefixSize,
			len(noncePrefix),
		)
	}
	if chunkSize <= 0 {
		chunkSize = DefaultChunkSize
	}
	if chunkSize <= aead.Overhead() {
		return nil, errors.New("chunk size is too small")
	}

	return &Writer{
		dst:         dst,
		aead:        aead,
		aad:         aad,
		noncePrefix: noncePrefix,
		chunkSize:   chunkSize,
		buf:         make([]byte, 0, chunkSize),
	}, nil
}

// Write implements io.Writer.
func (w *Writer) Write(p []byte) (int, error) {
	if w.closed {
		return 0, errors.New("encryption writer is closed")
	}

	total := 0
	for len(p) > 0 {
		room := w.chunkSize - len(w.buf)
		n := min(room, len(p))
		w.buf = append(w.buf, p[:n]...)
		p = p[n:]
		total += n

		if len(w.buf) == w.chunkSize {
			if err := w.flushChunk(); err != nil {
				return total, err
			}
		}
	}
	return total, nil
}

// Close flushes the final partial chunk. It does not close dst.
func (w *Writer) Close() error {
	if w.closed {
		return nil
	}
	w.closed = true
	return w.flushChunk()
}

func (w *Writer) flushChunk() error {
	if len(w.buf) == 0 {
		return nil
	}
	if w.counter > math.MaxUint32 {
		return errors.New("too many chunks for a single backup object")
	}

	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(w.buf)))

	ciphertext := w.aead.Seal(nil, w.nonce(), w.buf, w.aad)

	if _, err := w.dst.Write(length[:]); err != nil {
		return fmt.Errorf("write chunk length: %w", err)
	}
	if _, err := w.dst.Write(ciphertext); err != nil {
		return fmt.Errorf("write chunk: %w", err)
	}

	w.buf = w.buf[:0]
	w.counter++
	return nil
}

func (w *Writer) nonce() []byte {
	nonce := make([]byte, NonceSize)
	copy(nonce, w.noncePrefix)
	binary.BigEndian.PutUint32(nonce[len(w.noncePrefix):], uint32(w.counter))
	return nonce
}

// Reader decrypts a chunked stream produced by Writer.
type Reader struct {
	src         io.Reader
	aead        cipher.AEAD
	aad         []byte
	noncePrefix []byte
	chunkSize   int
	buf         []byte
	counter     uint64
	err         error
}

// NewReader returns a Reader that decrypts the chunked stream from src.
func NewReader(
	src io.Reader,
	key []byte,
	noncePrefix []byte,
	aad []byte,
	chunkSize int,
) (*Reader, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	if len(noncePrefix) != NoncePrefixSize {
		return nil, fmt.Errorf(
			"nonce prefix must be %d bytes, got %d",
			NoncePrefixSize,
			len(noncePrefix),
		)
	}
	if chunkSize <= 0 {
		chunkSize = DefaultChunkSize
	}

	return &Reader{
		src:         src,
		aead:        aead,
		aad:         aad,
		noncePrefix: noncePrefix,
		chunkSize:   chunkSize,
	}, nil
}

// Read implements io.Reader.
func (r *Reader) Read(p []byte) (int, error) {
	for len(r.buf) == 0 {
		if r.err != nil {
			return 0, r.err
		}
		if err := r.readChunk(); err != nil {
			r.err = err
			return 0, err
		}
	}
	n := copy(p, r.buf)
	r.buf = r.buf[n:]
	return n, nil
}

func (r *Reader) readChunk() error {
	var length [4]byte
	if _, err := io.ReadFull(r.src, length[:]); err != nil {
		if errors.Is(err, io.EOF) {
			return io.EOF
		}
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return errors.New("truncated chunk header")
		}
		return fmt.Errorf("read chunk header: %w", err)
	}

	n := binary.BigEndian.Uint32(length[:])
	if n == 0 {
		return errors.New("invalid zero-length chunk")
	}
	if int(n) > r.chunkSize {
		return fmt.Errorf(
			"chunk length %d exceeds maximum %d",
			n,
			r.chunkSize,
		)
	}

	ciphertext := make([]byte, int(n)+r.aead.Overhead())
	if _, err := io.ReadFull(r.src, ciphertext); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return errors.New("truncated chunk data")
		}
		return fmt.Errorf("read chunk data: %w", err)
	}

	plaintext, err := r.aead.Open(nil, r.nonce(), ciphertext, r.aad)
	if err != nil {
		return fmt.Errorf("decrypt chunk %d: %w", r.counter, err)
	}

	r.buf = plaintext
	r.counter++
	return nil
}

func (r *Reader) nonce() []byte {
	nonce := make([]byte, NonceSize)
	copy(nonce, r.noncePrefix)
	binary.BigEndian.PutUint32(nonce[len(r.noncePrefix):], uint32(r.counter))
	return nonce
}
