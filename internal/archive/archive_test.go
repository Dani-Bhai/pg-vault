package archive

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"

	"github.com/Dani-Bhai/pg-vault/internal/encryption"
)

func newKeyring(t *testing.T) encryption.Keyring {
	t.Helper()
	key := make([]byte, encryption.KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return encryption.Keyring{1: key}
}

func TestRoundTripEncrypted(t *testing.T) {
	keyring := newKeyring(t)
	payload := bytes.Repeat([]byte("pg_dump-data-"), 10000)

	var buf bytes.Buffer
	writer, err := NewWriter(&buf, Options{
		Header: Header{
			BackupID: "backup-1",
			Database: "production",
		},
		Encrypt:    true,
		Keyring:    keyring,
		KeyVersion: 1,
		ChunkSize:  1024,
	})
	if err != nil {
		t.Fatalf("new writer: %v", err)
	}
	if _, err := writer.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	reader, header, err := NewReader(&buf, keyring)
	if err != nil {
		t.Fatalf("new reader: %v", err)
	}
	defer reader.Close()

	if header.BackupID != "backup-1" || header.Database != "production" {
		t.Fatalf("unexpected header: %+v", header)
	}
	if header.Type != TypeLogical || header.Compression != CompressionZstd {
		t.Fatalf("unexpected header defaults: %+v", header)
	}
	if header.Encryption == nil ||
		header.Encryption.Algorithm != encryption.AlgorithmAES256GCM {
		t.Fatalf("expected encrypted header, got %+v", header.Encryption)
	}

	got, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("encrypted round trip mismatch")
	}
}

func TestRoundTripUnencrypted(t *testing.T) {
	payload := bytes.Repeat([]byte("plain-data-"), 5000)

	var buf bytes.Buffer
	writer, err := NewWriter(&buf, Options{
		Header: Header{BackupID: "backup-2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	reader, header, err := NewReader(&buf, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()

	if header.Encryption != nil {
		t.Fatal("expected unencrypted header")
	}

	got, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("unencrypted round trip mismatch")
	}
}

func TestHeaderTamperBreaksDecryption(t *testing.T) {
	keyring := newKeyring(t)

	var buf bytes.Buffer
	writer, err := NewWriter(&buf, Options{
		Header: Header{
			BackupID: "backup-3",
			Database: "production",
		},
		Encrypt:    true,
		Keyring:    keyring,
		KeyVersion: 1,
		ChunkSize:  512,
	})
	if err != nil {
		t.Fatal(err)
	}
	writer.Write(bytes.Repeat([]byte("x"), 4096))
	writer.Close()

	raw := buf.Bytes()
	index := bytes.Index(raw, []byte("production"))
	if index < 0 {
		t.Fatal("database name not found in header")
	}
	// Same length, still valid JSON, different content.
	raw[index+1] = '0'

	reader, _, err := NewReader(bytes.NewReader(raw), keyring)
	if err != nil {
		// Rejecting an inconsistent header early is also fine.
		return
	}
	defer reader.Close()

	if _, err := io.ReadAll(reader); err == nil {
		t.Fatal("expected tampered header to fail authentication")
	}
}

func TestWrongMasterKeyFails(t *testing.T) {
	keyring := newKeyring(t)

	var buf bytes.Buffer
	writer, _ := NewWriter(&buf, Options{
		Header:     Header{BackupID: "backup-4"},
		Encrypt:    true,
		Keyring:    keyring,
		KeyVersion: 1,
		ChunkSize:  512,
	})
	writer.Write(bytes.Repeat([]byte("x"), 4096))
	writer.Close()

	reader, _, err := NewReader(&buf, newKeyring(t))
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()

	if _, err := io.ReadAll(reader); err == nil {
		t.Fatal("expected wrong master key to fail decryption")
	}
}

func TestReadHeaderWithoutKey(t *testing.T) {
	keyring := newKeyring(t)

	var buf bytes.Buffer
	writer, _ := NewWriter(&buf, Options{
		Header: Header{
			BackupID: "backup-5",
			Database: "staging",
		},
		Encrypt:    true,
		Keyring:    keyring,
		KeyVersion: 1,
	})
	writer.Close()

	header, err := ReadHeader(&buf)
	if err != nil {
		t.Fatalf("read header: %v", err)
	}
	if header.BackupID != "backup-5" || header.Database != "staging" {
		t.Fatalf("unexpected header: %+v", header)
	}
	if header.Encryption == nil {
		t.Fatal("expected encryption info")
	}
}

func TestRejectsForeignBytes(t *testing.T) {
	if _, err := ReadHeader(bytes.NewReader([]byte("not a backup"))); err == nil {
		t.Fatal("expected foreign bytes to be rejected")
	}
}
