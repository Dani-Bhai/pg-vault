package backup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"time"

	"github.com/google/uuid"

	"github.com/Dani-Bhai/pg-vault/internal/archive"
	"github.com/Dani-Bhai/pg-vault/internal/encryption"
	"github.com/Dani-Bhai/pg-vault/internal/metadata"
	"github.com/Dani-Bhai/pg-vault/internal/postgres"
	"github.com/Dani-Bhai/pg-vault/internal/storage"
)

// Request describes one backup run.
type Request struct {
	DatabaseID     string
	DatabaseName   string
	DatabaseURL    string
	Storage        storage.Storage
	StorageBackend string
	Encryption     bool
	Keyring        encryption.Keyring
	KeyVersion     int
	Trigger        string
}

// Manager orchestrates a backup: pg_dump output is streamed through
// compression, encryption and checksumming directly into a storage
// backend. No temporary files are involved, and the metadata database
// records the lifecycle of every run.
type Manager struct {
	dumper *postgres.Dumper
	store  *metadata.Store
}

func NewManager(dumper *postgres.Dumper, store *metadata.Store) *Manager {
	return &Manager{
		dumper: dumper,
		store:  store,
	}
}

// Backup dumps req.DatabaseURL and stores the object under
// "<name>/<id>.pgv". The returned Backup is non-nil even on failure.
func (m *Manager) Backup(ctx context.Context, req Request) (*Backup, error) {
	id := uuid.NewString()
	started := time.Now().UTC()
	key := fmt.Sprintf("%s/%s.pgv", req.DatabaseName, id)

	encryptionName := ""
	keyVersion := 0
	if req.Encryption {
		encryptionName = encryption.AlgorithmAES256GCM
		keyVersion = req.KeyVersion
	}

	result := &Backup{
		ID:             id,
		DatabaseName:   req.DatabaseName,
		StartedAt:      started,
		Path:           key,
		Status:         StatusRunning,
		FormatVersion:  archive.Version,
		Compression:    archive.CompressionZstd,
		Encryption:     encryptionName,
		KeyVersion:     keyVersion,
		StorageBackend: req.StorageBackend,
		Trigger:        req.Trigger,
	}

	if err := m.store.CreateBackup(metadata.BackupRecord{
		ID:             result.ID,
		DatabaseID:     req.DatabaseID,
		DatabaseName:   result.DatabaseName,
		Status:         string(result.Status),
		Path:           result.Path,
		FormatVersion:  result.FormatVersion,
		Compression:    result.Compression,
		Encryption:     result.Encryption,
		KeyVersion:     result.KeyVersion,
		StorageBackend: result.StorageBackend,
		Trigger:        result.Trigger,
		StartedAt:      result.StartedAt,
	}); err != nil {
		return result, fmt.Errorf("record backup start: %w", err)
	}

	backupErr := m.stream(ctx, key, req, result)

	result.CompletedAt = time.Now().UTC()
	if backupErr != nil {
		result.Status = StatusFailed
		result.Error = backupErr.Error()
	} else {
		result.Status = StatusSuccess
	}

	if err := m.store.FinishBackup(
		result.ID,
		string(result.Status),
		result.Error,
		result.CompletedAt,
		result.SizeBytes,
		result.Checksum,
	); err != nil {
		if backupErr != nil {
			return result, fmt.Errorf(
				"%v (also failed to record the result: %w)",
				backupErr,
				err,
			)
		}
		return result, fmt.Errorf("record backup result: %w", err)
	}

	return result, backupErr
}

func (m *Manager) stream(
	ctx context.Context,
	key string,
	req Request,
	result *Backup,
) error {
	reader, writer := io.Pipe()

	var size byteCounter
	checksum := sha256.New()

	dumpErr := make(chan error, 1)

	go func() {
		err := func() error {
			archiveWriter, err := archive.NewWriter(
				writer,
				archive.Options{
					Header: archive.Header{
						BackupID:  result.ID,
						Database:  req.DatabaseName,
						CreatedAt: result.StartedAt,
					},
					Encrypt:    req.Encryption,
					Keyring:    req.Keyring,
					KeyVersion: req.KeyVersion,
				},
			)
			if err != nil {
				return err
			}

			if err := m.dumper.Dump(ctx, req.DatabaseURL, archiveWriter); err != nil {
				return err
			}

			return archiveWriter.Close()
		}()

		writer.CloseWithError(err)
		dumpErr <- err
	}()

	putErr := req.Storage.Put(
		ctx,
		key,
		io.TeeReader(reader, io.MultiWriter(&size, checksum)),
	)

	if putErr != nil {
		// Unblock the writer goroutine: storage has stopped reading,
		// so further writes must fail instead of blocking forever.
		reader.CloseWithError(putErr)
	}

	// When both sides fail, the dumper error is the more useful one.
	if err := <-dumpErr; err != nil {
		return err
	}
	if putErr != nil {
		return putErr
	}

	result.SizeBytes = size.n
	result.Checksum = hex.EncodeToString(checksum.Sum(nil))

	return nil
}

// byteCounter counts the bytes streamed through it.
type byteCounter struct {
	n int64
}

func (c *byteCounter) Write(p []byte) (int, error) {
	c.n += int64(len(p))
	return len(p), nil
}
