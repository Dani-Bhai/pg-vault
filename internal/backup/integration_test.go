//go:build integration

package backup_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Dani-Bhai/pg-vault/internal/archive"
	"github.com/Dani-Bhai/pg-vault/internal/backup"
	"github.com/Dani-Bhai/pg-vault/internal/encryption"
	"github.com/Dani-Bhai/pg-vault/internal/metadata"
	"github.com/Dani-Bhai/pg-vault/internal/postgres"
	"github.com/Dani-Bhai/pg-vault/internal/storage"
)

// TestEncryptedBackupRestores performs a real backup against a real
// PostgreSQL server, then decrypts and decompresses the stored object,
// verifies the checksum, and restores it into a scratch database.
//
// Configure with:
//
//	PGVAULT_TEST_DATABASE_URL=postgresql://postgres:...@127.0.0.1:55432/demo
//	PGVAULT_TEST_ADMIN_URL=postgresql://postgres:...@127.0.0.1:55432/postgres
//	PGVAULT_TEST_MASTER_KEY=<64 hex chars>
func TestEncryptedBackupRestores(t *testing.T) {
	databaseURL := os.Getenv("PGVAULT_TEST_DATABASE_URL")
	adminURL := os.Getenv("PGVAULT_TEST_ADMIN_URL")
	rawKey := os.Getenv("PGVAULT_TEST_MASTER_KEY")
	if databaseURL == "" || adminURL == "" || rawKey == "" {
		t.Skip("PGVAULT_TEST_DATABASE_URL, PGVAULT_TEST_ADMIN_URL and PGVAULT_TEST_MASTER_KEY are required")
	}

	masterKey, err := encryption.ParseMasterKey(rawKey)
	if err != nil {
		t.Fatalf("parse master key: %v", err)
	}

	const restoreDatabase = "pgvault_restore_e2e"
	restoreURL, err := replaceDatabase(databaseURL, restoreDatabase)
	if err != nil {
		t.Fatalf("build restore URL: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	store, err := metadata.Open(filepath.Join(t.TempDir(), "pgvault.db"))
	if err != nil {
		t.Fatalf("open metadata: %v", err)
	}
	defer store.Close()

	database, err := store.AddDatabase("e2e", databaseURL)
	if err != nil {
		t.Fatalf("add database: %v", err)
	}

	localStore := storage.NewLocalStorage(t.TempDir())
	manager := backup.NewManager(postgres.NewDumper(), store)

	result, err := manager.Backup(ctx, backup.Request{
		DatabaseID:     database.ID,
		DatabaseName:   database.Name,
		DatabaseURL:    databaseURL,
		Storage:        localStore,
		StorageBackend: "local",
		Encryption:     true,
		Keyring:        encryption.Keyring{1: masterKey},
		KeyVersion:     1,
		Trigger:        "manual",
	})
	if err != nil {
		t.Fatalf("backup: %v", err)
	}
	if result.Status != backup.StatusSuccess {
		t.Fatalf("unexpected status: %s (%s)", result.Status, result.Error)
	}
	if result.SizeBytes == 0 || result.Checksum == "" {
		t.Fatalf("missing size or checksum: %+v", result)
	}

	// The metadata database must agree with the result.
	record, err := store.GetBackup(result.ID)
	if err != nil {
		t.Fatalf("load backup record: %v", err)
	}
	if record.Status != string(backup.StatusSuccess) ||
		record.Checksum != result.Checksum ||
		record.SizeBytes != result.SizeBytes {
		t.Fatalf("metadata mismatch: %+v", record)
	}

	// The recorded checksum must match the stored bytes.
	stored, err := localStore.Get(ctx, result.Path)
	if err != nil {
		t.Fatalf("get object: %v", err)
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, stored); err != nil {
		t.Fatalf("hash object: %v", err)
	}
	stored.Close()
	if got := hex.EncodeToString(hasher.Sum(nil)); got != result.Checksum {
		t.Fatalf("checksum mismatch: storage %s, metadata %s", got, result.Checksum)
	}

	// Decrypt and decompress the object back into a custom-format
	// archive that pg_restore understands.
	stored, err = localStore.Get(ctx, result.Path)
	if err != nil {
		t.Fatalf("get object: %v", err)
	}
	reader, header, err := archive.NewReader(stored, encryption.Keyring{1: masterKey})
	if err != nil {
		t.Fatalf("open archive: %v", err)
	}
	defer reader.Close()

	if header.Encryption == nil {
		t.Fatal("expected an encrypted object")
	}

	archivePath := filepath.Join(t.TempDir(), "restore.dump")
	out, err := os.Create(archivePath)
	if err != nil {
		t.Fatalf("create archive file: %v", err)
	}
	if _, err := io.Copy(out, reader); err != nil {
		out.Close()
		t.Fatalf("write archive file: %v", err)
	}
	if err := out.Close(); err != nil {
		t.Fatalf("close archive file: %v", err)
	}

	listOutput, err := exec.CommandContext(ctx, "pg_restore", "--list", archivePath).Output()
	if err != nil {
		t.Fatalf("pg_restore --list: %v", err)
	}
	if !bytes.Contains(listOutput, []byte("TABLE DATA")) {
		t.Fatalf("archive listing looks wrong:\n%s", listOutput)
	}

	// Restore into a scratch database and compare row counts.
	runSQL(t, ctx, adminURL, fmt.Sprintf("DROP DATABASE IF EXISTS %s", restoreDatabase))
	runSQL(t, ctx, adminURL, fmt.Sprintf("CREATE DATABASE %s", restoreDatabase))

	restoreCmd := exec.CommandContext(
		ctx,
		"pg_restore",
		"--dbname", restoreURL,
		archivePath,
	)
	if output, err := restoreCmd.CombinedOutput(); err != nil {
		t.Fatalf("pg_restore: %v\n%s", err, output)
	}

	sourceCount := queryCount(t, ctx, databaseURL)
	restoredCount := queryCount(t, ctx, restoreURL)
	if sourceCount != restoredCount {
		t.Fatalf(
			"row count mismatch: source %d, restored %d",
			sourceCount,
			restoredCount,
		)
	}

	runSQL(t, ctx, adminURL, fmt.Sprintf("DROP DATABASE %s", restoreDatabase))
}

func replaceDatabase(databaseURL, name string) (string, error) {
	parsed, err := url.Parse(databaseURL)
	if err != nil {
		return "", err
	}
	parsed.Path = "/" + name
	return parsed.String(), nil
}

func runSQL(t *testing.T, ctx context.Context, databaseURL, statement string) {
	t.Helper()
	cmd := exec.CommandContext(
		ctx,
		"psql",
		"--dbname", databaseURL,
		"--no-psqlrc",
		"--quiet",
		"--command", statement,
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("psql %q: %v\n%s", statement, err, output)
	}
}

func queryCount(t *testing.T, ctx context.Context, databaseURL string) int {
	t.Helper()
	cmd := exec.CommandContext(
		ctx,
		"psql",
		"--dbname", databaseURL,
		"--no-psqlrc",
		"--tuples-only",
		"--no-align",
		"--command", "SELECT count(*) FROM customers",
	)
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("psql count: %v", err)
	}
	count, err := strconv.Atoi(strings.TrimSpace(string(output)))
	if err != nil {
		t.Fatalf("parse count %q: %v", output, err)
	}
	return count
}
