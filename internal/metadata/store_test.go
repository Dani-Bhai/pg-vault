package metadata

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestStoreLifecycle(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "pgvault.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close()

	database, err := store.AddDatabase("production", "postgresql://localhost/production")
	if err != nil {
		t.Fatalf("add database: %v", err)
	}
	if database.ID == "" {
		t.Fatal("expected a generated ID")
	}

	if _, err := store.AddDatabase("production", "postgresql://other"); err == nil {
		t.Fatal("expected duplicate name to be rejected")
	}

	loaded, err := store.GetDatabase("production")
	if err != nil {
		t.Fatalf("get database: %v", err)
	}
	if loaded.Name != database.Name || !loaded.Enabled {
		t.Fatalf("unexpected database: %+v", loaded)
	}

	if _, err := store.GetDatabase("missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}

	databases, err := store.ListDatabases()
	if err != nil || len(databases) != 1 {
		t.Fatalf("list databases: %v (%d)", err, len(databases))
	}

	policy, err := store.GetPolicy(database.ID)
	if err != nil {
		t.Fatal(err)
	}
	if policy != nil {
		t.Fatal("expected no policy yet")
	}

	err = store.UpsertPolicy(Policy{
		DatabaseID:     database.ID,
		Schedule:       "0 */6 * * *",
		StorageBackend: "s3",
		Encryption:     true,
		Enabled:        true,
	})
	if err != nil {
		t.Fatalf("upsert policy: %v", err)
	}

	policy, err = store.GetPolicy(database.ID)
	if err != nil || policy == nil {
		t.Fatalf("get policy: %v (%v)", err, policy)
	}
	if policy.Schedule != "0 */6 * * *" || policy.StorageBackend != "s3" {
		t.Fatalf("unexpected policy: %+v", policy)
	}

	policy.Schedule = "0 2 * * *"
	policy.Encryption = false
	if err := store.UpsertPolicy(*policy); err != nil {
		t.Fatalf("update policy: %v", err)
	}

	policy, _ = store.GetPolicy(database.ID)
	if policy.Schedule != "0 2 * * *" || policy.Encryption {
		t.Fatalf("policy update lost: %+v", policy)
	}

	schedules, err := store.ListSchedules()
	if err != nil || len(schedules) != 1 {
		t.Fatalf("list schedules: %v (%d)", err, len(schedules))
	}
	if schedules[0].DatabaseName != "production" ||
		schedules[0].Schedule != "0 2 * * *" {
		t.Fatalf("unexpected schedule: %+v", schedules[0])
	}

	started := time.Now().UTC().Truncate(time.Second)
	record := BackupRecord{
		ID:             "backup-1",
		DatabaseID:     database.ID,
		DatabaseName:   database.Name,
		Status:         "running",
		Path:           "production/backup-1.pgv",
		FormatVersion:  1,
		Compression:    "zstd",
		Encryption:     "aes-256-gcm",
		KeyVersion:     1,
		StorageBackend: "s3",
		Trigger:        "manual",
		StartedAt:      started,
	}
	if err := store.CreateBackup(record); err != nil {
		t.Fatalf("create backup: %v", err)
	}

	completed := started.Add(90 * time.Second)
	err = store.FinishBackup(
		record.ID,
		"success",
		"",
		completed,
		1024,
		"deadbeef",
	)
	if err != nil {
		t.Fatalf("finish backup: %v", err)
	}

	loadedRecord, err := store.GetBackup(record.ID)
	if err != nil {
		t.Fatalf("get backup: %v", err)
	}
	if loadedRecord.Status != "success" ||
		loadedRecord.SizeBytes != 1024 ||
		loadedRecord.Checksum != "deadbeef" {
		t.Fatalf("unexpected backup: %+v", loadedRecord)
	}
	if !loadedRecord.StartedAt.Equal(started) ||
		!loadedRecord.CompletedAt.Equal(completed) {
		t.Fatalf("timestamps lost: %+v", loadedRecord)
	}

	records, err := store.ListBackups("production")
	if err != nil || len(records) != 1 {
		t.Fatalf("list backups: %v (%d)", err, len(records))
	}
	records, err = store.ListBackups("other")
	if err != nil || len(records) != 0 {
		t.Fatalf("list other backups: %v (%d)", err, len(records))
	}

	if _, err := store.GetBackup("missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}
