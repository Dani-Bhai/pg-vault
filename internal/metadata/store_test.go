package metadata

import (
	"database/sql"
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

	tunnel, err := store.GetTunnel(database.ID)
	if err != nil || tunnel != nil {
		t.Fatalf("get tunnel: %v (%v)", err, tunnel)
	}

	if err := store.UpsertTunnel(Tunnel{
		DatabaseID: database.ID,
		Host:       "bastion.example.com",
		Port:       2222,
		User:       "alice",
		AuthMethod: "key",
		KeyPath:    "/home/alice/.ssh/id_ed25519",
		Insecure:   true,
		CreatedAt:  started,
	}); err != nil {
		t.Fatalf("upsert tunnel: %v", err)
	}

	tunnel, err = store.GetTunnel(database.ID)
	if err != nil || tunnel == nil {
		t.Fatalf("get tunnel: %v (%v)", err, tunnel)
	}
	if tunnel.Host != "bastion.example.com" ||
		tunnel.Port != 2222 ||
		tunnel.User != "alice" ||
		tunnel.AuthMethod != "key" ||
		tunnel.KeyPath != "/home/alice/.ssh/id_ed25519" ||
		!tunnel.Insecure {
		t.Fatalf("unexpected tunnel: %+v", tunnel)
	}

	// Upserting replaces the profile.
	tunnel.AuthMethod = "password"
	tunnel.Password = "s3cret"
	tunnel.Insecure = false
	tunnel.Port = 22
	if err := store.UpsertTunnel(*tunnel); err != nil {
		t.Fatalf("replace tunnel: %v", err)
	}

	tunnel, err = store.GetTunnel(database.ID)
	if err != nil {
		t.Fatalf("get tunnel: %v", err)
	}
	if tunnel.AuthMethod != "password" ||
		tunnel.Password != "s3cret" ||
		tunnel.Insecure ||
		tunnel.Port != 22 {
		t.Fatalf("tunnel update lost: %+v", tunnel)
	}

	// Invalid profiles are rejected by the schema.
	if err := store.UpsertTunnel(Tunnel{
		DatabaseID: database.ID,
		Host:       "bastion.example.com",
		Port:       0,
	}); err == nil {
		t.Fatal("expected invalid port to be rejected")
	}

	if err := store.DeleteTunnel(database.ID); err != nil {
		t.Fatalf("delete tunnel: %v", err)
	}
	if tunnel, err = store.GetTunnel(database.ID); err != nil || tunnel != nil {
		t.Fatalf("get tunnel after delete: %v (%v)", err, tunnel)
	}
	if err := store.DeleteTunnel(database.ID); err != nil {
		t.Fatalf("delete missing tunnel: %v", err)
	}

	container, err := store.GetDocker(database.ID)
	if err != nil || container != nil {
		t.Fatalf("get docker: %v (%v)", err, container)
	}

	if err := store.UpsertDocker(Docker{
		DatabaseID: database.ID,
		Container:  "postgres-1",
		Port:       4532,
		CreatedAt:  started,
	}); err != nil {
		t.Fatalf("upsert docker: %v", err)
	}

	container, err = store.GetDocker(database.ID)
	if err != nil || container == nil {
		t.Fatalf("get docker: %v (%v)", err, container)
	}
	if container.Container != "postgres-1" ||
		container.Host != "127.0.0.1" ||
		container.Port != 4532 {
		t.Fatalf("unexpected docker profile: %+v", container)
	}

	// Upserting replaces the profile.
	container.Container = "postgres-2"
	container.Port = 5432
	if err := store.UpsertDocker(*container); err != nil {
		t.Fatalf("replace docker: %v", err)
	}

	container, err = store.GetDocker(database.ID)
	if err != nil {
		t.Fatalf("get docker: %v", err)
	}
	if container.Container != "postgres-2" || container.Port != 5432 {
		t.Fatalf("docker update lost: %+v", container)
	}

	// Invalid profiles are rejected.
	if err := store.UpsertDocker(Docker{
		DatabaseID: database.ID,
		Container:  "postgres-2",
		Port:       0,
	}); err == nil {
		t.Fatal("expected invalid port to be rejected")
	}
	if err := store.UpsertDocker(Docker{
		DatabaseID: database.ID,
		Container:  "  ",
		Port:       5432,
	}); err == nil {
		t.Fatal("expected an empty container to be rejected")
	}

	if err := store.DeleteDocker(database.ID); err != nil {
		t.Fatalf("delete docker: %v", err)
	}
	if container, err = store.GetDocker(database.ID); err != nil || container != nil {
		t.Fatalf("get docker after delete: %v (%v)", err, container)
	}
	if err := store.DeleteDocker(database.ID); err != nil {
		t.Fatalf("delete missing docker: %v", err)
	}
}

// TestMigrateFromVersion2 upgrades a version 2 metadata database
// (before docker container profiles existed).
func TestMigrateFromVersion2(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pgvault.db")

	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open old database: %v", err)
	}
	oldSchema := `
CREATE TABLE IF NOT EXISTS databases (
	id                TEXT PRIMARY KEY,
	name              TEXT NOT NULL UNIQUE,
	connection_string TEXT NOT NULL,
	enabled           INTEGER NOT NULL DEFAULT 1,
	created_at        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ssh_tunnels (
	database_id    TEXT PRIMARY KEY REFERENCES databases (id) ON DELETE CASCADE,
	host           TEXT NOT NULL,
	port           INTEGER NOT NULL CHECK (port > 0 AND port < 65536),
	user_name      TEXT NOT NULL DEFAULT '',
	auth_method    TEXT NOT NULL DEFAULT 'auto'
		CHECK (auth_method IN ('auto', 'password', 'key', 'agent')),
	password       TEXT NOT NULL DEFAULT '',
	key_path       TEXT NOT NULL DEFAULT '',
	key_passphrase TEXT NOT NULL DEFAULT '',
	known_hosts    TEXT NOT NULL DEFAULT '',
	insecure       INTEGER NOT NULL DEFAULT 0,
	created_at     TEXT NOT NULL
);
`
	if _, err := database.Exec(oldSchema); err != nil {
		t.Fatalf("create old schema: %v", err)
	}
	if _, err := database.Exec(
		`INSERT INTO databases (id, name, connection_string, enabled, created_at)
		 VALUES ('db-1', 'production', 'postgresql://localhost/production', 1, '2025-01-01T00:00:00Z')`,
	); err != nil {
		t.Fatalf("seed old database: %v", err)
	}
	if _, err := database.Exec("PRAGMA user_version = 2"); err != nil {
		t.Fatalf("set old version: %v", err)
	}
	database.Close()

	store, err := Open(path)
	if err != nil {
		t.Fatalf("open for migration: %v", err)
	}
	defer store.Close()

	var version int
	if err := store.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != 3 {
		t.Fatalf("schema version: got %d, want 3", version)
	}

	if err := store.UpsertDocker(Docker{
		DatabaseID: "db-1",
		Container:  "qa-postgres",
		Port:       5432,
		CreatedAt:  time.Now().UTC(),
	}); err != nil {
		t.Fatalf("upsert docker after migration: %v", err)
	}

	container, err := store.GetDocker("db-1")
	if err != nil || container == nil || container.Container != "qa-postgres" {
		t.Fatalf("get docker after migration: %v (%v)", err, container)
	}
}

// TestMigrateFromVersion1 upgrades a version 1 metadata database
// (before tunnel profiles existed) and verifies the result is usable.
func TestMigrateFromVersion1(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pgvault.db")

	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open old database: %v", err)
	}
	oldSchema := `
CREATE TABLE IF NOT EXISTS databases (
	id                TEXT PRIMARY KEY,
	name              TEXT NOT NULL UNIQUE,
	connection_string TEXT NOT NULL,
	enabled           INTEGER NOT NULL DEFAULT 1,
	created_at        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS backup_policies (
	database_id     TEXT PRIMARY KEY REFERENCES databases (id) ON DELETE CASCADE,
	schedule        TEXT NOT NULL DEFAULT '',
	retention_days  INTEGER NOT NULL DEFAULT 0,
	storage_backend TEXT NOT NULL DEFAULT 'local',
	encryption      INTEGER NOT NULL DEFAULT 1,
	enabled         INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS backups (
	id              TEXT PRIMARY KEY,
	database_id     TEXT NOT NULL REFERENCES databases (id) ON DELETE CASCADE,
	database_name   TEXT NOT NULL,
	status          TEXT NOT NULL,
	reason          TEXT NOT NULL DEFAULT '',
	error           TEXT NOT NULL DEFAULT '',
	path            TEXT NOT NULL DEFAULT '',
	size_bytes      INTEGER NOT NULL DEFAULT 0,
	checksum        TEXT NOT NULL DEFAULT '',
	format_version  INTEGER NOT NULL DEFAULT 0,
	compression     TEXT NOT NULL DEFAULT '',
	encryption      TEXT NOT NULL DEFAULT '',
	key_version     INTEGER NOT NULL DEFAULT 0,
	storage_backend TEXT NOT NULL DEFAULT '',
	trigger         TEXT NOT NULL DEFAULT '',
	started_at      TEXT NOT NULL,
	completed_at    TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS backups_database_name_started_at
	ON backups (database_name, started_at DESC);
`
	if _, err := database.Exec(oldSchema); err != nil {
		t.Fatalf("create old schema: %v", err)
	}
	if _, err := database.Exec(
		`INSERT INTO databases (id, name, connection_string, enabled, created_at)
		 VALUES ('db-1', 'production', 'postgresql://localhost/production', 1, '2025-01-01T00:00:00Z')`,
	); err != nil {
		t.Fatalf("seed old database: %v", err)
	}
	if _, err := database.Exec("PRAGMA user_version = 1"); err != nil {
		t.Fatalf("set old version: %v", err)
	}
	database.Close()

	store, err := Open(path)
	if err != nil {
		t.Fatalf("open for migration: %v", err)
	}
	defer store.Close()

	var version int
	if err := store.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != 3 {
		t.Fatalf("schema version: got %d, want 3", version)
	}

	if err := store.UpsertTunnel(Tunnel{
		DatabaseID: "db-1",
		Host:       "bastion.example.com",
		Port:       22,
		AuthMethod: "agent",
		CreatedAt:  time.Now().UTC(),
	}); err != nil {
		t.Fatalf("upsert tunnel after migration: %v", err)
	}

	tunnel, err := store.GetTunnel("db-1")
	if err != nil || tunnel == nil || tunnel.Host != "bastion.example.com" {
		t.Fatalf("get tunnel after migration: %v (%v)", err, tunnel)
	}

	if err := store.UpsertDocker(Docker{
		DatabaseID: "db-1",
		Container:  "qa-postgres",
		Port:       5432,
		CreatedAt:  time.Now().UTC(),
	}); err != nil {
		t.Fatalf("upsert docker after migration: %v", err)
	}

	container, err := store.GetDocker("db-1")
	if err != nil || container == nil || container.Container != "qa-postgres" {
		t.Fatalf("get docker after migration: %v (%v)", err, container)
	}
}

// TestDeleteDatabaseCascades verifies that removing a database also
// removes its policy, tunnel profile and backup history.
func TestDeleteDatabaseCascades(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "pgvault.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close()

	database, err := store.AddDatabase("doomed", "postgresql://localhost/doomed")
	if err != nil {
		t.Fatalf("add database: %v", err)
	}

	if err := store.UpsertPolicy(Policy{
		DatabaseID:     database.ID,
		Schedule:       "0 * * * *",
		StorageBackend: "local",
		Encryption:     false,
		Enabled:        true,
	}); err != nil {
		t.Fatalf("upsert policy: %v", err)
	}

	if err := store.UpsertTunnel(Tunnel{
		DatabaseID: database.ID,
		Host:       "bastion.example.com",
		Port:       22,
		AuthMethod: "agent",
		CreatedAt:  time.Now().UTC(),
	}); err != nil {
		t.Fatalf("upsert tunnel: %v", err)
	}

	if err := store.UpsertDocker(Docker{
		DatabaseID: database.ID,
		Container:  "doomed-postgres",
		Port:       5432,
		CreatedAt:  time.Now().UTC(),
	}); err != nil {
		t.Fatalf("upsert docker: %v", err)
	}

	if err := store.CreateBackup(BackupRecord{
		ID:           "doomed-1",
		DatabaseID:   database.ID,
		DatabaseName: database.Name,
		Status:       "success",
		Path:         "doomed/doomed-1.pgv",
		StartedAt:    time.Now().UTC(),
	}); err != nil {
		t.Fatalf("create backup: %v", err)
	}

	if err := store.DeleteDatabase(database.ID); err != nil {
		t.Fatalf("delete database: %v", err)
	}

	if _, err := store.GetDatabase("doomed"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound after delete, got %v", err)
	}
	policy, err := store.GetPolicy(database.ID)
	if err != nil || policy != nil {
		t.Fatalf("policy survived the delete: %v (%v)", err, policy)
	}
	tunnel, err := store.GetTunnel(database.ID)
	if err != nil || tunnel != nil {
		t.Fatalf("tunnel survived the delete: %v (%v)", err, tunnel)
	}
	container, err := store.GetDocker(database.ID)
	if err != nil || container != nil {
		t.Fatalf("docker profile survived the delete: %v (%v)", err, container)
	}
	records, err := store.ListBackups("doomed")
	if err != nil || len(records) != 0 {
		t.Fatalf("backups survived the delete: %v (%d)", err, len(records))
	}

	if err := store.DeleteDatabase("missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}
