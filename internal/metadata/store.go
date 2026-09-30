// Package metadata is the SQLite-backed pgvault registry: registered
// databases, backup policies and backup history. It lives at
// ~/.pgvault/pgvault.db by default and is authoritative for all backup
// metadata; storage backends only hold the backup objects.
package metadata

import (
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

// ErrNotFound is returned when a database or backup does not exist.
var ErrNotFound = errors.New("not found")

const schema = `
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

// Store is a handle on the metadata database.
type Store struct {
	db *sql.DB
}

// Open opens (creating if necessary) the metadata database at path.
func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create data directory: %w", err)
	}

	dsn := (&url.URL{
		Scheme: "file",
		Path:   path,
		RawQuery: "_pragma=busy_timeout(5000)" +
			"&_pragma=journal_mode(WAL)" +
			"&_pragma=foreign_keys(1)",
	}).String()

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open metadata database: %w", err)
	}
	db.SetMaxOpenConns(1)

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("open metadata database: %w", err)
	}

	store := &Store{db: db}
	if err := store.migrate(); err != nil {
		db.Close()
		return nil, err
	}

	_ = os.Chmod(path, 0o600)

	return store, nil
}

// Close closes the metadata database.
func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) migrate() error {
	var version int
	if err := s.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}

	switch {
	case version == 0:
		if _, err := s.db.Exec(schema); err != nil {
			return fmt.Errorf("create schema: %w", err)
		}
		if _, err := s.db.Exec("PRAGMA user_version = 1"); err != nil {
			return fmt.Errorf("set schema version: %w", err)
		}
	case version > 1:
		return fmt.Errorf(
			"metadata schema version %d is newer than this pgvault build supports",
			version,
		)
	}
	return nil
}

// AddDatabase registers a database.
func (s *Store) AddDatabase(name, connectionString string) (*Database, error) {
	database := &Database{
		ID:               uuid.NewString(),
		Name:             name,
		ConnectionString: connectionString,
		Enabled:          true,
		CreatedAt:        time.Now().UTC(),
	}

	_, err := s.db.Exec(
		`INSERT INTO databases (id, name, connection_string, enabled, created_at)
		 VALUES (?, ?, ?, 1, ?)`,
		database.ID,
		database.Name,
		database.ConnectionString,
		formatTime(database.CreatedAt),
	)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return nil, fmt.Errorf("database %q is already registered", name)
		}
		return nil, fmt.Errorf("register database: %w", err)
	}

	return database, nil
}

// GetDatabase returns the database registered under name.
func (s *Store) GetDatabase(name string) (*Database, error) {
	row := s.db.QueryRow(
		`SELECT id, name, connection_string, enabled, created_at
		 FROM databases WHERE name = ?`,
		name,
	)

	database, err := scanDatabase(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("database %q: %w", name, ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("load database %q: %w", name, err)
	}
	return database, nil
}

// ListDatabases returns all registered databases ordered by name.
func (s *Store) ListDatabases() ([]Database, error) {
	rows, err := s.db.Query(
		`SELECT id, name, connection_string, enabled, created_at
		 FROM databases ORDER BY name`,
	)
	if err != nil {
		return nil, fmt.Errorf("list databases: %w", err)
	}
	defer rows.Close()

	var databases []Database
	for rows.Next() {
		database, err := scanDatabase(rows)
		if err != nil {
			return nil, fmt.Errorf("list databases: %w", err)
		}
		databases = append(databases, *database)
	}
	return databases, rows.Err()
}

// UpsertPolicy creates or replaces the backup policy of a database.
func (s *Store) UpsertPolicy(policy Policy) error {
	_, err := s.db.Exec(
		`INSERT INTO backup_policies
			(database_id, schedule, retention_days, storage_backend, encryption, enabled)
		 VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT (database_id) DO UPDATE SET
			schedule = excluded.schedule,
			retention_days = excluded.retention_days,
			storage_backend = excluded.storage_backend,
			encryption = excluded.encryption,
			enabled = excluded.enabled`,
		policy.DatabaseID,
		policy.Schedule,
		policy.RetentionDays,
		policy.StorageBackend,
		policy.Encryption,
		policy.Enabled,
	)
	if err != nil {
		return fmt.Errorf("save backup policy: %w", err)
	}
	return nil
}

// GetPolicy returns the backup policy of a database, or (nil, nil) if
// the database has none.
func (s *Store) GetPolicy(databaseID string) (*Policy, error) {
	row := s.db.QueryRow(
		`SELECT database_id, schedule, retention_days, storage_backend, encryption, enabled
		 FROM backup_policies WHERE database_id = ?`,
		databaseID,
	)

	var policy Policy
	err := row.Scan(
		&policy.DatabaseID,
		&policy.Schedule,
		&policy.RetentionDays,
		&policy.StorageBackend,
		&policy.Encryption,
		&policy.Enabled,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("load backup policy: %w", err)
	}
	return &policy, nil
}

// CreateBackup inserts a new backup record.
func (s *Store) CreateBackup(record BackupRecord) error {
	_, err := s.db.Exec(
		`INSERT INTO backups
			(id, database_id, database_name, status, reason, error, path,
			 size_bytes, checksum, format_version, compression, encryption,
			 key_version, storage_backend, trigger, started_at, completed_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		record.ID,
		record.DatabaseID,
		record.DatabaseName,
		record.Status,
		record.Reason,
		record.Error,
		record.Path,
		record.SizeBytes,
		record.Checksum,
		record.FormatVersion,
		record.Compression,
		record.Encryption,
		record.KeyVersion,
		record.StorageBackend,
		record.Trigger,
		formatTime(record.StartedAt),
		formatTime(record.CompletedAt),
	)
	if err != nil {
		return fmt.Errorf("create backup record: %w", err)
	}
	return nil
}

// FinishBackup records the terminal state of a backup.
func (s *Store) FinishBackup(
	id string,
	status string,
	errorMessage string,
	completedAt time.Time,
	sizeBytes int64,
	checksum string,
) error {
	result, err := s.db.Exec(
		`UPDATE backups
		 SET status = ?, error = ?, completed_at = ?, size_bytes = ?, checksum = ?
		 WHERE id = ?`,
		status,
		errorMessage,
		formatTime(completedAt),
		sizeBytes,
		checksum,
		id,
	)
	if err != nil {
		return fmt.Errorf("finish backup record: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("finish backup record: %w", err)
	}
	if affected == 0 {
		return fmt.Errorf("backup %s: %w", id, ErrNotFound)
	}
	return nil
}

// GetBackup returns one backup record by ID.
func (s *Store) GetBackup(id string) (*BackupRecord, error) {
	row := s.db.QueryRow(
		`SELECT id, database_id, database_name, status, reason, error, path,
			size_bytes, checksum, format_version, compression, encryption,
			key_version, storage_backend, trigger, started_at, completed_at
		 FROM backups WHERE id = ?`,
		id,
	)

	record, err := scanBackup(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("backup %s: %w", id, ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("load backup %s: %w", id, err)
	}
	return record, nil
}

// ListBackups returns backup history, newest first, optionally
// filtered by database name.
func (s *Store) ListBackups(databaseName string) ([]BackupRecord, error) {
	query := `SELECT id, database_id, database_name, status, reason, error, path,
			size_bytes, checksum, format_version, compression, encryption,
			key_version, storage_backend, trigger, started_at, completed_at
		 FROM backups`
	var args []any
	if databaseName != "" {
		query += " WHERE database_name = ?"
		args = append(args, databaseName)
	}
	query += " ORDER BY started_at DESC"

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("list backups: %w", err)
	}
	defer rows.Close()

	var records []BackupRecord
	for rows.Next() {
		record, err := scanBackup(rows)
		if err != nil {
			return nil, fmt.Errorf("list backups: %w", err)
		}
		records = append(records, *record)
	}
	return records, rows.Err()
}

// ListSchedules returns enabled databases with a non-empty schedule.
func (s *Store) ListSchedules() ([]Schedule, error) {
	rows, err := s.db.Query(
		`SELECT d.id, d.name, p.schedule
		 FROM backup_policies p
		 JOIN databases d ON d.id = p.database_id
		 WHERE p.enabled = 1 AND p.schedule <> '' AND d.enabled = 1
		 ORDER BY d.name`,
	)
	if err != nil {
		return nil, fmt.Errorf("list schedules: %w", err)
	}
	defer rows.Close()

	var schedules []Schedule
	for rows.Next() {
		var schedule Schedule
		if err := rows.Scan(
			&schedule.DatabaseID,
			&schedule.DatabaseName,
			&schedule.Schedule,
		); err != nil {
			return nil, fmt.Errorf("list schedules: %w", err)
		}
		schedules = append(schedules, schedule)
	}
	return schedules, rows.Err()
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanDatabase(row rowScanner) (*Database, error) {
	var (
		database  Database
		createdAt string
		enabled   bool
	)
	if err := row.Scan(
		&database.ID,
		&database.Name,
		&database.ConnectionString,
		&enabled,
		&createdAt,
	); err != nil {
		return nil, err
	}
	database.Enabled = enabled
	database.CreatedAt = parseTime(createdAt)
	return &database, nil
}

func scanBackup(row rowScanner) (*BackupRecord, error) {
	var (
		record      BackupRecord
		startedAt   string
		completedAt string
	)
	if err := row.Scan(
		&record.ID,
		&record.DatabaseID,
		&record.DatabaseName,
		&record.Status,
		&record.Reason,
		&record.Error,
		&record.Path,
		&record.SizeBytes,
		&record.Checksum,
		&record.FormatVersion,
		&record.Compression,
		&record.Encryption,
		&record.KeyVersion,
		&record.StorageBackend,
		&record.Trigger,
		&startedAt,
		&completedAt,
	); err != nil {
		return nil, err
	}
	record.StartedAt = parseTime(startedAt)
	record.CompletedAt = parseTime(completedAt)
	return &record, nil
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func parseTime(raw string) time.Time {
	if raw == "" {
		return time.Time{}
	}
	parsed, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return time.Time{}
	}
	return parsed
}
