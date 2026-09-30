package metadata

import "time"

// Database is a registered PostgreSQL database.
type Database struct {
	ID               string
	Name             string
	ConnectionString string
	Enabled          bool
	CreatedAt        time.Time
}

// Policy describes how a database is backed up.
type Policy struct {
	DatabaseID     string
	Schedule       string
	RetentionDays  int
	StorageBackend string
	Encryption     bool
	Enabled        bool
}

// BackupRecord is one row of backup history. It is authoritative for
// metadata; storage backends only hold the objects.
type BackupRecord struct {
	ID             string
	DatabaseID     string
	DatabaseName   string
	Status         string
	Reason         string
	Error          string
	Path           string
	SizeBytes      int64
	Checksum       string
	FormatVersion  int
	Compression    string
	Encryption     string
	KeyVersion     int
	StorageBackend string
	Trigger        string
	StartedAt      time.Time
	CompletedAt    time.Time
}

// Schedule is a database with an enabled backup schedule, used by the
// daemon to register cron jobs.
type Schedule struct {
	DatabaseID   string
	DatabaseName string
	Schedule     string
}
