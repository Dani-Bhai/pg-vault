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

// Tunnel is the SSH tunnel profile of a database: backups are taken
// through an SSH bastion at Host:Port, forwarding to the address the
// connection string points at.
type Tunnel struct {
	DatabaseID string
	Host       string // bastion host
	Port       int    // bastion port, default 22
	User       string // bastion user, empty means the current OS user

	AuthMethod    string // auto (default), password, key or agent
	Password      string // may be empty; PGVAULT_SSH_PASSWORD overrides
	KeyPath       string // private key for key authentication
	KeyPassphrase string // may be empty; PGVAULT_SSH_KEY_PASSPHRASE overrides

	KnownHosts string // known_hosts file, default ~/.ssh/known_hosts
	Insecure   bool   // skip ssh host key verification

	CreatedAt time.Time
}

// Docker is the container profile of a database: backups run pg_dump
// inside Container instead of on the host. When the database also has
// an SSH tunnel profile the docker host is the bastion; otherwise it
// is this machine. Host and Port describe where PostgreSQL listens
// inside the container.
type Docker struct {
	DatabaseID string
	Container  string
	Host       string // address inside the container
	Port       int    // port inside the container

	CreatedAt time.Time
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
