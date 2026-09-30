package backup

import "time"

type Status string

const (
	StatusRunning Status = "running"
	StatusSuccess Status = "success"
	StatusFailed  Status = "failed"
	StatusSkipped Status = "skipped"
)

type Backup struct {
	ID           string
	DatabaseName string
	StartedAt    time.Time
	CompletedAt  time.Time

	Path      string
	SizeBytes int64

	Status Status
	Error  string
	Reason string

	Checksum       string
	FormatVersion  int
	Compression    string
	Encryption     string
	KeyVersion     int
	StorageBackend string
	Trigger        string
}
