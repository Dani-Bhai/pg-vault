package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/Dani-Bhai/pg-vault/internal/encryption"
)

// Config is the process-wide configuration, loaded from the
// environment. Eventually this may grow into a config file; the
// metadata database remains authoritative for databases, policies and
// backup history.
type Config struct {
	Dir       string
	DBPath    string
	BackupDir string

	DefaultStorage string

	KeyVersion    int
	EncryptionKey []byte

	S3 S3
}

// S3 holds the settings for the S3-compatible storage backend. The
// same settings work for AWS S3, MinIO, Cloudflare R2, Backblaze B2
// and DigitalOcean Spaces; only the endpoint differs.
type S3 struct {
	Bucket    string
	Region    string
	Endpoint  string
	Prefix    string
	PathStyle bool
}

func Load() (*Config, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("resolve home directory: %w", err)
	}

	dir := envOr("PGVAULT_DIR", filepath.Join(home, ".pgvault"))

	cfg := &Config{
		Dir:            dir,
		DBPath:         filepath.Join(dir, "pgvault.db"),
		BackupDir:      filepath.Join(dir, "backups"),
		DefaultStorage: envOr("PGVAULT_STORAGE", "local"),
		KeyVersion:     1,
		S3: S3{
			Bucket:    os.Getenv("PGVAULT_S3_BUCKET"),
			Region:    envOr("PGVAULT_S3_REGION", "us-east-1"),
			Endpoint:  os.Getenv("PGVAULT_S3_ENDPOINT"),
			Prefix:    os.Getenv("PGVAULT_S3_PREFIX"),
			PathStyle: os.Getenv("PGVAULT_S3_ENDPOINT") != "",
		},
	}

	if raw, ok := os.LookupEnv("PGVAULT_S3_PATH_STYLE"); ok && raw != "" {
		value, err := strconv.ParseBool(raw)
		if err != nil {
			return nil, fmt.Errorf("PGVAULT_S3_PATH_STYLE: %w", err)
		}
		cfg.S3.PathStyle = value
	}

	switch cfg.DefaultStorage {
	case "local", "s3":
	default:
		return nil, fmt.Errorf(
			"PGVAULT_STORAGE must be \"local\" or \"s3\", got %q",
			cfg.DefaultStorage,
		)
	}

	if cfg.DefaultStorage == "s3" && cfg.S3.Bucket == "" {
		return nil, fmt.Errorf("PGVAULT_STORAGE=s3 requires PGVAULT_S3_BUCKET")
	}

	if raw := os.Getenv("PGVAULT_MASTER_KEY"); raw != "" {
		key, err := encryption.ParseMasterKey(raw)
		if err != nil {
			return nil, fmt.Errorf("PGVAULT_MASTER_KEY: %w", err)
		}
		cfg.EncryptionKey = key
	}

	return cfg, nil
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
