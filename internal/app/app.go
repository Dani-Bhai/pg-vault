// Package app wires configuration, metadata, storage and the backup
// manager together. Both the CLI and the scheduler go through it, so
// manual and scheduled backups follow exactly the same path.
package app

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/Dani-Bhai/pg-vault/internal/backup"
	"github.com/Dani-Bhai/pg-vault/internal/config"
	"github.com/Dani-Bhai/pg-vault/internal/docker"
	"github.com/Dani-Bhai/pg-vault/internal/encryption"
	"github.com/Dani-Bhai/pg-vault/internal/metadata"
	"github.com/Dani-Bhai/pg-vault/internal/postgres"
	"github.com/Dani-Bhai/pg-vault/internal/sshtunnel"
	"github.com/Dani-Bhai/pg-vault/internal/storage"
)

// App is a fully wired pgvault instance.
type App struct {
	Config  *config.Config
	Store   *metadata.Store
	Manager *backup.Manager
}

// Open loads configuration, opens the metadata database and builds a
// backup manager.
func Open() (*App, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, err
	}

	store, err := metadata.Open(cfg.DBPath)
	if err != nil {
		return nil, err
	}

	return &App{
		Config:  cfg,
		Store:   store,
		Manager: backup.NewManager(postgres.NewLocalDumper(), store),
	}, nil
}

// Close releases resources held by the app.
func (a *App) Close() error {
	return a.Store.Close()
}

// RunBackup backs up a registered database using its policy.
func (a *App) RunBackup(
	ctx context.Context,
	databaseName string,
	trigger string,
) (*backup.Backup, error) {
	database, err := a.Store.GetDatabase(databaseName)
	if err != nil {
		return nil, err
	}

	policy, err := a.Store.GetPolicy(database.ID)
	if err != nil {
		return nil, err
	}

	backend := a.Config.DefaultStorage
	encryptBackups := true
	if policy != nil {
		if policy.StorageBackend != "" {
			backend = policy.StorageBackend
		}
		encryptBackups = policy.Encryption
	}

	backend, err = a.ResolveStorage(backend)
	if err != nil {
		return nil, err
	}

	store, err := a.Storage(backend)
	if err != nil {
		return nil, err
	}

	var (
		keyring    encryption.Keyring
		keyVersion int
	)
	if encryptBackups {
		if a.Config.EncryptionKey == nil {
			return nil, errors.New(
				"backups are encrypted but PGVAULT_MASTER_KEY is not set " +
					"(set it or disable encryption for this database)",
			)
		}
		keyVersion = a.Config.KeyVersion
		keyring = encryption.Keyring{keyVersion: a.Config.EncryptionKey}
	}

	// A tunnel profile routes the backup through an SSH bastion. A
	// docker profile additionally switches pg_dump from this machine
	// into the container: on the bastion when both profiles exist,
	// locally otherwise.
	tunnelSpec, err := a.Store.GetTunnel(database.ID)
	if err != nil {
		return nil, err
	}

	containerSpec, err := a.Store.GetDocker(database.ID)
	if err != nil {
		return nil, err
	}

	dumper := selectDumper(tunnelSpec, containerSpec)

	databaseURL := database.ConnectionString
	if containerSpec == nil && tunnelSpec != nil {
		// pg_dump dials the local end of the tunnel instead of the
		// database directly.
		forward, tunneledURL, err := a.openTunnel(
			ctx,
			database.ConnectionString,
			tunnelSpec,
		)
		if err != nil {
			return nil, err
		}
		defer forward.Close()
		databaseURL = tunneledURL
	}

	return a.Manager.Backup(ctx, backup.Request{
		DatabaseID:     database.ID,
		DatabaseName:   database.Name,
		DatabaseURL:    databaseURL,
		Storage:        store,
		StorageBackend: backend,
		Encryption:     encryptBackups,
		Keyring:        keyring,
		KeyVersion:     keyVersion,
		Trigger:        trigger,
		Dumper:         dumper,
	})
}

// selectDumper picks the dump strategy for a database. A tunnel
// without a docker profile is handled by the caller with a local port
// forward, so it keeps the local dumper.
func selectDumper(
	tunnel *metadata.Tunnel,
	container *metadata.Docker,
) postgres.Dumper {
	if container == nil {
		return postgres.NewLocalDumper()
	}

	dumper := &docker.Dumper{
		Profile: docker.Profile{
			Container: container.Container,
			Host:      container.Host,
			Port:      container.Port,
		},
	}
	if tunnel != nil {
		cfg := TunnelConfig(tunnel)
		dumper.Host.Tunnel = &cfg
	}

	return dumper
}

// RecordSkipped records a scheduled backup that was not started
// because another backup of the same database was still running.
func (a *App) RecordSkipped(databaseName, reason string) error {
	database, err := a.Store.GetDatabase(databaseName)
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	return a.Store.CreateBackup(metadata.BackupRecord{
		ID:           uuid.NewString(),
		DatabaseID:   database.ID,
		DatabaseName: database.Name,
		Status:       string(backup.StatusSkipped),
		Reason:       reason,
		Trigger:      "schedule",
		StartedAt:    now,
		CompletedAt:  now,
	})
}

// ResolveStorage validates a storage backend name against the
// configuration, falling back to the default.
func (a *App) ResolveStorage(backend string) (string, error) {
	if backend == "" {
		backend = a.Config.DefaultStorage
	}
	switch backend {
	case "local", "s3":
		return backend, nil
	default:
		return "", fmt.Errorf(
			"unknown storage backend %q (want local or s3)",
			backend,
		)
	}
}

// Storage builds a storage backend from the configuration.
func (a *App) Storage(backend string) (storage.Storage, error) {
	backend, err := a.ResolveStorage(backend)
	if err != nil {
		return nil, err
	}

	if backend == "local" {
		return storage.NewLocalStorage(a.Config.BackupDir), nil
	}

	return storage.NewS3Storage(context.Background(), storage.S3Config{
		Bucket:    a.Config.S3.Bucket,
		Region:    a.Config.S3.Region,
		Endpoint:  a.Config.S3.Endpoint,
		Prefix:    a.Config.S3.Prefix,
		PathStyle: a.Config.S3.PathStyle,
	})
}

// openTunnel starts an SSH forward for a connection string and returns
// the tunnel together with the connection string rewritten to dial the
// local end of the tunnel.
func (a *App) openTunnel(
	ctx context.Context,
	connectionString string,
	spec *metadata.Tunnel,
) (*sshtunnel.Tunnel, string, error) {
	endpoint, err := postgres.ParseEndpoint(connectionString)
	if err != nil {
		return nil, "", fmt.Errorf("ssh tunnel target: %w", err)
	}

	forward, err := sshtunnel.Open(
		ctx,
		TunnelConfig(spec),
		endpoint.Host,
		endpoint.Port,
	)
	if err != nil {
		return nil, "", fmt.Errorf("open ssh tunnel to %s:%d: %w", spec.Host, spec.Port, err)
	}

	url, err := postgres.RewriteEndpoint(
		connectionString,
		forward.LocalAddr(),
	)
	if err != nil {
		forward.Close()
		return nil, "", err
	}

	return forward, url, nil
}

// TunnelConfig converts a stored tunnel profile into runtime
// configuration; secrets left empty come from the environment at
// resolve time (PGVAULT_SSH_PASSWORD, PGVAULT_SSH_KEY_PASSPHRASE).
func TunnelConfig(spec *metadata.Tunnel) sshtunnel.Config {
	return sshtunnel.Config{
		Host:                  spec.Host,
		Port:                  spec.Port,
		User:                  spec.User,
		Auth:                  spec.AuthMethod,
		Password:              spec.Password,
		KeyFile:               spec.KeyPath,
		KeyPassphrase:         spec.KeyPassphrase,
		KnownHosts:            spec.KnownHosts,
		InsecureIgnoreHostKey: spec.Insecure,
	}
}
