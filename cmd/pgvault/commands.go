package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/spf13/pflag"

	"github.com/Dani-Bhai/pg-vault/internal/app"
	"github.com/Dani-Bhai/pg-vault/internal/archive"
	"github.com/Dani-Bhai/pg-vault/internal/backup"
	"github.com/Dani-Bhai/pg-vault/internal/metadata"
	"github.com/Dani-Bhai/pg-vault/internal/scheduler"
)

var errHelp = errors.New("help requested")

func openApp(fn func(*app.App) error) error {
	a, err := app.Open()
	if err != nil {
		return err
	}
	defer a.Close()
	return fn(a)
}

func newFlagSet(name string) *pflag.FlagSet {
	fs := pflag.NewFlagSet(name, pflag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

func parseFlags(fs *pflag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, pflag.ErrHelp) {
			fmt.Fprint(os.Stderr, usage)
			return errHelp
		}
		return err
	}
	return nil
}

func cmdAdd(args []string) error {
	fs := newFlagSet("add")
	url := fs.String("url", "", "postgres connection string")
	backend := fs.String("storage", "", "storage backend: local or s3")
	encrypt := fs.Bool("encryption", true, "encrypt this database's backups")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: pgvault add <name> --url <postgres-url>")
	}
	if *url == "" {
		return errors.New("add: --url is required")
	}

	return openApp(func(a *app.App) error {
		resolved, err := a.ResolveStorage(*backend)
		if err != nil {
			return err
		}

		database, err := a.Store.AddDatabase(fs.Arg(0), *url)
		if err != nil {
			return err
		}

		err = a.Store.UpsertPolicy(metadata.Policy{
			DatabaseID:     database.ID,
			StorageBackend: resolved,
			Encryption:     *encrypt,
		})
		if err != nil {
			return err
		}

		fmt.Printf(
			"registered %s (storage: %s, encryption: %t)\n",
			database.Name,
			resolved,
			*encrypt,
		)
		return nil
	})
}

func cmdDatabases(args []string) error {
	fs := newFlagSet("databases")
	if err := parseFlags(fs, args); err != nil {
		return err
	}

	return openApp(func(a *app.App) error {
		databases, err := a.Store.ListDatabases()
		if err != nil {
			return err
		}
		if len(databases) == 0 {
			fmt.Println("no databases registered")
			return nil
		}

		rows := make([][]string, 0, len(databases))
		for _, database := range databases {
			policy, err := a.Store.GetPolicy(database.ID)
			if err != nil {
				return err
			}

			schedule := "-"
			backend := a.Config.DefaultStorage
			encryption := true
			if policy != nil {
				if policy.Schedule != "" && policy.Enabled {
					schedule = policy.Schedule
				}
				backend = policy.StorageBackend
				encryption = policy.Encryption
			}

			enabled := "yes"
			if !database.Enabled {
				enabled = "no"
			}

			rows = append(rows, []string{
				database.Name,
				enabled,
				schedule,
				backend,
				fmt.Sprintf("%t", encryption),
			})
		}

		printTable(
			[]string{"NAME", "ENABLED", "SCHEDULE", "STORAGE", "ENCRYPTION"},
			rows,
		)
		return nil
	})
}

func cmdBackup(args []string) error {
	fs := newFlagSet("backup")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: pgvault backup <name>")
	}
	name := fs.Arg(0)

	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

	return openApp(func(a *app.App) error {
		result, err := a.RunBackup(ctx, name, "manual")
		if err != nil {
			if result != nil {
				return fmt.Errorf("backup %s failed: %w", result.ID, err)
			}
			return err
		}
		printBackup(result)
		return nil
	})
}

func cmdBackups(args []string) error {
	fs := newFlagSet("backups")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() > 1 {
		return errors.New("usage: pgvault backups [name]")
	}
	var name string
	if fs.NArg() == 1 {
		name = fs.Arg(0)
	}

	return openApp(func(a *app.App) error {
		records, err := a.Store.ListBackups(name)
		if err != nil {
			return err
		}
		if len(records) == 0 {
			fmt.Println("no backups found")
			return nil
		}

		rows := make([][]string, 0, len(records))
		for _, record := range records {
			rows = append(rows, []string{
				record.ID,
				record.DatabaseName,
				record.Status,
				sizeOrDash(record),
				localTime(record.StartedAt),
				durationOrDash(record),
			})
		}

		printTable(
			[]string{"BACKUP ID", "DATABASE", "STATUS", "SIZE", "STARTED", "DURATION"},
			rows,
		)
		return nil
	})
}

func cmdInspect(args []string) error {
	fs := newFlagSet("inspect")
	verify := fs.Bool("verify", false, "stream the object and verify its checksum")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: pgvault inspect <backup-id> [--verify]")
	}
	id := fs.Arg(0)

	return openApp(func(a *app.App) error {
		record, err := a.Store.GetBackup(id)
		if err != nil {
			return err
		}

		fmt.Println("Backup:    ", record.ID)
		fmt.Println("Database:  ", record.DatabaseName)
		fmt.Println("Status:    ", record.Status)
		if record.Reason != "" {
			fmt.Println("Reason:    ", record.Reason)
		}
		fmt.Println("Started:   ", localTime(record.StartedAt))
		fmt.Println("Completed: ", localTime(record.CompletedAt))
		fmt.Println("Duration:  ", durationOrDash(*record))
		if record.SizeBytes > 0 {
			fmt.Printf(
				"Size:       %s (%d bytes)\n",
				formatBytes(record.SizeBytes),
				record.SizeBytes,
			)
		}
		fmt.Println("Path:      ", record.Path)
		fmt.Println("Storage:   ", record.StorageBackend)
		if record.Trigger != "" {
			fmt.Println("Trigger:   ", record.Trigger)
		}
		if record.Checksum != "" {
			fmt.Println("Checksum:  ", "sha256:"+record.Checksum)
		}
		if record.Encryption != "" {
			fmt.Printf(
				"Encryption: %s (key version %d)\n",
				record.Encryption,
				record.KeyVersion,
			)
		} else {
			fmt.Println("Encryption: none")
		}
		if record.Error != "" {
			fmt.Println("Error:     ", record.Error)
		}

		store, err := a.Storage(record.StorageBackend)
		if err != nil {
			return err
		}

		object, err := store.Get(context.Background(), record.Path)
		if err != nil {
			return err
		}
		defer object.Close()

		hasher := sha256.New()
		var source io.Reader = object
		if *verify {
			source = io.TeeReader(object, hasher)
		}

		header, err := archive.ReadHeader(source)
		if err != nil {
			return fmt.Errorf("read object header: %w", err)
		}

		fmt.Printf("Format:     pgvault/%d (%s, %s)\n",
			header.Version,
			header.Type,
			header.Compression,
		)
		fmt.Println("Created:   ", header.CreatedAt.Local().Format(time.RFC3339))
		if header.Encryption != nil {
			fmt.Printf(
				"Object encryption: %s (key version %d, chunk size %d)\n",
				header.Encryption.Algorithm,
				header.Encryption.KeyVersion,
				header.Encryption.ChunkSize,
			)
		}

		if !*verify {
			return nil
		}

		if record.Checksum == "" {
			return errors.New("no checksum recorded for this backup")
		}
		if _, err := io.Copy(io.Discard, source); err != nil {
			return fmt.Errorf("read object: %w", err)
		}

		sum := hex.EncodeToString(hasher.Sum(nil))
		if sum != record.Checksum {
			return fmt.Errorf(
				"checksum mismatch: object is %s, metadata says %s",
				sum,
				record.Checksum,
			)
		}

		fmt.Println("Checksum verified.")
		return nil
	})
}

func cmdSchedule(args []string) error {
	fs := newFlagSet("schedule")
	backend := fs.String("storage", "", "storage backend: local or s3")
	encrypt := fs.Bool("encryption", true, "encrypt backups")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return errors.New(`usage: pgvault schedule <name> "<cron>"`)
	}
	name, spec := fs.Arg(0), fs.Arg(1)

	if err := scheduler.ValidateSchedule(spec); err != nil {
		return fmt.Errorf("invalid schedule %q: %w", spec, err)
	}

	return openApp(func(a *app.App) error {
		database, err := a.Store.GetDatabase(name)
		if err != nil {
			return err
		}

		policy, err := a.Store.GetPolicy(database.ID)
		if err != nil {
			return err
		}

		updated := metadata.Policy{
			DatabaseID:     database.ID,
			StorageBackend: a.Config.DefaultStorage,
			Encryption:     true,
		}
		if policy != nil {
			updated = *policy
		}
		updated.Schedule = spec
		updated.Enabled = true

		if fs.Changed("storage") {
			resolved, err := a.ResolveStorage(*backend)
			if err != nil {
				return err
			}
			updated.StorageBackend = resolved
		}
		if fs.Changed("encryption") {
			updated.Encryption = *encrypt
		}

		if err := a.Store.UpsertPolicy(updated); err != nil {
			return err
		}

		fmt.Printf("scheduled %s: %s\n", name, spec)
		return nil
	})
}

func cmdDaemon(args []string) error {
	fs := newFlagSet("daemon")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: pgvault daemon")
	}

	return openApp(func(a *app.App) error {
		logger := log.New(os.Stderr, "pgvault: ", log.LstdFlags)

		sched := scheduler.New(a, a.Store, logger)
		if err := sched.Reload(); err != nil {
			return err
		}

		ctx, stop := signal.NotifyContext(
			context.Background(),
			os.Interrupt,
			syscall.SIGTERM,
		)
		defer stop()

		sched.Start()
		logger.Printf("daemon started")

		<-ctx.Done()
		logger.Printf("daemon stopping")

		stopCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := sched.Stop(stopCtx); err != nil {
			return fmt.Errorf("stop scheduler: %w", err)
		}
		return nil
	})
}

func printBackup(result *backup.Backup) {
	fmt.Println("Backup complete")
	fmt.Println("ID:", result.ID)
	fmt.Println("Path:", result.Path)
	fmt.Printf(
		"Size: %s (%d bytes)\n",
		formatBytes(result.SizeBytes),
		result.SizeBytes,
	)
	if result.Checksum != "" {
		fmt.Println("Checksum: sha256:" + result.Checksum)
	}
	if result.Encryption != "" {
		fmt.Printf(
			"Encryption: %s (key version %d)\n",
			result.Encryption,
			result.KeyVersion,
		)
	} else {
		fmt.Println("Encryption: none")
	}
	fmt.Println("Started:", localTime(result.StartedAt))
	fmt.Println("Completed:", localTime(result.CompletedAt))
}

func printTable(headers []string, rows [][]string) {
	writer := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(writer, strings.Join(headers, "\t"))
	for _, row := range rows {
		fmt.Fprintln(writer, strings.Join(row, "\t"))
	}
	writer.Flush()
}

func sizeOrDash(record metadata.BackupRecord) string {
	if record.SizeBytes <= 0 {
		return "-"
	}
	return formatBytes(record.SizeBytes)
}

func durationOrDash(record metadata.BackupRecord) string {
	if record.StartedAt.IsZero() || record.CompletedAt.IsZero() {
		return "-"
	}
	return record.CompletedAt.Sub(record.StartedAt).Round(time.Millisecond).String()
}

func localTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.Local().Format("2006-01-02 15:04:05")
}

// formatBytes renders a byte count using binary units.
func formatBytes(n int64) string {
	const unit = 1024

	if n < unit {
		return fmt.Sprintf("%d B", n)
	}

	units := []string{"KiB", "MiB", "GiB", "TiB", "PiB"}

	value := float64(n)
	i := -1

	for value >= unit && i < len(units)-1 {
		value /= unit
		i++
	}

	return fmt.Sprintf("%.1f %s", value, units[i])
}
