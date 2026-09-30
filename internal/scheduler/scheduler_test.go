package scheduler

import (
	"context"
	"io"
	"log"
	"sync"
	"testing"
	"time"

	"github.com/Dani-Bhai/pg-vault/internal/backup"
)

type fakeRunner struct {
	started chan struct{}
	release chan struct{}

	mu    sync.Mutex
	skips []string
}

func (f *fakeRunner) RunBackup(
	ctx context.Context,
	databaseName string,
	trigger string,
) (*backup.Backup, error) {
	if f.started != nil {
		f.started <- struct{}{}
	}
	if f.release != nil {
		<-f.release
	}
	return &backup.Backup{
		ID:           "backup-1",
		DatabaseName: databaseName,
		Status:       backup.StatusSuccess,
	}, nil
}

func (f *fakeRunner) RecordSkipped(databaseName, reason string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.skips = append(f.skips, databaseName+":"+reason)
	return nil
}

func TestValidateSchedule(t *testing.T) {
	for _, valid := range []string{"0 */6 * * *", "0 2 * * *", "@every 1h"} {
		if err := ValidateSchedule(valid); err != nil {
			t.Fatalf("expected %q to be valid: %v", valid, err)
		}
	}

	if err := ValidateSchedule("not a cron"); err == nil {
		t.Fatal("expected invalid schedule to be rejected")
	}
}

func TestOverlappingBackupIsSkipped(t *testing.T) {
	runner := &fakeRunner{
		started: make(chan struct{}, 1),
		release: make(chan struct{}),
	}
	s := New(runner, nil, log.New(io.Discard, "", 0))

	done := make(chan struct{})
	go func() {
		s.run("production")
		close(done)
	}()

	select {
	case <-runner.started:
	case <-time.After(5 * time.Second):
		t.Fatal("first backup did not start")
	}

	// The first backup is still running; this occurrence must be
	// skipped instead of stacking up.
	s.run("production")

	select {
	case <-done:
		t.Fatal("first backup finished unexpectedly")
	default:
	}

	close(runner.release)

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("first backup did not finish")
	}

	runner.mu.Lock()
	defer runner.mu.Unlock()
	if len(runner.skips) != 1 {
		t.Fatalf("expected exactly one skipped backup, got %v", runner.skips)
	}
	if runner.skips[0] != "production:previous_backup_running" {
		t.Fatalf("unexpected skip record: %v", runner.skips)
	}
}
