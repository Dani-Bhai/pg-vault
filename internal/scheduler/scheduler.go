// Package scheduler runs scheduled backups inside the pgvault daemon.
//
// Schedules are loaded from the metadata database at startup. Every
// database gets its own lock, so a backup that is still running causes
// the next occurrence to be skipped and recorded as "skipped" with
// reason "previous_backup_running" instead of overlapping.
package scheduler

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/robfig/cron/v3"

	"github.com/Dani-Bhai/pg-vault/internal/backup"
	"github.com/Dani-Bhai/pg-vault/internal/metadata"
)

// Runner runs one backup. It is implemented by app.App.
type Runner interface {
	RunBackup(
		ctx context.Context,
		databaseName string,
		trigger string,
	) (*backup.Backup, error)

	RecordSkipped(databaseName, reason string) error
}

// Scheduler registers one cron job per scheduled database.
type Scheduler struct {
	runner Runner
	store  *metadata.Store
	log    *log.Logger
	cron   *cron.Cron
	locks  sync.Map // database name -> *sync.Mutex
}

var parser = cron.NewParser(
	cron.Minute |
		cron.Hour |
		cron.Dom |
		cron.Month |
		cron.Dow |
		cron.Descriptor,
)

// ValidateSchedule reports whether spec is a valid cron expression or
// descriptor, for example "0 */6 * * *" or "@every 1h".
func ValidateSchedule(spec string) error {
	_, err := parser.Parse(spec)
	return err
}

// New returns a Scheduler. The store is used by Reload.
func New(
	runner Runner,
	store *metadata.Store,
	logger *log.Logger,
) *Scheduler {
	return &Scheduler{
		runner: runner,
		store:  store,
		log:    logger,
		cron:   cron.New(cron.WithParser(parser)),
	}
}

// Reload registers a cron job for every enabled schedule in the
// metadata database. Call it before Start.
func (s *Scheduler) Reload() error {
	schedules, err := s.store.ListSchedules()
	if err != nil {
		return err
	}

	for _, schedule := range schedules {
		name := schedule.DatabaseName
		if _, err := s.cron.AddFunc(
			schedule.Schedule,
			func() { s.run(name) },
		); err != nil {
			return fmt.Errorf(
				"register schedule for %s: %w",
				name,
				err,
			)
		}
		s.log.Printf("scheduled %s: %s", name, schedule.Schedule)
	}

	if len(schedules) == 0 {
		s.log.Printf("no schedules configured")
	}
	return nil
}

// Start begins running jobs.
func (s *Scheduler) Start() {
	s.cron.Start()
}

// Stop stops scheduling new jobs and waits for running backups to
// finish, or until ctx is done.
func (s *Scheduler) Stop(ctx context.Context) error {
	stopped := s.cron.Stop()
	select {
	case <-stopped.Done():
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// run executes one scheduled backup, skipping it when a backup of the
// same database is already in progress.
func (s *Scheduler) run(databaseName string) {
	lock := s.lock(databaseName)
	if !lock.TryLock() {
		s.log.Printf(
			"skip %s: previous backup still running",
			databaseName,
		)
		if err := s.runner.RecordSkipped(
			databaseName,
			"previous_backup_running",
		); err != nil {
			s.log.Printf(
				"record skipped backup for %s: %v",
				databaseName,
				err,
			)
		}
		return
	}
	defer lock.Unlock()

	s.log.Printf("backup start: %s", databaseName)
	started := time.Now()

	result, err := s.runner.RunBackup(
		context.Background(),
		databaseName,
		"schedule",
	)
	if err != nil {
		s.log.Printf("backup failed: %s: %v", databaseName, err)
		return
	}

	s.log.Printf(
		"backup complete: %s id=%s size=%dB duration=%s",
		databaseName,
		result.ID,
		result.SizeBytes,
		time.Since(started).Round(time.Millisecond),
	)
}

func (s *Scheduler) lock(databaseName string) *sync.Mutex {
	value, _ := s.locks.LoadOrStore(databaseName, &sync.Mutex{})
	return value.(*sync.Mutex)
}
