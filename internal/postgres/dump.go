package postgres

import (
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
)

// Dumper streams PostgreSQL backups using pg_dump.
type Dumper struct {
	Binary string
}

func NewDumper() *Dumper {
	return &Dumper{
		Binary: "pg_dump",
	}
}

// Dump writes a custom-format archive of databaseURL to writer.
//
// The archive is streamed as pg_dump produces it; no temporary file is
// involved. The custom format is kept because it supports selective and
// reordered restores with pg_restore; compression is disabled here
// because the archive pipeline compresses the stream itself.
func (d *Dumper) Dump(
	ctx context.Context,
	databaseURL string,
	writer io.Writer,
) error {

	cmd := exec.CommandContext(
		ctx,
		d.Binary,
		"--format=custom",
		"--compress=0",
		"--no-owner",
		"--no-privileges",
		databaseURL,
	)

	cmd.Stdout = writer

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}

	if err := cmd.Start(); err != nil {
		return err
	}

	// Drain stderr before waiting: a chatty pg_dump must not block on
	// a full pipe while we sit in cmd.Wait().
	errBytes, _ := io.ReadAll(stderr)

	if err := cmd.Wait(); err != nil {
		return fmt.Errorf(
			"pg_dump failed: %w: %s",
			err,
			strings.TrimSpace(string(errBytes)),
		)
	}

	return nil
}
