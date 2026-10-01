package postgres

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
)

// Dumper streams a custom-format PostgreSQL archive of databaseURL into
// writer.
type Dumper interface {
	Dump(ctx context.Context, databaseURL string, writer io.Writer) error
}

// DumpArgs are the pg_dump arguments shared by every execution mode.
//
// The custom format is kept because it supports selective and
// reordered restores with pg_restore; compression is disabled here
// because the archive pipeline compresses the stream itself.
func DumpArgs(databaseURL string) []string {
	return []string{
		"--format=custom",
		"--compress=0",
		"--no-owner",
		"--no-privileges",
		databaseURL,
	}
}

// DumpError annotates a failed pg_dump-like command with its stderr.
func DumpError(name string, err error, stderr string) error {
	if message := strings.TrimSpace(stderr); message != "" {
		return fmt.Errorf("%s failed: %w: %s", name, err, message)
	}
	return fmt.Errorf("%s failed: %w", name, err)
}

// RunCommand runs name with args, streaming stdout and stderr to the
// given writers. It is the shared implementation for local dumps and
// local docker exec.
func RunCommand(
	ctx context.Context,
	name string,
	args []string,
	stdout, stderr io.Writer,
) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	return cmd.Run()
}

// LocalDumper streams backups by running pg_dump as a local process.
type LocalDumper struct {
	Binary string
}

func NewLocalDumper() *LocalDumper {
	return &LocalDumper{
		Binary: "pg_dump",
	}
}

// Dump writes a custom-format archive of databaseURL to writer.
//
// The archive is streamed as pg_dump produces it; no temporary file is
// involved.
func (d *LocalDumper) Dump(
	ctx context.Context,
	databaseURL string,
	writer io.Writer,
) error {
	var stderr bytes.Buffer

	err := RunCommand(ctx, d.Binary, DumpArgs(databaseURL), writer, &stderr)
	if err != nil {
		return DumpError(d.Binary, err, stderr.String())
	}

	return nil
}
