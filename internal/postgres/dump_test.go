package postgres

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakePgDump installs a pg_dump executable for tests.
func fakePgDump(t *testing.T, script string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "pg_dump")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script+"\n"), 0o755); err != nil {
		t.Fatalf("write fake pg_dump: %v", err)
	}
	return path
}

func TestLocalDumperStreamsArchive(t *testing.T) {
	argsFile := filepath.Join(t.TempDir(), "args")
	t.Setenv("PG_DUMP_ARGS", argsFile)
	path := fakePgDump(t, `printf '%s\n' "$@" > "$PG_DUMP_ARGS"; printf 'archive'`)

	dumper := &LocalDumper{Binary: path}

	var output bytes.Buffer
	if err := dumper.Dump(
		context.Background(),
		"postgres://user:secret@127.0.0.1:5432/db",
		&output,
	); err != nil {
		t.Fatalf("dump: %v", err)
	}
	if output.String() != "archive" {
		t.Fatalf("output: got %q", output.String())
	}

	raw, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatalf("read captured args: %v", err)
	}
	got := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	want := DumpArgs("postgres://user:secret@127.0.0.1:5432/db")
	if len(got) != len(want) {
		t.Fatalf("args: got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("args[%d]: got %q, want %q", i, got[i], want[i])
		}
	}
}

func TestLocalDumperErrorIncludesStderr(t *testing.T) {
	path := fakePgDump(t, `echo "connection refused" >&2; exit 2`)

	dumper := &LocalDumper{Binary: path}
	err := dumper.Dump(
		context.Background(),
		"postgres://user:secret@127.0.0.1:5432/db",
		&bytes.Buffer{},
	)
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "pg_dump failed") ||
		!strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("unexpected error: %v", err)
	}
}
