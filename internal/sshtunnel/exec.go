package sshtunnel

import (
	"context"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/ssh"
)

// Exec runs command through the login shell on the bastion, streaming
// its stdout and stderr to the given writers. The command is executed
// by the remote shell, so argv elements must be quoted with ShellQuote
// (or joined with ShellJoin).
//
// Cancelling ctx terminates the remote command.
func Exec(
	ctx context.Context,
	cfg Config,
	command string,
	stdout, stderr io.Writer,
) error {
	client, resolved, err := dial(ctx, cfg)
	if err != nil {
		return err
	}
	defer client.Close()
	defer closeAgent(resolved.agentConn)

	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("ssh session: %w", err)
	}
	defer session.Close()

	session.Stdout = stdout
	session.Stderr = stderr

	done := make(chan struct{})
	var runErr error
	go func() {
		defer close(done)
		runErr = session.Run(command)
	}()

	select {
	case <-ctx.Done():
		// Closing the session and client unblocks Run regardless of
		// whether the remote side honours SIGTERM.
		_ = session.Signal(ssh.SIGTERM)
		_ = session.Close()
		_ = client.Close()
		<-done
		return ctx.Err()
	case <-done:
	}

	if runErr != nil {
		return fmt.Errorf("ssh exec: %w", runErr)
	}
	return nil
}

// ShellQuote wraps s so a POSIX shell passes it through as a single
// argument, even when it contains quotes, spaces, dollar signs or
// newlines.
func ShellQuote(s string) string {
	if s == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// ShellJoin quotes every element of argv and joins them into one
// command string for a shell.
func ShellJoin(argv []string) string {
	quoted := make([]string, len(argv))
	for i, arg := range argv {
		quoted[i] = ShellQuote(arg)
	}
	return strings.Join(quoted, " ")
}
