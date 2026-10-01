package docker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/Dani-Bhai/pg-vault/internal/sshtunnel"
)

// testBastion is a minimal in-process SSH server that runs exec
// requests with a local shell, so the remote docker path is exercised
// without sshd.
type testBastion struct {
	host string
	port int
}

func newTestBastion(t *testing.T) *testBastion {
	t.Helper()

	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatalf("host signer: %v", err)
	}

	config := &ssh.ServerConfig{
		PasswordCallback: func(
			meta ssh.ConnMetadata,
			password []byte,
		) (*ssh.Permissions, error) {
			if meta.User() == "vault" && string(password) == "carrot" {
				return &ssh.Permissions{}, nil
			}
			return nil, fmt.Errorf("password rejected for %q", meta.User())
		},
	}
	config.AddHostKey(signer)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { listener.Close() })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go serveTestConn(conn, config)
		}
	}()

	host, portString, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("split listen address: %v", err)
	}
	port, err := strconv.Atoi(portString)
	if err != nil {
		t.Fatalf("parse listen port: %v", err)
	}

	return &testBastion{host: host, port: port}
}

func (b *testBastion) config() *sshtunnel.Config {
	return &sshtunnel.Config{
		Host:                  b.host,
		Port:                  b.port,
		User:                  "vault",
		Password:              "carrot",
		InsecureIgnoreHostKey: true,
	}
}

func serveTestConn(conn net.Conn, config *ssh.ServerConfig) {
	serverConn, channels, requests, err := ssh.NewServerConn(conn, config)
	if err != nil {
		conn.Close()
		return
	}
	defer serverConn.Close()

	go ssh.DiscardRequests(requests)

	for newChannel := range channels {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unsupported")
			continue
		}
		go serveTestSession(newChannel)
	}
}

func serveTestSession(newChannel ssh.NewChannel) {
	channel, requests, err := newChannel.Accept()
	if err != nil {
		return
	}
	defer channel.Close()

	for request := range requests {
		if request.Type != "exec" {
			_ = request.Reply(false, nil)
			continue
		}

		var payload struct{ Command string }
		if err := ssh.Unmarshal(request.Payload, &payload); err != nil {
			_ = request.Reply(false, nil)
			continue
		}
		_ = request.Reply(true, nil)

		command := exec.Command("sh", "-c", payload.Command)
		command.Stdout = channel
		command.Stderr = channel.Stderr()

		var status uint32
		if err := command.Run(); err != nil {
			status = 1
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				status = uint32(exitErr.ExitCode())
			}
		}

		_, _ = channel.SendRequest(
			"exit-status",
			false,
			ssh.Marshal(struct{ Status uint32 }{status}),
		)
		return
	}
}

func TestHostStreamsThroughSSH(t *testing.T) {
	argsFile := filepath.Join(t.TempDir(), "args")
	t.Setenv("DOCKER_ARGS", argsFile)
	fakeDocker(t, `printf '%s\n' "$@" > "$DOCKER_ARGS"; printf 'remote-archive'`)

	bastion := newTestBastion(t)
	host := Host{Tunnel: bastion.config()}

	var output bytes.Buffer
	err := host.Stream(
		context.Background(),
		[]string{
			"exec", "qa-postgres", "pg_dump",
			"--format=custom", "--compress=0", "--no-owner", "--no-privileges",
			"postgres://user:pa'ss@127.0.0.1:5432/qa",
		},
		&output,
	)
	if err != nil {
		t.Fatalf("stream: %v", err)
	}
	if output.String() != "remote-archive" {
		t.Fatalf("output: got %q", output.String())
	}

	raw, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatalf("read captured args: %v", err)
	}
	got := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(got) != 8 {
		t.Fatalf("args: got %d (%v)", len(got), got)
	}
	if got[0] != "exec" || got[1] != "qa-postgres" || got[2] != "pg_dump" {
		t.Fatalf("unexpected prefix: %v", got[:3])
	}
	// The password with a quote must arrive intact through the
	// remote shell.
	if got[7] != "postgres://user:pa'ss@127.0.0.1:5432/qa" {
		t.Fatalf("connection string: got %q", got[7])
	}
}

func TestHostRunThroughSSHError(t *testing.T) {
	fakeDocker(t, `echo "Error: No such container: missing" >&2; exit 1`)

	bastion := newTestBastion(t)
	host := Host{Tunnel: bastion.config()}

	_, err := host.Run(context.Background(), "inspect", "missing")
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "docker inspect") ||
		!strings.Contains(err.Error(), "No such container") {
		t.Fatalf("unexpected error: %v", err)
	}
}
