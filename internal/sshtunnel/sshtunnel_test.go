package sshtunnel

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// bastion is an in-process SSH server: it authenticates according to
// its ServerConfig and forwards direct-tcpip channels to a real local
// listener, so the whole forwarding path is exercised without sshd.
type bastion struct {
	listener net.Listener
	config   *ssh.ServerConfig
}

func newBastion(
	t *testing.T,
	setup func(*ssh.ServerConfig),
) (*bastion, ssh.Signer) {
	t.Helper()

	_, hostPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(hostPrivateKey)
	if err != nil {
		t.Fatalf("create host signer: %v", err)
	}

	config := &ssh.ServerConfig{}
	setup(config)
	config.AddHostKey(signer)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	server := &bastion{listener: listener, config: config}
	go server.serve()
	t.Cleanup(func() { listener.Close() })
	return server, signer
}

func (b *bastion) serve() {
	for {
		conn, err := b.listener.Accept()
		if err != nil {
			return
		}
		go b.handle(conn)
	}
}

func (b *bastion) handle(conn net.Conn) {
	serverConn, channels, requests, err := ssh.NewServerConn(conn, b.config)
	if err != nil {
		conn.Close()
		return
	}
	defer serverConn.Close()

	go ssh.DiscardRequests(requests)

	for newChannel := range channels {
		switch newChannel.ChannelType() {
		case "direct-tcpip":
			go b.forward(newChannel)
		case "session":
			go b.session(newChannel)
		default:
			newChannel.Reject(ssh.UnknownChannelType, "unsupported")
		}
	}
}

// forward handles a direct-tcpip channel by dialing the requested
// address and relaying bytes, like an sshd's port forward.
func (b *bastion) forward(newChannel ssh.NewChannel) {
	var request directTCPIPRequest
	if err := ssh.Unmarshal(newChannel.ExtraData(), &request); err != nil {
		newChannel.Reject(ssh.ConnectionFailed, err.Error())
		return
	}

	upstream, err := net.Dial(
		"tcp",
		net.JoinHostPort(request.Address, strconv.Itoa(int(request.Port))),
	)
	if err != nil {
		newChannel.Reject(ssh.ConnectionFailed, err.Error())
		return
	}

	channel, channelRequests, err := newChannel.Accept()
	if err != nil {
		upstream.Close()
		return
	}
	go ssh.DiscardRequests(channelRequests)

	go func() {
		defer upstream.Close()
		defer channel.Close()
		_, _ = io.Copy(upstream, channel)
	}()
	go func() {
		defer upstream.Close()
		defer channel.Close()
		_, _ = io.Copy(channel, upstream)
	}()
}

// session handles an exec session channel by running the command with
// a local shell, like an sshd would.
func (b *bastion) session(newChannel ssh.NewChannel) {
	channel, requests, err := newChannel.Accept()
	if err != nil {
		return
	}
	defer channel.Close()

	var status uint32 = 1
	ran := false

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
		ran = true

		command := exec.Command("sh", "-c", payload.Command)
		command.Stdout = channel
		command.Stderr = channel.Stderr()

		if err := command.Run(); err != nil {
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				status = uint32(exitErr.ExitCode())
			} else {
				status = 127
			}
		} else {
			status = 0
		}
		break
	}

	if ran {
		_, _ = channel.SendRequest(
			"exit-status",
			false,
			ssh.Marshal(struct{ Status uint32 }{status}),
		)
	}
}

// directTCPIPRequest mirrors the direct-tcpip channel open payload.
type directTCPIPRequest struct {
	Address       string
	Port          uint32
	OriginAddress string
	OriginPort    uint32
}

// echoServer accepts connections, sends a greeting line and then
// echoes everything back; it stands in for PostgreSQL.
func echoServer(t *testing.T) (addr string, greeting string) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { listener.Close() })

	greeting = "backup-ready\n"
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				if _, err := conn.Write([]byte(greeting)); err != nil {
					return
				}
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()

	return listener.Addr().String(), greeting
}

func targetOf(addr string) (host string, port int) {
	host, portString, err := net.SplitHostPort(addr)
	if err != nil {
		panic(err)
	}
	port, err = strconv.Atoi(portString)
	if err != nil {
		panic(err)
	}
	return host, port
}

// tunnelConfig returns a Config for a bastion.
func tunnelConfig(bastionAddr string, override func(*Config)) Config {
	host, port := targetOf(bastionAddr)
	cfg := Config{
		Host:                  host,
		Port:                  port,
		User:                  "vault",
		Password:              "carrot",
		InsecureIgnoreHostKey: true,
	}
	if override != nil {
		override(&cfg)
	}
	return cfg
}

// exchange dials through the tunnel, reads the greeting and echoes one
// round trip.
func exchange(t *testing.T, tunnel *Tunnel, greeting string) {
	t.Helper()

	conn, err := net.Dial("tcp", tunnel.LocalAddr())
	if err != nil {
		t.Fatalf("dial tunnel: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read greeting: %v", err)
	}
	if line != greeting {
		t.Fatalf("greeting: got %q, want %q", line, greeting)
	}

	if _, err := conn.Write([]byte("ping\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	line, err = reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if line != "ping\n" {
		t.Fatalf("echo: got %q", line)
	}
}

func passwordSetup(user, password string) func(*ssh.ServerConfig) {
	return func(config *ssh.ServerConfig) {
		config.PasswordCallback = func(
			meta ssh.ConnMetadata,
			offered []byte,
		) (*ssh.Permissions, error) {
			if meta.User() == user && string(offered) == password {
				return &ssh.Permissions{}, nil
			}
			return nil, fmt.Errorf("password rejected for %q", meta.User())
		}
	}
}

func keySetup(public ssh.PublicKey) func(*ssh.ServerConfig) {
	return func(config *ssh.ServerConfig) {
		config.PublicKeyCallback = func(
			meta ssh.ConnMetadata,
			key ssh.PublicKey,
		) (*ssh.Permissions, error) {
			if bytes.Equal(key.Marshal(), public.Marshal()) {
				return &ssh.Permissions{}, nil
			}
			return nil, fmt.Errorf("unknown key for %q", meta.User())
		}
	}
}

func interactiveSetup(user, password string) func(*ssh.ServerConfig) {
	return func(config *ssh.ServerConfig) {
		config.KeyboardInteractiveCallback = func(
			meta ssh.ConnMetadata,
			challenge ssh.KeyboardInteractiveChallenge,
		) (*ssh.Permissions, error) {
			if meta.User() != user {
				return nil, fmt.Errorf("user %q rejected", meta.User())
			}
			answers, err := challenge("vault", "", []string{"Password: "}, []bool{false})
			if err != nil {
				return nil, err
			}
			if len(answers) != 1 || answers[0] != password {
				return nil, fmt.Errorf("answers rejected for %q", meta.User())
			}
			return &ssh.Permissions{}, nil
		}
	}
}

// writeKey writes a private key to disk and returns its path and
// public key.
func writeKey(
	t *testing.T,
	dir string,
	passphrase string,
) (path string, public ssh.PublicKey) {
	t.Helper()

	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	var block *pem.Block
	if passphrase != "" {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(
			private,
			"",
			[]byte(passphrase),
		)
	} else {
		block, err = ssh.MarshalPrivateKey(private, "")
	}
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}

	path = filepath.Join(dir, "id_ed25519")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatalf("write key: %v", err)
	}
	defer file.Close()
	if err := pem.Encode(file, block); err != nil {
		t.Fatalf("encode key: %v", err)
	}

	public, err = ssh.NewPublicKey(private.Public())
	if err != nil {
		t.Fatalf("public key: %v", err)
	}
	return path, public
}

// startAgent runs an in-process ssh-agent on a unix socket.
func startAgent(t *testing.T, private ed25519.PrivateKey) string {
	t.Helper()

	listener, err := net.Listen(
		"unix",
		filepath.Join(t.TempDir(), "agent.sock"),
	)
	if err != nil {
		t.Fatalf("listen agent: %v", err)
	}
	t.Cleanup(func() { listener.Close() })

	keyring := agent.NewKeyring()
	if err := keyring.Add(agent.AddedKey{PrivateKey: private}); err != nil {
		t.Fatalf("add key: %v", err)
	}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go agent.ServeAgent(keyring, conn)
		}
	}()

	return listener.Addr().String()
}

func TestOpenForwardsThroughTunnelWithPassword(t *testing.T) {
	targetAddr, greeting := echoServer(t)
	targetHost, targetPort := targetOf(targetAddr)

	server, _ := newBastion(t, passwordSetup("vault", "carrot"))

	tunnel, err := Open(
		context.Background(),
		tunnelConfig(server.listener.Addr().String(), nil),
		targetHost,
		targetPort,
	)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer tunnel.Close()

	if got, want := tunnel.LocalAddr(), "127.0.0.1:"; !strings.HasPrefix(got, want) {
		t.Fatalf("local addr %q: want prefix %q", got, want)
	}

	exchange(t, tunnel, greeting)
}

func TestOpenWithKeyboardInteractiveOnly(t *testing.T) {
	targetAddr, greeting := echoServer(t)
	targetHost, targetPort := targetOf(targetAddr)

	server, _ := newBastion(t, interactiveSetup("vault", "carrot"))

	tunnel, err := Open(
		context.Background(),
		tunnelConfig(server.listener.Addr().String(), nil),
		targetHost,
		targetPort,
	)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer tunnel.Close()

	exchange(t, tunnel, greeting)
}

func TestOpenWithWrongPassword(t *testing.T) {
	targetAddr, _ := echoServer(t)
	targetHost, targetPort := targetOf(targetAddr)

	server, _ := newBastion(t, passwordSetup("vault", "carrot"))

	_, err := Open(
		context.Background(),
		tunnelConfig(server.listener.Addr().String(), func(c *Config) {
			c.Password = "wrong"
		}),
		targetHost,
		targetPort,
	)
	if err == nil {
		t.Fatal("expected authentication failure")
	}
	if !strings.Contains(err.Error(), "authenticate") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestOpenWithKey(t *testing.T) {
	targetAddr, greeting := echoServer(t)
	targetHost, targetPort := targetOf(targetAddr)

	keyPath, public := writeKey(t, t.TempDir(), "")
	server, _ := newBastion(t, keySetup(public))

	tunnel, err := Open(
		context.Background(),
		tunnelConfig(server.listener.Addr().String(), func(c *Config) {
			c.Auth = AuthKey
			c.KeyFile = keyPath
			c.Password = ""
		}),
		targetHost,
		targetPort,
	)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer tunnel.Close()

	exchange(t, tunnel, greeting)
}

func TestOpenWithEncryptedKey(t *testing.T) {
	targetAddr, greeting := echoServer(t)
	targetHost, targetPort := targetOf(targetAddr)

	keyPath, public := writeKey(t, t.TempDir(), "passthrough")
	server, _ := newBastion(t, keySetup(public))

	cfg := tunnelConfig(server.listener.Addr().String(), func(c *Config) {
		c.Auth = AuthKey
		c.KeyFile = keyPath
		c.Password = ""
	})

	// Without a passphrase the encrypted key must be rejected.
	if _, err := Open(context.Background(), cfg, targetHost, targetPort); err == nil {
		t.Fatal("expected missing passphrase to be rejected")
	} else if !strings.Contains(err.Error(), "encrypted") {
		t.Fatalf("unexpected error: %v", err)
	}

	// A wrong passphrase must be rejected too.
	wrong := cfg
	wrong.KeyPassphrase = "nope"
	if _, err := Open(context.Background(), wrong, targetHost, targetPort); err == nil {
		t.Fatal("expected wrong passphrase to be rejected")
	} else if !strings.Contains(err.Error(), "decrypt") {
		t.Fatalf("unexpected error: %v", err)
	}

	// The right passphrase opens the tunnel.
	cfg.KeyPassphrase = "passthrough"
	tunnel, err := Open(context.Background(), cfg, targetHost, targetPort)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer tunnel.Close()

	exchange(t, tunnel, greeting)
}

func TestOpenWithPassphraseFromEnvironment(t *testing.T) {
	targetAddr, _ := echoServer(t)
	targetHost, targetPort := targetOf(targetAddr)

	keyPath, public := writeKey(t, t.TempDir(), "passthrough")
	server, _ := newBastion(t, keySetup(public))

	t.Setenv(EnvKeyPassphrase, "passthrough")

	tunnel, err := Open(
		context.Background(),
		tunnelConfig(server.listener.Addr().String(), func(c *Config) {
			c.Auth = AuthKey
			c.KeyFile = keyPath
			c.Password = ""
		}),
		targetHost,
		targetPort,
	)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer tunnel.Close()
}

func TestOpenWithAgent(t *testing.T) {
	targetAddr, greeting := echoServer(t)
	targetHost, targetPort := targetOf(targetAddr)

	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	public, err := ssh.NewPublicKey(private.Public())
	if err != nil {
		t.Fatalf("public key: %v", err)
	}

	socket := startAgent(t, private)
	t.Setenv("SSH_AUTH_SOCK", socket)

	server, _ := newBastion(t, keySetup(public))

	tunnel, err := Open(
		context.Background(),
		tunnelConfig(server.listener.Addr().String(), func(c *Config) {
			c.Auth = AuthAgent
			c.Password = ""
		}),
		targetHost,
		targetPort,
	)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer tunnel.Close()

	exchange(t, tunnel, greeting)
}

func TestOpenAutoPrefersKey(t *testing.T) {
	targetAddr, greeting := echoServer(t)
	targetHost, targetPort := targetOf(targetAddr)

	// The bastion only accepts public keys; if auto picked the
	// password, authentication would fail.
	keyPath, public := writeKey(t, t.TempDir(), "")
	server, _ := newBastion(t, keySetup(public))

	tunnel, err := Open(
		context.Background(),
		tunnelConfig(server.listener.Addr().String(), func(c *Config) {
			c.KeyFile = keyPath
			c.Password = "carrot"
		}),
		targetHost,
		targetPort,
	)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer tunnel.Close()

	exchange(t, tunnel, greeting)
}

func TestOpenAutoFallsBackToPassword(t *testing.T) {
	targetAddr, greeting := echoServer(t)
	targetHost, targetPort := targetOf(targetAddr)

	// The bastion only accepts passwords and no agent is running.
	server, _ := newBastion(t, passwordSetup("vault", "carrot"))

	t.Setenv("SSH_AUTH_SOCK", "")

	tunnel, err := Open(
		context.Background(),
		tunnelConfig(server.listener.Addr().String(), nil),
		targetHost,
		targetPort,
	)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer tunnel.Close()

	exchange(t, tunnel, greeting)
}

func TestPasswordFromEnvironmentOverridesStored(t *testing.T) {
	targetAddr, greeting := echoServer(t)
	targetHost, targetPort := targetOf(targetAddr)

	// The bastion accepts only the environment password.
	server, _ := newBastion(t, passwordSetup("vault", "carrot"))

	t.Setenv(EnvPassword, "carrot")

	tunnel, err := Open(
		context.Background(),
		tunnelConfig(server.listener.Addr().String(), func(c *Config) {
			c.Password = "stale"
		}),
		targetHost,
		targetPort,
	)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer tunnel.Close()

	exchange(t, tunnel, greeting)
}

func TestKnownHostsVerification(t *testing.T) {
	targetAddr, greeting := echoServer(t)
	targetHost, targetPort := targetOf(targetAddr)

	server, hostSigner := newBastion(t, passwordSetup("vault", "carrot"))

	knownHostsPath := filepath.Join(t.TempDir(), "known_hosts")

	// A missing known_hosts file is a configuration error.
	missing := tunnelConfig(server.listener.Addr().String(), nil)
	missing.InsecureIgnoreHostKey = false
	missing.KnownHosts = knownHostsPath
	if _, err := Open(context.Background(), missing, targetHost, targetPort); err == nil {
		t.Fatal("expected missing known_hosts to be rejected")
	} else if !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("unexpected error: %v", err)
	}

	// An unknown host key is rejected with a remediation hint.
	empty, err := os.Create(knownHostsPath)
	if err != nil {
		t.Fatal(err)
	}
	empty.Close()
	if _, err := Open(context.Background(), missing, targetHost, targetPort); err == nil {
		t.Fatal("expected unknown host key to be rejected")
	} else if !strings.Contains(err.Error(), "no key in") {
		t.Fatalf("unexpected error: %v", err)
	}

	// With the host key recorded, the tunnel verifies and opens.
	_, bastionPort := targetOf(server.listener.Addr().String())
	line := fmt.Sprintf(
		"[127.0.0.1]:%d %s",
		bastionPort,
		strings.TrimSpace(string(ssh.MarshalAuthorizedKey(hostSigner.PublicKey()))),
	)
	if err := os.WriteFile(knownHostsPath, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}

	tunnel, err := Open(context.Background(), missing, targetHost, targetPort)
	if err != nil {
		t.Fatalf("open with known host: %v", err)
	}
	defer tunnel.Close()

	exchange(t, tunnel, greeting)
}

func TestInsecureEnvironmentSkipsHostKey(t *testing.T) {
	targetAddr, greeting := echoServer(t)
	targetHost, targetPort := targetOf(targetAddr)

	server, _ := newBastion(t, passwordSetup("vault", "carrot"))

	t.Setenv(EnvInsecure, "1")

	tunnel, err := Open(
		context.Background(),
		tunnelConfig(server.listener.Addr().String(), func(c *Config) {
			c.InsecureIgnoreHostKey = false
		}),
		targetHost,
		targetPort,
	)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer tunnel.Close()

	exchange(t, tunnel, greeting)
}

func TestOpenWithCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	server, _ := newBastion(t, passwordSetup("vault", "carrot"))

	if _, err := Open(
		ctx,
		tunnelConfig(server.listener.Addr().String(), nil),
		"127.0.0.1",
		5432,
	); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestCloseIsIdempotent(t *testing.T) {
	targetAddr, _ := echoServer(t)
	targetHost, targetPort := targetOf(targetAddr)

	server, _ := newBastion(t, passwordSetup("vault", "carrot"))

	tunnel, err := Open(
		context.Background(),
		tunnelConfig(server.listener.Addr().String(), nil),
		targetHost,
		targetPort,
	)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	if err := tunnel.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := tunnel.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
}

func TestResolveDefaults(t *testing.T) {
	cfg := Config{Host: "bastion", Password: "x"}

	resolved, err := cfg.Resolve()
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if resolved.Port != DefaultPort {
		t.Fatalf("port: got %d, want %d", resolved.Port, DefaultPort)
	}

	current, err := user.Current()
	if err != nil {
		t.Skipf("cannot resolve current user: %v", err)
	}
	if resolved.User != current.Username {
		t.Fatalf("user: got %q, want %q", resolved.User, current.Username)
	}
	if len(resolved.AuthMethods) == 0 {
		t.Fatal("expected auth methods for a configured password")
	}
}

func TestResolveErrors(t *testing.T) {
	tests := []struct {
		name    string
		config  func(*Config)
		message string
	}{
		{
			name:    "no host",
			config:  func(c *Config) { c.Host = "" },
			message: "host is required",
		},
		{
			name:    "no authentication",
			config:  func(c *Config) { c.Password = ""; c.Auth = AuthAuto },
			message: "no ssh authentication configured",
		},
		{
			name:    "password without password",
			config:  func(c *Config) { c.Password = ""; c.Auth = AuthPassword },
			message: "needs a password",
		},
		{
			name:    "key without key file",
			config:  func(c *Config) { c.Password = ""; c.Auth = AuthKey },
			message: "needs a key file",
		},
		{
			name:    "unknown auth method",
			config:  func(c *Config) { c.Auth = "gopher" },
			message: "unknown ssh auth method",
		},
		{
			name:   "agent without socket",
			config: func(c *Config) { c.Auth = AuthAgent },
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("SSH_AUTH_SOCK", "")
			t.Setenv(EnvPassword, "")
			t.Setenv(EnvInsecure, "1") // keep host key checks out of these tests

			cfg := Config{Host: "bastion", Password: "carrot"}
			test.config(&cfg)

			_, err := cfg.Resolve()
			if err == nil {
				t.Fatalf("expected an error")
			}
			if test.message != "" && !strings.Contains(err.Error(), test.message) {
				t.Fatalf("error %q: want it to contain %q", err, test.message)
			}
		})
	}
}

func TestParseTarget(t *testing.T) {
	tests := []struct {
		spec  string
		user  string
		host  string
		port  int
		error string
	}{
		{spec: "bastion", host: "bastion"},
		{spec: "alice@bastion", user: "alice", host: "bastion"},
		{spec: "bastion:2222", host: "bastion", port: 2222},
		{spec: "alice@bastion:2222", user: "alice", host: "bastion", port: 2222},
		{spec: "[::1]:22", host: "::1", port: 22},
		{spec: "[::1]", host: "::1"},
		{spec: " alice@bastion:22 ", user: "alice", host: "bastion", port: 22},
		{spec: "user:pass@host", error: "--tunnel-password"},
		{spec: "::1", error: "too many colons"},
		{spec: "host:99999", error: "invalid port"},
		{spec: "host:0", error: "invalid port"},
		{spec: "", error: "empty"},
	}

	for _, test := range tests {
		t.Run(test.spec, func(t *testing.T) {
			specUser, host, port, err := ParseTarget(test.spec)
			if test.error != "" {
				if err == nil {
					t.Fatalf("expected error containing %q", test.error)
				}
				if !strings.Contains(err.Error(), test.error) {
					t.Fatalf("error %q: want it to contain %q", err, test.error)
				}
				return
			}
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if specUser != test.user || host != test.host || port != test.port {
				t.Fatalf("got (%q, %q, %d), want (%q, %q, %d)",
					specUser, host, port, test.user, test.host, test.port)
			}
		})
	}
}

func TestResolvedDescription(t *testing.T) {
	keyPath, _ := writeKey(t, t.TempDir(), "")

	t.Setenv(EnvInsecure, "1")
	t.Setenv("SSH_AUTH_SOCK", "")

	resolved, err := Config{Host: "b", KeyFile: keyPath}.Resolve()
	if err != nil {
		t.Fatalf("resolve key: %v", err)
	}
	if !strings.Contains(resolved.Description, "key "+keyPath) {
		t.Fatalf("description %q: want the key file", resolved.Description)
	}

	resolved, err = Config{Host: "b", Password: "x"}.Resolve()
	if err != nil {
		t.Fatalf("resolve password: %v", err)
	}
	if !strings.Contains(resolved.Description, "password") {
		t.Fatalf("description %q: want password", resolved.Description)
	}
}

func TestExecStreamsOutput(t *testing.T) {
	server, _ := newBastion(t, passwordSetup("vault", "carrot"))

	var stdout, stderr bytes.Buffer
	err := Exec(
		context.Background(),
		tunnelConfig(server.listener.Addr().String(), nil),
		"printf 'hello from the bastion\\n'",
		&stdout,
		&stderr,
	)
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if got := stdout.String(); got != "hello from the bastion\n" {
		t.Fatalf("stdout: got %q", got)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr: got %q", stderr.String())
	}
}

func TestExecQuotesArguments(t *testing.T) {
	server, _ := newBastion(t, passwordSetup("vault", "carrot"))

	// The password-like argument must survive the remote shell
	// unchanged, including quotes, spaces and dollar signs.
	command := ShellJoin([]string{
		"printf",
		"%s\n",
		"it's a $test; rm -rf /",
	})

	var stdout bytes.Buffer
	err := Exec(
		context.Background(),
		tunnelConfig(server.listener.Addr().String(), nil),
		command,
		&stdout,
		io.Discard,
	)
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if got := stdout.String(); got != "it's a $test; rm -rf /\n" {
		t.Fatalf("stdout: got %q", got)
	}
}

func TestExecReportsExitStatusAndStderr(t *testing.T) {
	server, _ := newBastion(t, passwordSetup("vault", "carrot"))

	var stdout, stderr bytes.Buffer
	err := Exec(
		context.Background(),
		tunnelConfig(server.listener.Addr().String(), nil),
		"echo boom >&2; exit 3",
		&stdout,
		&stderr,
	)
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "status 3") {
		t.Fatalf("error %q: want status 3", err)
	}
	if !strings.Contains(stderr.String(), "boom") {
		t.Fatalf("stderr %q: want boom", stderr.String())
	}
}

func TestExecCanceledContext(t *testing.T) {
	server, _ := newBastion(t, passwordSetup("vault", "carrot"))

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- Exec(
			ctx,
			tunnelConfig(server.listener.Addr().String(), nil),
			"sleep 30",
			io.Discard,
			io.Discard,
		)
	}()

	time.Sleep(300 * time.Millisecond)
	cancel()

	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("exec did not stop after cancellation")
	}
}

func TestShellQuote(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{in: "", want: "''"},
		{in: "plain", want: "'plain'"},
		{in: "it's", want: `'it'\''s'`},
		{in: "a b", want: "'a b'"},
		{in: "$HOME", want: "'$HOME'"},
	}

	for _, test := range tests {
		if got := ShellQuote(test.in); got != test.want {
			t.Fatalf("ShellQuote(%q): got %q, want %q", test.in, got, test.want)
		}
	}
}
