// Package sshtunnel opens local SSH port forwards so tools running on
// this host, such as pg_dump, can reach a PostgreSQL database that is
// only reachable from an SSH bastion.
//
// The tunnel is a plain TCP forward: connections accepted on a local
// listener are relayed through the SSH connection to the database
// address as seen from the bastion. Password, private key and SSH
// agent authentication are supported. Host keys are verified against
// the user's known_hosts file unless verification is disabled.
package sshtunnel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

// Supported values for Config.Auth.
const (
	AuthAuto     = "auto"
	AuthPassword = "password"
	AuthKey      = "key"
	AuthAgent    = "agent"
)

// DefaultPort is the SSH port used when a target specifies none.
const DefaultPort = 22

// Environment variables that override or supply secrets at runtime.
const (
	EnvPassword      = "PGVAULT_SSH_PASSWORD"
	EnvKeyPassphrase = "PGVAULT_SSH_KEY_PASSPHRASE"
	EnvKnownHosts    = "PGVAULT_SSH_KNOWN_HOSTS"
	EnvInsecure      = "PGVAULT_SSH_INSECURE"
)

// dialTimeout bounds the SSH handshake; the tunnel itself is unbounded.
const dialTimeout = 15 * time.Second

// Config describes how to reach and authenticate against an SSH
// bastion.
type Config struct {
	Host string // bastion host
	Port int    // bastion port, 0 means the default SSH port
	User string // bastion user, 0 value means the current OS user

	Auth          string // auto (default), password, key or agent
	Password      string // password for AuthPassword
	KeyFile       string // private key path for AuthKey
	KeyPassphrase string // passphrase for an encrypted KeyFile

	KnownHosts string // known_hosts file, default ~/.ssh/known_hosts
	// InsecureIgnoreHostKey skips host key verification. Use it only
	// for tests and throwaway setups.
	InsecureIgnoreHostKey bool
}

// Resolved is a Config with defaults, environment overrides and
// authentication material prepared.
type Resolved struct {
	Config
	HostKeyCallback ssh.HostKeyCallback
	AuthMethods     []ssh.AuthMethod
	Description     string // human readable auth summary

	// AuthDescription and HostKeyDescription split Description into
	// its parts for multi-line displays.
	AuthDescription    string
	HostKeyDescription string

	// agentConn is the connection to ssh-agent; it must stay open
	// while authentication is in progress and is closed with the
	// tunnel.
	agentConn io.Closer
}

// Resolve fills in defaults, applies the environment overrides
// (PGVAULT_SSH_PASSWORD, PGVAULT_SSH_KEY_PASSPHRASE, PGVAULT_SSH_KNOWN_HOSTS,
// PGVAULT_SSH_INSECURE) and validates the combination. Environment
// variables take precedence over stored values.
func (c Config) Resolve() (Resolved, error) {
	r := Resolved{Config: c}

	if r.Host == "" {
		return r, errors.New("ssh bastion host is required")
	}
	if r.Port == 0 {
		r.Port = DefaultPort
	}
	if r.Port < 0 || r.Port > 65535 {
		return r, fmt.Errorf("invalid ssh port %d", r.Port)
	}

	if r.User == "" {
		current, err := user.Current()
		if err != nil {
			return r, fmt.Errorf("resolve ssh user: %w", err)
		}
		r.User = current.Username
	}

	passwordFromEnv := false
	if value := os.Getenv(EnvPassword); value != "" {
		r.Password = value
		passwordFromEnv = true
	}
	passphraseFromEnv := false
	if value := os.Getenv(EnvKeyPassphrase); value != "" {
		r.KeyPassphrase = value
		passphraseFromEnv = true
	}
	if value := os.Getenv(EnvInsecure); value != "" {
		insecure, err := strconv.ParseBool(value)
		if err != nil {
			return r, fmt.Errorf("%s: %w", EnvInsecure, err)
		}
		r.InsecureIgnoreHostKey = insecure
	}

	callback, knownHosts, err := r.hostKeyCallback()
	if err != nil {
		return r, err
	}
	r.HostKeyCallback = callback
	if !r.InsecureIgnoreHostKey {
		// Keep the resolved path for display.
		r.KnownHosts = knownHosts
	}

	auth := strings.ToLower(strings.TrimSpace(r.Auth))
	if auth == "" {
		auth = AuthAuto
	}

	method, description, agentConn, err := r.authMethod(auth, passwordFromEnv, passphraseFromEnv)
	if err != nil {
		return r, err
	}

	r.Auth = auth
	r.AuthMethods = method
	r.AuthDescription = description
	r.HostKeyDescription = hostKeyDescription(r.InsecureIgnoreHostKey)
	r.Description = description + "; " + r.HostKeyDescription
	r.agentConn = agentConn
	return r, nil
}

func (c Config) authMethod(
	auth string,
	passwordFromEnv bool,
	passphraseFromEnv bool,
) (method []ssh.AuthMethod, description string, agentConn io.Closer, err error) {
	switch auth {
	case AuthPassword:
		if c.Password == "" {
			return nil, "", nil, fmt.Errorf(
				"password authentication needs a password (set --tunnel-password or %s)",
				EnvPassword,
			)
		}
		return passwordMethods(c.Password), passwordDescription(passwordFromEnv), nil, nil

	case AuthKey:
		if c.KeyFile == "" {
			return nil, "", nil, errors.New(
				"key authentication needs a key file (set --tunnel-key)",
			)
		}
		signer, err := loadKey(c.KeyFile, c.KeyPassphrase, passphraseFromEnv)
		if err != nil {
			return nil, "", nil, err
		}
		return []ssh.AuthMethod{ssh.PublicKeys(signer)},
			"key " + c.KeyFile, nil, nil

	case AuthAgent:
		method, description, agentConn, err := agentMethod()
		if err != nil {
			return nil, "", nil, err
		}
		return method, description, agentConn, nil

	case AuthAuto:
		// In order: an explicitly configured key file, the ssh
		// agent, a password.
		if c.KeyFile != "" {
			signer, err := loadKey(c.KeyFile, c.KeyPassphrase, passphraseFromEnv)
			if err != nil {
				return nil, "", nil, err
			}
			return []ssh.AuthMethod{ssh.PublicKeys(signer)},
				"key " + c.KeyFile, nil, nil
		}

		if os.Getenv("SSH_AUTH_SOCK") != "" {
			method, description, agentConn, err := agentMethod()
			if err == nil {
				return method, description, agentConn, nil
			}
			// The agent is broken; if a password is available it
			// still works, otherwise report the agent problem.
			if c.Password != "" {
				return passwordMethods(c.Password), passwordDescription(passwordFromEnv), nil, nil
			}
			return nil, "", nil, err
		}

		if c.Password != "" {
			return passwordMethods(c.Password), passwordDescription(passwordFromEnv), nil, nil
		}

		return nil, "", nil, errors.New(
			"no ssh authentication configured: set --tunnel-key, start an ssh agent (SSH_AUTH_SOCK), or set --tunnel-password / " + EnvPassword,
		)

	default:
		return nil, "", nil, fmt.Errorf(
			"unknown ssh auth method %q (want auto, password, key or agent)",
			auth,
		)
	}
}

func passwordDescription(fromEnv bool) string {
	if fromEnv {
		return "password (from " + EnvPassword + ")"
	}
	return "password (stored in metadata)"
}

func passwordMethods(password string) []ssh.AuthMethod {
	return []ssh.AuthMethod{
		ssh.Password(password),
		// Many bastions only accept keyboard-interactive prompts;
		// answer those with the same password.
		ssh.KeyboardInteractive(func(
			name, instruction string,
			questions []string,
			echos []bool,
		) ([]string, error) {
			answers := make([]string, len(questions))
			for i := range questions {
				answers[i] = password
			}
			return answers, nil
		}),
	}
}

// loadKey reads a private key, decrypting it with passphrase if the
// key is encrypted.
func loadKey(path, passphrase string, passphraseFromEnv bool) (ssh.Signer, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read ssh key: %w", err)
	}

	signer, err := ssh.ParsePrivateKey(pemBytes)
	if err == nil {
		return signer, nil
	}

	var missing *ssh.PassphraseMissingError
	if !errors.As(err, &missing) {
		return nil, fmt.Errorf("parse ssh key %s: %w", path, err)
	}
	if passphrase == "" {
		return nil, fmt.Errorf(
			"ssh key %s is encrypted: set --tunnel-key-passphrase or %s",
			path, EnvKeyPassphrase,
		)
	}

	signer, err = ssh.ParsePrivateKeyWithPassphrase(pemBytes, []byte(passphrase))
	if err != nil {
		return nil, fmt.Errorf("decrypt ssh key %s: %w", path, err)
	}
	return signer, nil
}

// agentMethod talks to the user's ssh agent; it does not close the
// agent connection until the tunnel is closed, because authentication
// signs through it.
func agentMethod() ([]ssh.AuthMethod, string, io.Closer, error) {
	socket := os.Getenv("SSH_AUTH_SOCK")
	if socket == "" {
		return nil, "", nil, errors.New("no ssh agent: set SSH_AUTH_SOCK")
	}

	conn, err := net.Dial("unix", socket)
	if err != nil {
		return nil, "", nil, fmt.Errorf("connect ssh agent %s: %w", socket, err)
	}

	signers, err := agent.NewClient(conn).Signers()
	if err != nil || len(signers) == 0 {
		conn.Close()
		if err == nil {
			err = errors.New("ssh agent has no keys")
		}
		return nil, "", nil, fmt.Errorf("ssh agent %s: %w", socket, err)
	}

	return []ssh.AuthMethod{ssh.PublicKeys(signers...)},
		"agent (" + socket + ")", conn, nil
}

func hostKeyDescription(insecure bool) string {
	if insecure {
		return "host key NOT verified (insecure)"
	}
	return "host key verified against known_hosts"
}

// hostKeyCallback builds the host key verification callback and
// reports the known_hosts file it resolved. With InsecureIgnoreHostKey
// set, every key is accepted; otherwise the known_hosts file must
// exist and contain the bastion.
func (c Config) hostKeyCallback() (ssh.HostKeyCallback, string, error) {
	if c.InsecureIgnoreHostKey {
		return ssh.InsecureIgnoreHostKey(), "", nil
	}

	file := c.KnownHosts
	if file == "" {
		file = os.Getenv(EnvKnownHosts)
	}
	if file == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, "", fmt.Errorf("resolve home directory: %w", err)
		}
		file = filepath.Join(home, ".ssh", "known_hosts")
	}

	if _, err := os.Stat(file); err != nil {
		if os.IsNotExist(err) {
			return nil, "", fmt.Errorf(
				"%s does not exist: add the bastion with `ssh-keyscan -H -p %d %s >> %s`, or allow unverified hosts with --tunnel-insecure / %s=1",
				file, c.Port, c.Host, file, EnvInsecure,
			)
		}
		return nil, "", fmt.Errorf("ssh host keys: %w", err)
	}

	verify, err := knownhosts.New(file)
	if err != nil {
		return nil, "", fmt.Errorf("ssh host keys: %w", err)
	}

	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		err := verify(hostname, remote, key)
		if err == nil {
			return nil
		}

		var keyErr *knownhosts.KeyError
		if errors.As(err, &keyErr) {
			if len(keyErr.Want) == 0 {
				return fmt.Errorf(
					"host %q has no key in %s: run `ssh-keyscan -H -p %d %s >> %s` once, or allow unverified hosts with --tunnel-insecure / %s=1",
					hostname, file, c.Port, c.Host, file, EnvInsecure,
				)
			}
			return fmt.Errorf(
				"host key for %q changed or does not match %s: %w",
				hostname, file, err,
			)
		}
		return err
	}, file, nil
}

// ParseTarget parses a bastion address: "host", "user@host",
// "host:port" or "user@host:port", with brackets allowed for IPv6
// hosts. The port is 0 when not given; Config.Resolve defaults it to
// the SSH port.
func ParseTarget(spec string) (user, host string, port int, err error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return "", "", 0, errors.New("empty ssh target")
	}

	if at := strings.LastIndex(spec, "@"); at >= 0 {
		user = spec[:at]
		spec = spec[at+1:]
		if strings.Contains(user, ":") {
			return "", "", 0, errors.New(
				"passwords are not part of the ssh target: use --tunnel-password or PGVAULT_SSH_PASSWORD",
			)
		}
	}

	host, portString, err := net.SplitHostPort(spec)
	if err != nil {
		var addrErr *net.AddrError
		if !errors.As(err, &addrErr) ||
			!strings.Contains(addrErr.Err, "missing port") {
			return "", "", 0, fmt.Errorf("parse ssh target %q: %w", spec, err)
		}
		// No port; the whole remaining text is the host.
		host, portString = spec, ""
	}

	if host == "" && portString == "" {
		return "", "", 0, fmt.Errorf("parse ssh target %q: no host", spec)
	}

	// SplitHostPort keeps brackets for bare IPv6 hosts.
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")

	if portString != "" {
		port, err = strconv.Atoi(portString)
		if err != nil || port <= 0 || port > 65535 {
			return "", "", 0, fmt.Errorf(
				"parse ssh target %q: invalid port %q",
				spec, portString,
			)
		}
	}

	return user, host, port, nil
}

// Tunnel is an open SSH connection with a local listener forwarding to
// a database address reachable from the bastion.
type Tunnel struct {
	cfg      Resolved
	client   *ssh.Client
	listener net.Listener
	remote   string
	ctx      context.Context
	cancel   context.CancelFunc

	mu     sync.Mutex
	closed bool
	wg     sync.WaitGroup
}

// Open dials the bastion and starts a local listener that forwards to
// databaseHost:databasePort as seen from the bastion. Hostnames are
// resolved on the bastion, so localhost there means the bastion
// itself.
func Open(
	ctx context.Context,
	cfg Config,
	databaseHost string,
	databasePort int,
) (*Tunnel, error) {
	if databaseHost == "" {
		return nil, errors.New("ssh tunnel needs a database host to forward to")
	}
	if databasePort <= 0 || databasePort > 65535 {
		return nil, fmt.Errorf("ssh tunnel: invalid database port %d", databasePort)
	}

	client, resolved, err := dial(ctx, cfg)
	if err != nil {
		return nil, err
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		client.Close()
		closeAgent(resolved.agentConn)
		return nil, fmt.Errorf("ssh tunnel listener: %w", err)
	}

	ctx, cancel := context.WithCancel(ctx)
	tunnel := &Tunnel{
		cfg:      resolved,
		client:   client,
		listener: listener,
		remote:   net.JoinHostPort(databaseHost, strconv.Itoa(databasePort)),
		ctx:      ctx,
		cancel:   cancel,
	}

	go tunnel.acceptLoop()

	// Tear down with the caller's context, for example when a backup
	// is cancelled. Close is idempotent, so this also runs after the
	// explicit deferred Close.
	go func() {
		<-ctx.Done()
		tunnel.Close()
	}()

	return tunnel, nil
}

// dial resolves cfg (defaults, environment overrides, auth material and
// host key verification) and connects to the bastion. The returned
// client and resolved.agentConn belong to the caller, which must close
// them; on error both are already cleaned up.
func dial(ctx context.Context, cfg Config) (*ssh.Client, Resolved, error) {
	resolved, err := cfg.Resolve()
	if err != nil {
		return nil, Resolved{}, err
	}

	select {
	case <-ctx.Done():
		closeAgent(resolved.agentConn)
		return nil, Resolved{}, ctx.Err()
	default:
	}

	client, err := ssh.Dial(
		"tcp",
		net.JoinHostPort(cfg.Host, strconv.Itoa(resolved.Port)),
		&ssh.ClientConfig{
			User:            resolved.User,
			Auth:            resolved.AuthMethods,
			HostKeyCallback: resolved.HostKeyCallback,
			Timeout:         dialTimeout,
		},
	)
	if err != nil {
		closeAgent(resolved.agentConn)
		return nil, Resolved{}, fmt.Errorf(
			"ssh dial %s@%s:%d: %w",
			resolved.User, cfg.Host, resolved.Port, err,
		)
	}

	return client, resolved, nil
}

func closeAgent(agentConn io.Closer) {
	if agentConn != nil {
		_ = agentConn.Close()
	}
}

// LocalAddr is the local host:port forwarded through the tunnel; a
// connection string can be rewritten to dial it.
func (t *Tunnel) LocalAddr() string {
	return t.listener.Addr().String()
}

// Close stops the tunnel: the listener and the SSH connection are
// closed, and all relays end. Close is idempotent.
func (t *Tunnel) Close() error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil
	}
	t.closed = true
	t.mu.Unlock()

	t.cancel()
	_ = t.listener.Close()
	_ = t.client.Close()
	closeAgent(t.cfg.agentConn)
	t.wg.Wait()
	return nil
}

// acceptLoop relays every connection from the listener through the
// SSH connection. The listener and SSH connection are closed before
// Wait, so every relay ends on its own once its streams break.
func (t *Tunnel) acceptLoop() {
	for {
		local, err := t.listener.Accept()
		if err != nil {
			return
		}

		t.mu.Lock()
		if t.closed {
			t.mu.Unlock()
			local.Close()
			return
		}
		t.wg.Add(2)
		t.mu.Unlock()

		remote, err := t.client.Dial("tcp", t.remote)
		if err != nil {
			local.Close()
			t.wg.Done()
			t.wg.Done()
			continue
		}

		go t.relay(local, remote)
		go t.relay(remote, local)
	}
}

func (t *Tunnel) relay(dst io.WriteCloser, src io.ReadCloser) {
	defer t.wg.Done()
	defer dst.Close()
	defer src.Close()
	_, _ = io.Copy(dst, src)
}
