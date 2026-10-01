// Package docker runs PostgreSQL client commands inside a Docker
// container, either on this machine or on an SSH bastion. pgvault uses
// it to back up databases whose host has no pg_dump, which is the case
// when PostgreSQL itself runs in a container.
package docker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/Dani-Bhai/pg-vault/internal/postgres"
	"github.com/Dani-Bhai/pg-vault/internal/sshtunnel"
)

const (
	// DefaultHost is the address pg_dump connects to inside the
	// container.
	DefaultHost = "127.0.0.1"
	// DefaultPort is PostgreSQL's port inside the container.
	DefaultPort = 5432
	// DefaultBinary is the docker CLI name.
	DefaultBinary = "docker"
	// DefaultPgDump is the pg_dump binary name inside the container.
	DefaultPgDump = "pg_dump"
)

// Host runs docker commands locally, or on an SSH bastion when Tunnel
// is set.
type Host struct {
	Tunnel *sshtunnel.Config
	Binary string
}

func (h Host) binary() string {
	if h.Binary != "" {
		return h.Binary
	}
	return DefaultBinary
}

// Run runs "docker args..." and returns its stdout. On failure the
// returned error carries the command's stderr.
func (h Host) Run(ctx context.Context, args ...string) ([]byte, error) {
	var stdout, stderr bytes.Buffer

	if err := h.run(ctx, args, &stdout, &stderr); err != nil {
		return nil, commandError(args, err, stderr.String())
	}

	return stdout.Bytes(), nil
}

// Stream runs "docker args..." streaming its stdout to writer; stderr
// is kept for error reporting.
func (h Host) Stream(
	ctx context.Context,
	args []string,
	writer io.Writer,
) error {
	var stderr bytes.Buffer

	if err := h.run(ctx, args, writer, &stderr); err != nil {
		return commandError(args, err, stderr.String())
	}

	return nil
}

func (h Host) run(
	ctx context.Context,
	args []string,
	stdout, stderr io.Writer,
) error {
	if len(args) == 0 {
		return errors.New("docker: empty command")
	}

	argv := append([]string{h.binary()}, args...)

	if h.Tunnel != nil {
		return sshtunnel.Exec(
			ctx,
			*h.Tunnel,
			sshtunnel.ShellJoin(argv),
			stdout,
			stderr,
		)
	}

	return postgres.RunCommand(ctx, argv[0], argv[1:], stdout, stderr)
}

// commandError annotates a failed docker invocation with its stderr.
func commandError(args []string, err error, stderr string) error {
	prefix := "docker"
	if len(args) > 0 {
		prefix += " " + args[0]
		if args[0] == "exec" && len(args) > 1 {
			prefix += " " + args[1]
		}
	}

	if message := strings.TrimSpace(stderr); message != "" {
		return fmt.Errorf("%s: %w: %s", prefix, err, message)
	}
	return fmt.Errorf("%s: %w", prefix, err)
}

// Profile describes where PostgreSQL listens inside a container.
type Profile struct {
	Container string // container name or ID
	Host      string // address inside the container, default 127.0.0.1
	Port      int    // port inside the container, default 5432
}

func (p Profile) host() string {
	if p.Host == "" {
		return DefaultHost
	}
	return p.Host
}

func (p Profile) port() int {
	if p.Port == 0 {
		return DefaultPort
	}
	return p.Port
}

// Command returns the docker arguments for one dump: the connection
// string is rewritten to the container-internal address, and the
// custom-format options are shared with the local dumper.
func (p Profile) Command(pgDump, databaseURL string) ([]string, error) {
	if p.Container == "" {
		return nil, errors.New("docker: no container configured")
	}
	if pgDump == "" {
		pgDump = DefaultPgDump
	}

	inner, err := postgres.RewriteEndpoint(
		databaseURL,
		net.JoinHostPort(p.host(), strconv.Itoa(p.port())),
	)
	if err != nil {
		return nil, fmt.Errorf(
			"rewrite connection string for container %s: %w",
			p.Container, err,
		)
	}

	args := []string{"exec", p.Container, pgDump}
	return append(args, postgres.DumpArgs(inner)...), nil
}

// Dumper implements postgres.Dumper by running pg_dump inside a
// container.
type Dumper struct {
	Host    Host
	Profile Profile
	PgDump  string
}

// Dump streams a custom-format archive out of the container.
func (d *Dumper) Dump(
	ctx context.Context,
	databaseURL string,
	writer io.Writer,
) error {
	args, err := d.Profile.Command(d.PgDump, databaseURL)
	if err != nil {
		return err
	}

	return d.Host.Stream(ctx, args, writer)
}

// DetectPort returns the container-side TCP port PostgreSQL listens
// on, inspecting the container through host. Published bindings win
// over ports the image merely exposes.
func DetectPort(
	ctx context.Context,
	host Host,
	container string,
) (int, error) {
	output, err := host.Run(
		ctx,
		"inspect",
		"--format",
		"{{json .NetworkSettings.Ports}}",
		container,
	)
	if err != nil {
		return 0, fmt.Errorf("inspect container %s: %w", container, err)
	}

	port, ok := ParseInspectPorts(output)
	if !ok {
		return 0, fmt.Errorf(
			"container %s exposes no TCP port; pass --docker-port",
			container,
		)
	}

	return port, nil
}

// Running reports whether the container exists and is running.
func Running(
	ctx context.Context,
	host Host,
	container string,
) (bool, error) {
	output, err := host.Run(
		ctx,
		"inspect",
		"--format",
		"{{.State.Running}}",
		container,
	)
	if err != nil {
		return false, fmt.Errorf("inspect container %s: %w", container, err)
	}

	return strings.TrimSpace(string(output)) == "true", nil
}

// ParseInspectPorts extracts a port from the JSON output of
// `docker inspect --format '{{json .NetworkSettings.Ports}}'`. The map
// value is null for a port that is merely exposed.
func ParseInspectPorts(raw []byte) (int, bool) {
	var ports map[string][]struct {
		HostIP   string `json:"HostIp"`
		HostPort string `json:"HostPort"`
	}
	if err := json.Unmarshal(raw, &ports); err != nil {
		return 0, false
	}

	var bound, exposed []int
	for key, bindings := range ports {
		port, ok := portFromKey(key)
		if !ok {
			continue
		}
		if len(bindings) > 0 {
			bound = append(bound, port)
		} else {
			exposed = append(exposed, port)
		}
	}

	if port, ok := pickPort(bound); ok {
		return port, true
	}
	return pickPort(exposed)
}

// Container is one docker container as reported by `docker ps`.
type Container struct {
	Name   string
	Image  string
	Ports  string
	Status string
	Port   int // container-side port, 0 when unknown
}

// psFormat is the docker ps template used by List; fields are
// separated by tabs because names and ports may contain spaces.
const psFormat = "{{.Names}}\t{{.Image}}\t{{.Ports}}\t{{.Status}}"

// List returns the postgres containers known to host, or every
// running container when all is set.
func List(ctx context.Context, host Host, all bool) ([]Container, error) {
	output, err := host.Run(ctx, "ps", "--no-trunc", "--format", psFormat)
	if err != nil {
		return nil, fmt.Errorf("list containers: %w", err)
	}

	return ParseContainers(string(output), all)
}

// ParseContainers parses docker ps output produced with psFormat.
func ParseContainers(raw string, all bool) ([]Container, error) {
	var containers []Container

	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		fields := strings.Split(line, "\t")
		if len(fields) != 4 {
			return nil, fmt.Errorf("unexpected docker ps output %q", line)
		}

		container := Container{
			Name:   strings.TrimPrefix(fields[0], "/"),
			Image:  fields[1],
			Ports:  fields[2],
			Status: fields[3],
		}
		if !all && !isPostgresImage(container.Image) {
			continue
		}
		if port, ok := ParsePorts(container.Ports); ok {
			container.Port = port
		}

		containers = append(containers, container)
	}

	sort.Slice(containers, func(i, j int) bool {
		return containers[i].Name < containers[j].Name
	})

	return containers, nil
}

// isPostgresImage reports whether an image looks like a PostgreSQL
// server. Exporter images are excluded: they connect to a server but
// do not run one.
func isPostgresImage(image string) bool {
	lower := strings.ToLower(image)
	if strings.Contains(lower, "exporter") {
		return false
	}

	return strings.Contains(lower, "postgres") ||
		strings.Contains(lower, "pgvector") ||
		strings.Contains(lower, "postgis")
}

// ParsePorts derives the container-side TCP port from the PORTS column
// of docker ps, for example
// "0.0.0.0:4532->4532/tcp, [::]:4532->4532/tcp, 5432/tcp".
// Published bindings win over merely exposed ports.
func ParsePorts(ports string) (int, bool) {
	var bound, exposed []int

	for _, segment := range strings.Split(ports, ",") {
		segment = strings.TrimSpace(segment)
		if segment == "" {
			continue
		}

		containerSide := segment
		published := false
		if _, after, found := strings.Cut(segment, "->"); found {
			containerSide = after
			published = true
		}

		port, ok := portFromKey(containerSide)
		if !ok {
			continue
		}
		if published {
			bound = append(bound, port)
		} else {
			exposed = append(exposed, port)
		}
	}

	if port, ok := pickPort(bound); ok {
		return port, true
	}
	return pickPort(exposed)
}

// portFromKey parses a "5432/tcp" key.
func portFromKey(key string) (int, bool) {
	number, protocol, found := strings.Cut(strings.TrimSpace(key), "/")
	if !found || protocol != "tcp" {
		return 0, false
	}

	port, err := strconv.Atoi(number)
	if err != nil || port <= 0 || port > 65535 {
		return 0, false
	}

	return port, true
}

// pickPort prefers 5432, then the lowest port.
func pickPort(ports []int) (int, bool) {
	if len(ports) == 0 {
		return 0, false
	}

	best := ports[0]
	for _, port := range ports {
		if port == DefaultPort {
			return port, true
		}
		if port < best {
			best = port
		}
	}
	return best, true
}

// SuggestName turns a container name into a short database name:
// "temporal-postgresql" -> "temporal", "chatwoot_docker-postgres-1" ->
// "chatwoot".
func SuggestName(container string) string {
	name := container

	if index := strings.Index(strings.ToLower(name), "_docker-postgres"); index > 0 {
		return name[:index]
	}

	suffixes := []string{
		"-postgresql", "-postgres", "_postgresql", "_postgres",
		"-postgis", "-pg", "-db",
	}
	for {
		trimmed := name
		for _, suffix := range suffixes {
			if strings.HasSuffix(strings.ToLower(trimmed), suffix) {
				trimmed = trimmed[:len(trimmed)-len(suffix)]
				break
			}
		}
		if trimmed == name {
			break
		}
		name = trimmed
	}

	// Strip a compose-style numeric suffix ("postgres-1") but keep
	// names such as "db2" intact.
	if index := strings.LastIndexAny(name, "-_"); index > 0 {
		if _, err := strconv.Atoi(name[index+1:]); err == nil {
			name = name[:index]
		}
	}

	if name == "" {
		return container
	}
	return name
}
