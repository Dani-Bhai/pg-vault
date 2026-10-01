package docker

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeDocker installs a docker executable for tests: it runs script
// with /bin/sh and puts it first on PATH.
func fakeDocker(t *testing.T, script string) {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "docker")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script+"\n"), 0o755); err != nil {
		t.Fatalf("write fake docker: %v", err)
	}

	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestProfileCommand(t *testing.T) {
	tests := []struct {
		name    string
		profile Profile
		url     string
		wantURL string
		wantErr string
	}{
		{
			name:    "published host port is rewritten",
			profile: Profile{Container: "qa-postgres", Port: 5432},
			url:     "postgres://user:secret@127.0.0.1:9532/qa",
			wantURL: "postgres://user:secret@127.0.0.1:5432/qa",
		},
		{
			name:    "custom container port is kept",
			profile: Profile{Container: "robocalling-postgres", Port: 4532},
			url:     "postgres://user:pass@127.0.0.1:4532/robocalling",
			wantURL: "postgres://user:pass@127.0.0.1:4532/robocalling",
		},
		{
			name:    "keyword value connection string",
			profile: Profile{Container: "postiz-postgres", Port: 5432},
			url:     "host=127.0.0.1 port=9532 user=postiz dbname=postiz",
			wantURL: "host=127.0.0.1 port=5432 user=postiz dbname=postiz",
		},
		{
			name:    "default port",
			profile: Profile{Container: "temporal-postgresql"},
			url:     "postgres://temporal:temporal@127.0.0.1/temporal",
			wantURL: "postgres://temporal:temporal@127.0.0.1:5432/temporal",
		},
		{
			name:    "connection string without a host",
			profile: Profile{Container: "x", Port: 5432},
			url:     "postgres://user:pass@/db",
			wantErr: "rewrite connection string",
		},
		{
			name:    "missing container",
			profile: Profile{Port: 5432},
			url:     "postgres://user:pass@127.0.0.1/db",
			wantErr: "no container configured",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			args, err := test.profile.Command("", test.url)
			if test.wantErr != "" {
				if err == nil {
					t.Fatalf("expected an error containing %q", test.wantErr)
				}
				if !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("error %q: want it to contain %q", err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("command: %v", err)
			}

			if args[0] != "exec" ||
				args[1] != test.profile.Container ||
				args[2] != DefaultPgDump {
				t.Fatalf("unexpected prefix: %v", args[:3])
			}
			if got := args[len(args)-1]; got != test.wantURL {
				t.Fatalf("connection string: got %q, want %q", got, test.wantURL)
			}
		})
	}
}

func TestDumperStreamsArchive(t *testing.T) {
	argsFile := filepath.Join(t.TempDir(), "args")
	t.Setenv("DOCKER_ARGS", argsFile)
	fakeDocker(t, `printf '%s\n' "$@" > "$DOCKER_ARGS"; printf 'archive-bytes'`)

	dumper := &Dumper{
		Profile: Profile{Container: "qa-postgres", Port: 5432},
	}

	var output bytes.Buffer
	err := dumper.Dump(
		context.Background(),
		"postgres://user:secret@127.0.0.1:9532/qa",
		&output,
	)
	if err != nil {
		t.Fatalf("dump: %v", err)
	}
	if output.String() != "archive-bytes" {
		t.Fatalf("output: got %q", output.String())
	}

	raw, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatalf("read captured args: %v", err)
	}
	got := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	want := []string{
		"exec", "qa-postgres", "pg_dump",
		"--format=custom", "--compress=0", "--no-owner", "--no-privileges",
		"postgres://user:secret@127.0.0.1:5432/qa",
	}
	if len(got) != len(want) {
		t.Fatalf("args: got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("args[%d]: got %q, want %q", i, got[i], want[i])
		}
	}
}

func TestHostRunErrorIncludesStderr(t *testing.T) {
	fakeDocker(t, `echo "Error: No such container: missing" >&2; exit 1`)

	_, err := Host{}.Run(context.Background(), "inspect", "missing")
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "docker inspect") ||
		!strings.Contains(err.Error(), "No such container") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestList(t *testing.T) {
	fakeDocker(t, `printf 'qa-postgres\tpostgres:17\t127.0.0.1:9532->5432/tcp\tUp 12 days (healthy)\nrobocalling-postgres-exporter\tprometheuscommunity/postgres-exporter:latest\t9187/tcp\tUp 12 days\n'`)

	containers, err := List(context.Background(), Host{}, false)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(containers) != 1 {
		t.Fatalf("containers: got %d, want 1 (%+v)", len(containers), containers)
	}
	if containers[0].Name != "qa-postgres" ||
		containers[0].Image != "postgres:17" ||
		containers[0].Port != 5432 {
		t.Fatalf("unexpected container: %+v", containers[0])
	}
}

func TestParseContainers(t *testing.T) {
	raw := strings.Join([]string{
		"temporal-postgresql\tpostgres:16\t5432/tcp\tUp 12 days (healthy)",
		"postiz-postgres\tpostgres:17-alpine\t5432/tcp\tUp 12 days (healthy)",
		"robocalling-postgres\tpostgres:17\t0.0.0.0:4532->4532/tcp, [::]:4532->4532/tcp, 5432/tcp\tUp 12 days (healthy)",
		"robocalling-postgres-exporter\tprometheuscommunity/postgres-exporter:latest\t9187/tcp\tUp 12 days",
		"qa-postgres\tpostgres:17\t127.0.0.1:9532->5432/tcp\tUp 12 days (healthy)",
		"chatwoot_docker-postgres-1\tpgvector/pgvector:pg16\t127.0.0.1:5432->5432/tcp\tUp 12 days (healthy)",
	}, "\n")

	containers, err := ParseContainers(raw, false)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(containers) != 5 {
		t.Fatalf("containers: got %d, want 5 (%+v)", len(containers), containers)
	}

	byName := make(map[string]Container)
	for _, container := range containers {
		byName[container.Name] = container
	}

	if container := byName["qa-postgres"]; container.Port != 5432 {
		t.Fatalf("qa-postgres port: got %d", container.Port)
	}
	if container := byName["robocalling-postgres"]; container.Port != 4532 {
		t.Fatalf("robocalling-postgres port: got %d", container.Port)
	}
	if container := byName["temporal-postgresql"]; container.Port != 5432 {
		t.Fatalf("temporal-postgresql port: got %d", container.Port)
	}
	if _, ok := byName["robocalling-postgres-exporter"]; ok {
		t.Fatal("exporter container should be filtered out")
	}

	// The list is sorted by name.
	if containers[0].Name != "chatwoot_docker-postgres-1" {
		t.Fatalf("first container: got %q", containers[0].Name)
	}

	// --all keeps the exporter.
	containers, err = ParseContainers(raw, true)
	if err != nil {
		t.Fatalf("parse all: %v", err)
	}
	if len(containers) != 6 {
		t.Fatalf("containers with --all: got %d, want 6", len(containers))
	}
}

func TestParseContainersRejectsMalformedOutput(t *testing.T) {
	if _, err := ParseContainers("no tabs here", false); err == nil {
		t.Fatal("expected malformed output to be rejected")
	}
}

func TestParsePorts(t *testing.T) {
	tests := []struct {
		ports string
		want  int
		ok    bool
	}{
		{
			ports: "0.0.0.0:4532->4532/tcp, [::]:4532->4532/tcp, 5432/tcp",
			want:  4532,
			ok:    true,
		},
		{ports: "127.0.0.1:9532->5432/tcp", want: 5432, ok: true},
		{ports: "127.0.0.1:5432->5432/tcp, [::]:5432->5432/tcp", want: 5432, ok: true},
		{ports: "5432/tcp", want: 5432, ok: true},
		{ports: "0.0.0.0:9999->9999/tcp", want: 9999, ok: true},
		{ports: "127.0.0.1:5432->5432/tcp, 0.0.0.0:9999->9999/tcp", want: 5432, ok: true},
		{ports: "", ok: false},
		{ports: "127.0.0.1:1234->1234/udp", ok: false},
	}

	for _, test := range tests {
		port, ok := ParsePorts(test.ports)
		if ok != test.ok || port != test.want {
			t.Fatalf("ParsePorts(%q): got (%d, %t), want (%d, %t)",
				test.ports, port, ok, test.want, test.ok)
		}
	}
}

func TestParseInspectPorts(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want int
		ok   bool
	}{
		{
			name: "bound port wins over exposed",
			raw:  `{"4532/tcp":[{"HostIp":"0.0.0.0","HostPort":"4532"}],"5432/tcp":null}`,
			want: 4532,
			ok:   true,
		},
		{
			name: "exposed only",
			raw:  `{"5432/tcp":null}`,
			want: 5432,
			ok:   true,
		},
		{
			name: "prefers 5432 among bound",
			raw:  `{"9999/tcp":[{"HostIp":"127.0.0.1","HostPort":"9999"}],"5432/tcp":[{"HostIp":"127.0.0.1","HostPort":"9532"}]}`,
			want: 5432,
			ok:   true,
		},
		{name: "no ports", raw: `{}`, ok: false},
		{name: "null", raw: `null`, ok: false},
		{name: "garbage", raw: `not json`, ok: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			port, ok := ParseInspectPorts([]byte(test.raw))
			if ok != test.ok || port != test.want {
				t.Fatalf("got (%d, %t), want (%d, %t)", port, ok, test.want, test.ok)
			}
		})
	}
}

func TestSuggestName(t *testing.T) {
	tests := map[string]string{
		"temporal-postgresql":        "temporal",
		"postiz-postgres":            "postiz",
		"robocalling-postgres":       "robocalling",
		"qa-postgres":                "qa",
		"chatwoot_docker-postgres-1": "chatwoot",
		"production":                 "production",
		"db2":                        "db2",
		"postgres-1":                 "postgres",
	}

	for container, want := range tests {
		if got := SuggestName(container); got != want {
			t.Fatalf("SuggestName(%q): got %q, want %q", container, got, want)
		}
	}
}
