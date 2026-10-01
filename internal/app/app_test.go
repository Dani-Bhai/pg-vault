package app

import (
	"testing"

	"github.com/Dani-Bhai/pg-vault/internal/docker"
	"github.com/Dani-Bhai/pg-vault/internal/metadata"
	"github.com/Dani-Bhai/pg-vault/internal/postgres"
)

func TestSelectDumper(t *testing.T) {
	// No profiles: local pg_dump.
	if _, ok := selectDumper(nil, nil).(*postgres.LocalDumper); !ok {
		t.Fatal("expected a local dumper")
	}

	// A tunnel without a container is handled by the caller's port
	// forward, so pg_dump stays local.
	tunnel := &metadata.Tunnel{Host: "bastion", Port: 22, AuthMethod: "agent"}
	if _, ok := selectDumper(tunnel, nil).(*postgres.LocalDumper); !ok {
		t.Fatal("expected a local dumper with a tunnel")
	}

	// A container without a tunnel means local docker exec.
	container := &metadata.Docker{
		Container: "qa-postgres",
		Host:      "127.0.0.1",
		Port:      5432,
	}
	dumper, ok := selectDumper(nil, container).(*docker.Dumper)
	if !ok {
		t.Fatal("expected a docker dumper")
	}
	if dumper.Host.Tunnel != nil {
		t.Fatal("local docker dumper must not have a tunnel")
	}
	if dumper.Profile.Container != "qa-postgres" || dumper.Profile.Port != 5432 {
		t.Fatalf("unexpected profile: %+v", dumper.Profile)
	}

	// A container and a tunnel means docker exec on the bastion.
	dumper, ok = selectDumper(tunnel, container).(*docker.Dumper)
	if !ok {
		t.Fatal("expected a docker dumper")
	}
	if dumper.Host.Tunnel == nil {
		t.Fatal("expected the bastion to run docker")
	}
	if dumper.Host.Tunnel.Host != "bastion" ||
		dumper.Host.Tunnel.Port != 22 {
		t.Fatalf("unexpected tunnel config: %+v", dumper.Host.Tunnel)
	}
}
