package postgres

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"
)

func TestParseEndpoint(t *testing.T) {
	tests := []struct {
		connectionString string
		host             string
		port             int
		error            string
	}{
		{
			connectionString: "postgres://vault:secret@db.internal:5432/app",
			host:             "db.internal",
			port:             5432,
		},
		{
			connectionString: "postgresql://vault@db.internal/app",
			host:             "db.internal",
			port:             defaultPort,
		},
		{
			connectionString: "postgres://db.internal/app",
			host:             "db.internal",
			port:             defaultPort,
		},
		{
			// hostaddr wins over host, matching libpq.
			connectionString: "postgres://db.internal/app?hostaddr=10.1.2.3",
			host:             "10.1.2.3",
			port:             defaultPort,
		},
		{
			connectionString: "postgres://?host=db.internal&port=5433&user=vault&dbname=app",
			host:             "db.internal",
			port:             5433,
		},
		{
			connectionString: "host=db.internal port=5432 user=vault password=secret dbname=app",
			host:             "db.internal",
			port:             5432,
		},
		{
			// Later occurrences win, matching libpq.
			connectionString: "host=wrong port=1 host=db.internal port=5432",
			host:             "db.internal",
			port:             5432,
		},
		{
			connectionString: "host='db internal' port=5432",
			host:             "db internal",
			port:             5432,
		},
		{
			connectionString: "hostaddr=10.1.2.3 host=db.internal port=5432",
			host:             "10.1.2.3",
			port:             5432,
		},
		{
			connectionString: `host=ho\ st`,
			host:             "ho st",
			port:             defaultPort,
		},
		{
			connectionString: "postgres://a.one:5432,b.two:5432/app",
			error:            "multiple hosts",
		},
		{
			connectionString: "host=one,two port=5432",
			error:            "multiple hosts",
		},
		{
			connectionString: "postgres:///app?host=/var/run/postgresql",
			error:            "unix socket",
		},
		{
			connectionString: "dbname=app",
			error:            "no host",
		},
		{
			connectionString: "http://example.com/app",
			error:            "not a postgres scheme",
		},
		{
			connectionString: "not a connection string",
			error:            "expected keyword=value",
		},
		{
			connectionString: "port=5432 dbname=app host=",
			error:            "no host",
		},
		{
			connectionString: "host=db port=99999",
			error:            "invalid port",
		},
	}

	for _, test := range tests {
		t.Run(test.connectionString, func(t *testing.T) {
			endpoint, err := ParseEndpoint(test.connectionString)
			if test.error != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got %v", test.error, endpoint)
				}
				if !strings.Contains(err.Error(), test.error) {
					t.Fatalf("error %q: want it to contain %q", err, test.error)
				}
				return
			}
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if endpoint.Host != test.host || endpoint.Port != test.port {
				t.Fatalf("got (%q, %d), want (%q, %d)",
					endpoint.Host, endpoint.Port, test.host, test.port)
			}
		})
	}
}

func TestRewriteEndpointURL(t *testing.T) {
	tests := []struct {
		name             string
		connectionString string
		localAddr        string
		want             string
	}{
		{
			name:             "authority host and port replaced",
			connectionString: "postgres://vault:secret@db.internal:5432/app?sslmode=require",
			localAddr:        "127.0.0.1:49152",
			want:             "postgres://vault:secret@127.0.0.1:49152/app?sslmode=require",
		},
		{
			name:             "missing port is added",
			connectionString: "postgresql://vault@db.internal/app",
			localAddr:        "127.0.0.1:49152",
			want:             "postgresql://vault@127.0.0.1:49152/app",
		},
		{
			name:             "query only host",
			connectionString: "postgres://?host=db.internal&port=5432&user=vault&dbname=app",
			localAddr:        "127.0.0.1:49152",
			want:             "postgres://?dbname=app&host=127.0.0.1&port=49152&user=vault",
		},
		{
			// hostaddr is rewritten, host is kept for TLS host
			// name verification.
			name:             "hostaddr rewritten, host kept",
			connectionString: "postgres://db.internal:5432/app?hostaddr=10.1.2.3&sslmode=verify-full",
			localAddr:        "127.0.0.1:49152",
			want:             "postgres://db.internal:49152/app?hostaddr=127.0.0.1&sslmode=verify-full",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := RewriteEndpoint(test.connectionString, test.localAddr)
			if err != nil {
				t.Fatalf("rewrite: %v", err)
			}
			if got != test.want {
				t.Fatalf("got %q, want %q", got, test.want)
			}

			// The rewritten string must now connect to the local
			// address.
			endpoint, err := ParseEndpoint(got)
			if err != nil {
				t.Fatalf("parse rewritten: %v", err)
			}
			host, port := splitAddr(test.localAddr)
			if endpoint.Host != host || endpoint.Port != port {
				t.Fatalf("rewritten endpoint (%q, %d), want (%q, %d)",
					endpoint.Host, endpoint.Port, host, port)
			}
		})
	}
}

func TestRewriteEndpointParams(t *testing.T) {
	tests := []struct {
		name             string
		connectionString string
		localAddr        string
		want             string
	}{
		{
			name:             "plain values",
			connectionString: "host=db.internal port=5432 user=vault password=secret dbname=app",
			localAddr:        "127.0.0.1:49152",
			want:             "host=127.0.0.1 port=49152 user=vault password=secret dbname=app",
		},
		{
			name:             "quoted value keeps its quotes",
			connectionString: "host='db internal' port=5432 dbname=app",
			localAddr:        "127.0.0.1:49152",
			want:             "host='127.0.0.1' port=49152 dbname=app",
		},
		{
			name:             "escaped value is replaced",
			connectionString: `host=ho\ st port=5432`,
			localAddr:        "127.0.0.1:49152",
			want:             "host=127.0.0.1 port=49152",
		},
		{
			// hostaddr is rewritten, host is kept for TLS host
			// name verification.
			name:             "hostaddr rewritten, host kept",
			connectionString: "host=db.internal hostaddr=10.1.2.3 port=5432 sslmode=verify-full",
			localAddr:        "127.0.0.1:49152",
			want:             "host=db.internal hostaddr=127.0.0.1 port=49152 sslmode=verify-full",
		},
		{
			// Without a port parameter, one must be appended so
			// libpq does not dial the default 5432.
			name:             "missing port is appended",
			connectionString: "host=db.internal dbname=app",
			localAddr:        "127.0.0.1:49152",
			want:             "host=127.0.0.1 dbname=app port=49152",
		},
		{
			// Everything else must be preserved byte for byte,
			// including surrounding whitespace.
			name:             "whitespace preserved",
			connectionString: "host = db.internal   port = 5432   sslmode = require",
			localAddr:        "127.0.0.1:49152",
			want:             "host = 127.0.0.1   port = 49152   sslmode = require",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := RewriteEndpoint(test.connectionString, test.localAddr)
			if err != nil {
				t.Fatalf("rewrite: %v", err)
			}
			if got != test.want {
				t.Fatalf("got %q, want %q", got, test.want)
			}

			endpoint, err := ParseEndpoint(got)
			if err != nil {
				t.Fatalf("parse rewritten: %v", err)
			}
			host, port := splitAddr(test.localAddr)
			if endpoint.Host != host || endpoint.Port != port {
				t.Fatalf("rewritten endpoint (%q, %d), want (%q, %d)",
					endpoint.Host, endpoint.Port, host, port)
			}
		})
	}
}

func TestRewriteEndpointErrors(t *testing.T) {
	tests := []struct {
		connectionString string
		error            string
	}{
		{connectionString: "dbname=app", error: "no host"},
		{connectionString: "host=one,two", error: "multiple hosts"},
		{connectionString: "http://example.com", error: "not a postgres scheme"},
	}

	for _, test := range tests {
		t.Run(test.connectionString, func(t *testing.T) {
			if _, err := RewriteEndpoint(test.connectionString, "127.0.0.1:49152"); err == nil {
				t.Fatal("expected an error")
			} else if !strings.Contains(err.Error(), test.error) {
				t.Fatalf("error %q: want it to contain %q", err, test.error)
			}
		})
	}

	if _, err := RewriteEndpoint("host=db", "no-port-here"); err == nil {
		t.Fatal("expected invalid local address to be rejected")
	} else if !strings.Contains(err.Error(), "not host:port") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func splitAddr(addr string) (string, int) {
	host, portString, err := net.SplitHostPort(addr)
	if err != nil {
		panic(fmt.Sprintf("test address %q: %v", addr, err))
	}
	port, err := strconv.Atoi(portString)
	if err != nil {
		panic(fmt.Sprintf("test address %q: %v", addr, err))
	}
	return host, port
}
