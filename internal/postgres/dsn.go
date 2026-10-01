// Helpers for libpq connection strings. pg_dump and pg_restore receive
// the registered connection string as-is, so tunneling rewrites it:
// the connect address is replaced by the local end of an SSH tunnel
// while everything else (user, password, dbname, sslmode, ...) is
// preserved.
package postgres

import (
	"bytes"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// defaultPort is libpq's fallback when a connection string sets none.
const defaultPort = 5432

// Endpoint is the address a connection string connects to.
type Endpoint struct {
	Host string
	Port int
}

// ParseEndpoint returns the address a connection string connects to,
// following libpq's resolution: hostaddr wins over host, and the port
// defaults to 5432.
func ParseEndpoint(connectionString string) (Endpoint, error) {
	info, err := parseConnectionString(connectionString)
	if err != nil {
		return Endpoint{}, err
	}
	return info.endpoint()
}

// RewriteEndpoint returns connectionString with its connect address
// replaced by localAddr, a host:port pair such as the local end of a
// tunnel. When the connection string uses hostaddr, hostaddr is
// rewritten and host is kept so TLS host name verification keeps
// working through the tunnel.
func RewriteEndpoint(connectionString, localAddr string) (string, error) {
	info, err := parseConnectionString(connectionString)
	if err != nil {
		return "", err
	}

	// Validate first: rewriting must not silently succeed where
	// connecting would fail anyway.
	if _, err := info.endpoint(); err != nil {
		return "", err
	}

	localHost, localPort, err := splitLocalAddr(localAddr)
	if err != nil {
		return "", err
	}

	if info.isURL {
		return rewriteURL(info.u, localHost, localPort)
	}
	return rewriteParams(info.raw, info.params, localHost, localPort)
}

// connectionInfo is a parsed connection string in either form libpq
// accepts: a postgres:// URL or "keyword=value" parameters.
type connectionInfo struct {
	isURL  bool
	u      *url.URL
	raw    string
	params []param
}

// param is one "keyword=value" pair. value is unescaped; rawEnd is the
// exclusive byte offset of the value inside the original string,
// without any surrounding quote.
type param struct {
	key        string
	value      string
	valueStart int
	rawEnd     int
}

func parseConnectionString(connectionString string) (connectionInfo, error) {
	trimmed := strings.TrimLeft(connectionString, " \t\n\r")
	if looksLikeURL(trimmed) {
		u, err := url.Parse(trimmed)
		if err != nil {
			return connectionInfo{}, fmt.Errorf("invalid connection URL: %w", err)
		}
		if u.Scheme != "postgres" && u.Scheme != "postgresql" {
			return connectionInfo{}, fmt.Errorf(
				"connection URL scheme %q is not a postgres scheme",
				u.Scheme,
			)
		}
		return connectionInfo{isURL: true, u: u}, nil
	}

	params, err := parseParams(connectionString)
	if err != nil {
		return connectionInfo{}, err
	}
	return connectionInfo{raw: connectionString, params: params}, nil
}

// looksLikeURL reports whether a string starts with a "scheme://"
// prefix, so a non-postgres scheme gets a clear error instead of a
// confusing keyword/value parse failure.
func looksLikeURL(s string) bool {
	scheme, _, found := strings.Cut(s, "://")
	if !found || scheme == "" {
		return false
	}
	for i := 0; i < len(scheme); i++ {
		c := scheme[i]
		if !('a' <= c && c <= 'z') && !('A' <= c && c <= 'Z') &&
			!('0' <= c && c <= '9') && c != '+' && c != '-' && c != '.' {
			return false
		}
	}
	return true
}

// endpoint resolves the connect address. hostaddr takes precedence
// over host, and a missing port falls back to libpq's default.
func (c connectionInfo) endpoint() (Endpoint, error) {
	host, port, err := c.hostAndPort()
	if err != nil {
		return Endpoint{}, err
	}

	if strings.Contains(host, ",") {
		return Endpoint{}, fmt.Errorf(
			"connection string lists multiple hosts (%s); tunneling supports a single host",
			host,
		)
	}
	if strings.HasPrefix(host, "/") {
		return Endpoint{}, fmt.Errorf(
			"connection string uses a unix socket (%s); tunneling needs a TCP host",
			host,
		)
	}

	return Endpoint{Host: host, Port: port}, nil
}

func (c connectionInfo) hostAndPort() (host string, port int, err error) {
	if c.isURL {
		return c.urlHostAndPort()
	}
	return c.paramsHostAndPort()
}

func (c connectionInfo) urlHostAndPort() (host string, port int, err error) {
	query := c.u.Query()

	hostaddr := query.Get("hostaddr")
	authorityHost := c.u.Hostname()
	queryHost := query.Get("host")

	if authorityHost != "" && queryHost != "" {
		return "", 0, fmt.Errorf(
			"connection URL sets host both in the authority part and as a query parameter",
		)
	}

	portValue := query.Get("port")
	if portValue == "" {
		portValue = c.u.Port()
	}

	host = hostaddr
	if host == "" {
		host = queryHost
	}
	if host == "" {
		host = authorityHost
	}
	if host == "" {
		return "", 0, fmt.Errorf("connection URL has no host")
	}

	port, err = portValueOr(portValue, defaultPort)
	if err != nil {
		return "", 0, err
	}
	return host, port, nil
}

func (c connectionInfo) paramsHostAndPort() (host string, port int, err error) {
	var hostValue, hostaddrValue, portValue string
	for _, param := range c.params {
		// Later occurrences win, matching libpq's conninfo
		// parsing.
		switch param.key {
		case "host":
			hostValue = param.value
		case "hostaddr":
			hostaddrValue = param.value
		case "port":
			portValue = param.value
		}
	}

	host = hostaddrValue
	if host == "" {
		host = hostValue
	}
	if host == "" {
		return "", 0, fmt.Errorf(
			"connection string has no host (unix sockets cannot be tunneled)",
		)
	}

	port, err = portValueOr(portValue, defaultPort)
	if err != nil {
		return "", 0, err
	}
	return host, port, nil
}

func portValueOr(value string, fallback int) (int, error) {
	if value == "" {
		return fallback, nil
	}
	port, err := strconv.Atoi(value)
	if err != nil || port <= 0 || port > 65535 {
		return 0, fmt.Errorf("invalid port %q", value)
	}
	return port, nil
}

func splitLocalAddr(localAddr string) (host string, port int, err error) {
	host, portString, err := net.SplitHostPort(localAddr)
	if err != nil {
		return "", 0, fmt.Errorf("local address %q is not host:port", localAddr)
	}
	port, err = strconv.Atoi(portString)
	if err != nil {
		return "", 0, fmt.Errorf("local address %q has an invalid port", localAddr)
	}
	return host, port, nil
}

// rewriteURL rebuilds a connection URL with its connect address
// pointing at the tunnel. Query parameters are re-encoded, which is
// equivalent to the original parameters.
func rewriteURL(u *url.URL, localHost string, localPort int) (string, error) {
	localPortString := strconv.Itoa(localPort)
	authorityHost := u.Hostname()
	authorityPort := u.Port()
	query := u.Query()
	changed := false

	switch {
	case query.Get("hostaddr") != "":
		// hostaddr is the connect address; host stays for TLS
		// host name verification through the tunnel.
		query.Set("hostaddr", localHost)
		changed = true
		if authorityHost != "" {
			u.Host = net.JoinHostPort(authorityHost, localPortString)
		}
		if query.Has("port") || authorityPort == "" {
			// Without this, libpq would dial the default 5432
			// instead of the tunnel.
			query.Set("port", localPortString)
		}
	case authorityHost != "":
		u.Host = net.JoinHostPort(localHost, localPortString)
	case query.Has("host"):
		// No authority part; the host comes from the query.
		query.Set("host", localHost)
		query.Set("port", localPortString)
		changed = true
	default:
		return "", fmt.Errorf("connection URL has no host")
	}

	if changed {
		u.RawQuery = query.Encode()
	}

	result := u.String()
	if !strings.HasPrefix(result, u.Scheme+"://") {
		// An empty authority is rendered without "//" by net/url,
		// but libpq's URI grammar requires it
		// (postgres://?host=...).
		result = u.Scheme + "://" + result[len(u.Scheme)+1:]
	}

	return result, nil
}

// rewriteParams rebuilds a keyword/value connection string, replacing
// only the raw value spans of host, hostaddr and port.
func rewriteParams(
	raw string,
	params []param,
	localHost string,
	localPort int,
) (string, error) {
	localPortString := strconv.Itoa(localPort)

	var (
		host      *param
		hostaddr  *param
		portParam *param
	)
	for i := range params {
		// Later occurrences win, matching libpq's conninfo
		// parsing.
		switch params[i].key {
		case "host":
			host = &params[i]
		case "hostaddr":
			hostaddr = &params[i]
		case "port":
			portParam = &params[i]
		}
	}

	replaced := make(map[*param]string)
	switch {
	case hostaddr != nil && host != nil:
		// Keep host for TLS host name verification.
		replaced[hostaddr] = localHost
	case host != nil:
		replaced[host] = localHost
	case hostaddr != nil:
		replaced[hostaddr] = localHost
	default:
		return "", fmt.Errorf(
			"connection string has no host (unix sockets cannot be tunneled)",
		)
	}

	if portParam != nil {
		replaced[portParam] = localPortString
	}

	out := bytes.NewBuffer(make([]byte, 0, len(raw)+32))
	position := 0
	for i := range params {
		value, ok := replaced[&params[i]]
		if !ok {
			continue
		}
		out.WriteString(raw[position:params[i].valueStart])
		out.WriteString(value)
		position = params[i].rawEnd
	}
	out.WriteString(raw[position:])

	if portParam == nil {
		// The rewritten connect address needs an explicit port;
		// libpq would otherwise dial the default 5432.
		out.WriteString(" port=" + localPortString)
	}

	return out.String(), nil
}

// parseParams parses a libpq "keyword=value" connection string with
// libpq's escaping rules: values may be single-quoted, and a backslash
// escapes the next character both inside and outside quotes.
func parseParams(raw string) ([]param, error) {
	var params []param

	position := 0
	for position < len(raw) {
		// Skip leading whitespace.
		for position < len(raw) && isSpace(raw[position]) {
			position++
		}
		if position == len(raw) {
			break
		}

		// Keyword: everything up to whitespace or '='.
		keyStart := position
		for position < len(raw) && !isSpace(raw[position]) && raw[position] != '=' {
			position++
		}
		key := raw[keyStart:position]
		if key == "" {
			return nil, fmt.Errorf("invalid connection parameter: empty keyword")
		}

		for position < len(raw) && isSpace(raw[position]) {
			position++
		}
		if position == len(raw) || raw[position] != '=' {
			return nil, fmt.Errorf(
				"invalid connection parameter %q (expected keyword=value)",
				strings.TrimSpace(raw[keyStart:min(position+32, len(raw))]),
			)
		}
		position++ // consume '='

		for position < len(raw) && isSpace(raw[position]) {
			position++
		}

		// The value may be empty, matching libpq ("host=" is an
		// empty host, which resolves to a unix socket).
		valueStart := position
		if position < len(raw) && raw[position] == '\'' {
			// The opening quote must survive span replacement,
			// so the raw value starts after it.
			valueStart++
		}
		var (
			value    string
			valueEnd = position
			rawEnd   = position
		)
		if position < len(raw) {
			var err error
			value, valueEnd, rawEnd, err = scanParamValue(raw, position)
			if err != nil {
				return nil, err
			}
		}
		position = valueEnd

		params = append(params, param{
			key:        key,
			value:      value,
			valueStart: valueStart,
			rawEnd:     rawEnd,
		})
	}

	return params, nil
}

// scanParamValue reads one value starting at start and returns its
// unescaped form, the index just past the value, and the exclusive
// end of the raw value (the closing quote, when quoted, stays outside
// the range).
func scanParamValue(raw string, start int) (value string, valueEnd int, rawEnd int, err error) {
	if raw[start] == '\'' {
		// Quoted: read to the closing unescaped quote.
		var out strings.Builder
		position := start + 1
		for position < len(raw) {
			switch raw[position] {
			case '\\':
				if position+1 >= len(raw) {
					return "", 0, 0, fmt.Errorf("unterminated escape in connection string")
				}
				out.WriteByte(raw[position+1])
				position += 2
			case '\'':
				return out.String(), position + 1, position, nil
			default:
				out.WriteByte(raw[position])
				position++
			}
		}
		return "", 0, 0, fmt.Errorf("unterminated quoted value in connection string")
	}

	// Unquoted: read to whitespace, honoring backslash escapes.
	var out strings.Builder
	position := start
	for position < len(raw) {
		switch {
		case isSpace(raw[position]):
			return out.String(), position, position, nil
		case raw[position] == '\\':
			if position+1 >= len(raw) {
				return "", 0, 0, fmt.Errorf("unterminated escape in connection string")
			}
			out.WriteByte(raw[position+1])
			position += 2
		default:
			out.WriteByte(raw[position])
			position++
		}
	}
	return out.String(), position, position, nil
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}
