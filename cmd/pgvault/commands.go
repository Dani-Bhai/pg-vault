package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/spf13/pflag"

	"github.com/Dani-Bhai/pg-vault/internal/app"
	"github.com/Dani-Bhai/pg-vault/internal/archive"
	"github.com/Dani-Bhai/pg-vault/internal/backup"
	"github.com/Dani-Bhai/pg-vault/internal/docker"
	"github.com/Dani-Bhai/pg-vault/internal/metadata"
	"github.com/Dani-Bhai/pg-vault/internal/scheduler"
	"github.com/Dani-Bhai/pg-vault/internal/sshtunnel"
	"github.com/Dani-Bhai/pg-vault/internal/storage"
)

var errHelp = errors.New("help requested")

func openApp(fn func(*app.App) error) error {
	a, err := app.Open()
	if err != nil {
		return err
	}
	defer a.Close()
	return fn(a)
}

func newFlagSet(name string) *pflag.FlagSet {
	fs := pflag.NewFlagSet(name, pflag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

func parseFlags(fs *pflag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, pflag.ErrHelp) {
			// Each command's flag set is named after its help
			// topic, so --help prints the right page.
			if !printTopic(helpWriter, fs.Name()) {
				printGlobalHelp(helpWriter)
			}
			return errHelp
		}
		return err
	}
	return nil
}

// flagsChanged reports whether any flag whose name starts with prefix
// was set on the command line.
func flagsChanged(fs *pflag.FlagSet, prefix string) bool {
	changed := false
	fs.Visit(func(flag *pflag.Flag) {
		if strings.HasPrefix(flag.Name, prefix) {
			changed = true
		}
	})
	return changed
}

// dockerFlags collects the --docker-* flags shared by add and docker.
type dockerFlags struct {
	container string
	port      int
}

func addDockerFlags(fs *pflag.FlagSet, f *dockerFlags) {
	fs.StringVar(&f.container, "docker", "",
		"run pg_dump inside this container")
	fs.IntVar(&f.port, "docker-port", 0,
		"postgres port inside the container (default 5432, or detected)")
}

// dockerHost builds the docker command runner for a database; a tunnel
// profile means the docker host is the ssh bastion.
func dockerHost(tunnel *metadata.Tunnel) docker.Host {
	host := docker.Host{}
	if tunnel != nil {
		cfg := app.TunnelConfig(tunnel)
		host.Tunnel = &cfg
	}
	return host
}

// resolveDockerPort validates an explicit container port, or detects it
// through the docker host. Detection is best-effort: on failure the
// default port is used with a note.
func resolveDockerPort(
	ctx context.Context,
	container string,
	port int,
	host docker.Host,
) (int, error) {
	if port != 0 {
		if port < 1 || port > 65535 {
			return 0, fmt.Errorf("--docker-port: invalid port %d", port)
		}
		return port, nil
	}

	detected, err := docker.DetectPort(ctx, host, container)
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"pgvault: note: could not detect the container port (%v); using %d\n",
			err,
			docker.DefaultPort,
		)
		return docker.DefaultPort, nil
	}

	if detected != docker.DefaultPort {
		fmt.Fprintf(os.Stderr,
			"pgvault: note: detected port %d inside %s\n",
			detected,
			container,
		)
	}
	return detected, nil
}

// dockerProfile validates the flags and resolves them into a stored
// container profile.
func dockerProfile(
	ctx context.Context,
	flags dockerFlags,
	databaseID string,
	tunnel *metadata.Tunnel,
) (metadata.Docker, error) {
	if strings.TrimSpace(flags.container) == "" {
		return metadata.Docker{}, errors.New(
			"--docker is required: <container name or id>",
		)
	}

	port, err := resolveDockerPort(
		ctx,
		flags.container,
		flags.port,
		dockerHost(tunnel),
	)
	if err != nil {
		return metadata.Docker{}, err
	}

	return metadata.Docker{
		DatabaseID: databaseID,
		Container:  flags.container,
		Host:       docker.DefaultHost,
		Port:       port,
	}, nil
}

// inspectContext bounds the docker host inspections done while
// configuring a database; backups themselves are not bounded here.
func inspectContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 30*time.Second)
}

// tunnelFlags collects the --tunnel-* flags shared by add and tunnel.
type tunnelFlags struct {
	via           string
	user          string
	port          int
	auth          string
	key           string
	keyPassphrase string
	password      string
	knownHosts    string
	insecure      bool
}

func addTunnelFlags(fs *pflag.FlagSet, f *tunnelFlags) {
	fs.StringVar(&f.via, "tunnel", "",
		"back up through an ssh bastion: [user@]host[:port]")
	fs.StringVar(&f.user, "tunnel-user", "",
		"ssh user for the bastion (or user@ in --tunnel)")
	fs.IntVar(&f.port, "tunnel-port", 0,
		"ssh port of the bastion (or :port in --tunnel)")
	fs.StringVar(&f.auth, "tunnel-auth", "auto",
		"bastion authentication: auto, password, key or agent")
	fs.StringVar(&f.key, "tunnel-key", "",
		"path to a private key for the bastion")
	fs.StringVar(&f.keyPassphrase, "tunnel-key-passphrase", "",
		"passphrase for --tunnel-key (prefer PGVAULT_SSH_KEY_PASSPHRASE)")
	fs.StringVar(&f.password, "tunnel-password", "",
		"password for the bastion (prefer PGVAULT_SSH_PASSWORD)")
	fs.StringVar(&f.knownHosts, "tunnel-known-hosts", "",
		"known_hosts file to verify the bastion (default ~/.ssh/known_hosts)")
	fs.BoolVar(&f.insecure, "tunnel-insecure", false,
		"skip ssh host key verification (insecure)")
}

// spec turns the flags into a stored tunnel profile for a database.
// Structurally invalid combinations fail; things that may only become
// available at backup time (a password from the environment) print a
// note instead.
func (f *tunnelFlags) spec(databaseID string) (metadata.Tunnel, error) {
	if f.via == "" {
		return metadata.Tunnel{}, errors.New(
			"--tunnel is required: [user@]host[:port]",
		)
	}

	specUser, host, port, err := sshtunnel.ParseTarget(f.via)
	if err != nil {
		return metadata.Tunnel{}, fmt.Errorf("--tunnel: %w", err)
	}
	if f.user != "" {
		specUser = f.user
	}
	if f.port != 0 {
		port = f.port
	}
	if port == 0 {
		port = sshtunnel.DefaultPort
	}

	auth := strings.ToLower(strings.TrimSpace(f.auth))
	if auth == "" {
		auth = sshtunnel.AuthAuto
	}
	switch auth {
	case sshtunnel.AuthAuto,
		sshtunnel.AuthPassword,
		sshtunnel.AuthKey,
		sshtunnel.AuthAgent:
	default:
		return metadata.Tunnel{}, fmt.Errorf(
			"--tunnel-auth: unknown method %q (want auto, password, key or agent)",
			f.auth,
		)
	}

	if auth == sshtunnel.AuthKey && f.key == "" {
		return metadata.Tunnel{}, errors.New(
			"--tunnel-auth key needs --tunnel-key <path>",
		)
	}

	profile := metadata.Tunnel{
		DatabaseID:    databaseID,
		Host:          host,
		Port:          port,
		User:          specUser,
		AuthMethod:    auth,
		Password:      f.password,
		KeyPath:       f.key,
		KeyPassphrase: f.keyPassphrase,
		KnownHosts:    f.knownHosts,
		Insecure:      f.insecure,
	}

	f.notes(profile)
	return profile, nil
}

// notes prints non-fatal remarks about a tunnel profile.
func (f *tunnelFlags) notes(profile metadata.Tunnel) {
	if profile.Password != "" {
		fmt.Fprintln(os.Stderr,
			"pgvault: note: the ssh password is stored in plaintext in the metadata database (prefer "+sshtunnel.EnvPassword+")")
	}
	if profile.AuthMethod == sshtunnel.AuthPassword &&
		profile.Password == "" && os.Getenv(sshtunnel.EnvPassword) == "" {
		fmt.Fprintf(os.Stderr,
			"pgvault: note: no password given; backups need %s set\n",
			sshtunnel.EnvPassword)
	}
	if profile.KeyPassphrase != "" {
		fmt.Fprintln(os.Stderr,
			"pgvault: note: the key passphrase is stored in plaintext in the metadata database (prefer "+sshtunnel.EnvKeyPassphrase+")")
	}
	if profile.Insecure {
		fmt.Fprintln(os.Stderr,
			"pgvault: note: ssh host key verification is disabled for this database")
	}
}

// tunnelTargetString renders a tunnel profile as user@host:port.
func tunnelTargetString(spec metadata.Tunnel) string {
	if spec.User == "" {
		return fmt.Sprintf("%s:%d", spec.Host, spec.Port)
	}
	return fmt.Sprintf("%s@%s:%d", spec.User, spec.Host, spec.Port)
}

func cmdAdd(args []string) error {
	fs := newFlagSet("add")
	url := fs.String("url", "", "postgres connection string")
	backend := fs.String("storage", "", "storage backend: local or s3")
	encrypt := fs.Bool("encryption", true, "encrypt this database's backups")
	var tunnels tunnelFlags
	addTunnelFlags(fs, &tunnels)
	var dockers dockerFlags
	addDockerFlags(fs, &dockers)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New(
			"usage: pgvault add <name> --url <postgres-url> [--tunnel [user@]host[:port]] [--docker <container>]",
		)
	}
	if *url == "" {
		return errors.New("add: --url is required")
	}

	return openApp(func(a *app.App) error {
		resolved, err := a.ResolveStorage(*backend)
		if err != nil {
			return err
		}

		database, err := a.Store.AddDatabase(fs.Arg(0), *url)
		if err != nil {
			return err
		}

		err = a.Store.UpsertPolicy(metadata.Policy{
			DatabaseID:     database.ID,
			StorageBackend: resolved,
			Encryption:     *encrypt,
		})
		if err != nil {
			return err
		}

		fmt.Printf(
			"registered %s (storage: %s, encryption: %t)\n",
			database.Name,
			resolved,
			*encrypt,
		)

		if fs.Changed("tunnel") {
			profile, err := tunnels.spec(database.ID)
			if err != nil {
				return err
			}
			if err := a.Store.UpsertTunnel(profile); err != nil {
				return err
			}
			printTunnelSummary(database.Name, profile)
		}

		if flagsChanged(fs, "docker") {
			// The docker host for backups is the bastion when a
			// tunnel profile exists, so detect against the saved
			// profile.
			tunnelSpec, err := a.Store.GetTunnel(database.ID)
			if err != nil {
				return err
			}

			ctx, cancel := inspectContext()
			profile, err := dockerProfile(ctx, dockers, database.ID, tunnelSpec)
			cancel()
			if err != nil {
				return err
			}

			if err := a.Store.UpsertDocker(profile); err != nil {
				return err
			}
			printDockerSummary(database.Name, profile, tunnelSpec)
		}

		return nil
	})
}

// printDockerSummary reports where and how container backups run.
func printDockerSummary(
	name string,
	profile metadata.Docker,
	tunnel *metadata.Tunnel,
) {
	fmt.Printf("docker saved for %s\n", name)
	printDockerProfile(name, profile, tunnel)
}

// printDockerProfile renders the container and the host that runs the
// docker command.
func printDockerProfile(
	name string,
	profile metadata.Docker,
	tunnel *metadata.Tunnel,
) {
	via := "this machine"
	if tunnel != nil {
		via = tunnelTargetString(*tunnel) + " (ssh)"
	}

	fmt.Printf("  container: %s\n", profile.Container)
	fmt.Printf(
		"  connects:  %s:%d inside the container\n",
		profile.Host,
		profile.Port,
	)
	fmt.Printf("  runs on:   %s\n", via)
	fmt.Printf("  verify:    pgvault docker %s --test\n", name)
}

// printTunnelSummary reports how backups of a database will reach it.
func printTunnelSummary(name string, profile metadata.Tunnel) {
	fmt.Printf("tunnel saved for %s\n", name)
	printTunnelProfile(profile)
}

// printTunnelProfile renders a stored tunnel profile. A profile whose
// settings cannot be resolved yet is still shown, with a note.
func printTunnelProfile(profile metadata.Tunnel) {
	fmt.Printf("  bastion:  %s\n", tunnelTargetString(profile))

	resolved, err := app.TunnelConfig(&profile).Resolve()
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"pgvault: note: not usable right now: %v\n",
			err,
		)
		return
	}

	fmt.Printf("  auth:     %s\n", resolved.AuthDescription)
	fmt.Printf("  host key: %s\n", tunnelHostKeyLine(resolved))
}

// tunnelHostKeyLine describes how the bastion host key is checked at
// backup time.
func tunnelHostKeyLine(resolved sshtunnel.Resolved) string {
	if resolved.InsecureIgnoreHostKey {
		return "not checked (insecure)"
	}
	if resolved.KnownHosts == "" {
		return "checked against known_hosts at backup time"
	}
	return fmt.Sprintf(
		"checked against %s at backup time",
		resolved.KnownHosts,
	)
}

func cmdDatabases(args []string) error {
	fs := newFlagSet("databases")
	if err := parseFlags(fs, args); err != nil {
		return err
	}

	return openApp(func(a *app.App) error {
		databases, err := a.Store.ListDatabases()
		if err != nil {
			return err
		}
		if len(databases) == 0 {
			fmt.Println("no databases registered")
			return nil
		}

		rows := make([][]string, 0, len(databases))
		for _, database := range databases {
			policy, err := a.Store.GetPolicy(database.ID)
			if err != nil {
				return err
			}

			schedule := "-"
			backend := a.Config.DefaultStorage
			encryption := true
			if policy != nil {
				if policy.Schedule != "" && policy.Enabled {
					schedule = policy.Schedule
				}
				backend = policy.StorageBackend
				encryption = policy.Encryption
			}

			tunnel, err := a.Store.GetTunnel(database.ID)
			if err != nil {
				return err
			}
			tunnelColumn := "-"
			if tunnel != nil {
				tunnelColumn = tunnelTargetString(*tunnel)
			}

			container, err := a.Store.GetDocker(database.ID)
			if err != nil {
				return err
			}
			containerColumn := "-"
			if container != nil {
				containerColumn = container.Container
			}

			enabled := "yes"
			if !database.Enabled {
				enabled = "no"
			}

			rows = append(rows, []string{
				database.Name,
				enabled,
				schedule,
				backend,
				fmt.Sprintf("%t", encryption),
				tunnelColumn,
				containerColumn,
			})
		}

		printTable(
			[]string{"NAME", "ENABLED", "SCHEDULE", "STORAGE", "ENCRYPTION", "TUNNEL", "DOCKER"},
			rows,
		)
		return nil
	})
}

func cmdTunnel(args []string) error {
	fs := newFlagSet("tunnel")
	var tunnels tunnelFlags
	addTunnelFlags(fs, &tunnels)
	remove := fs.Bool("remove", false, "remove the tunnel profile")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New(
			"usage: pgvault tunnel <name> --tunnel [user@]host[:port] [--tunnel-auth auto|password|key|agent]",
		)
	}
	name := fs.Arg(0)

	if *remove && tunnels.via != "" {
		return errors.New("tunnel: give either --tunnel or --remove, not both")
	}

	// Any tunnel flag counts as "set" intent, so lone flags such as
	// --tunnel-auth key are validated instead of silently ignored.
	tunnelFlagsChanged := false
	fs.Visit(func(flag *pflag.Flag) {
		if strings.HasPrefix(flag.Name, "tunnel") {
			tunnelFlagsChanged = true
		}
	})

	return openApp(func(a *app.App) error {
		database, err := a.Store.GetDatabase(name)
		if err != nil {
			return err
		}

		if *remove {
			if err := a.Store.DeleteTunnel(database.ID); err != nil {
				return err
			}
			fmt.Printf("removed tunnel for %s\n", name)
			return nil
		}

		if !tunnelFlagsChanged {
			return printTunnelStatus(a, name, database.ID)
		}

		profile, err := tunnels.spec(database.ID)
		if err != nil {
			return err
		}
		if err := a.Store.UpsertTunnel(profile); err != nil {
			return err
		}

		printTunnelSummary(name, profile)
		return nil
	})
}

// cmdDocker manages the container profile of a database, or discovers
// containers on a docker host.
func cmdDocker(args []string) error {
	fs := newFlagSet("docker")
	var dockers dockerFlags
	addDockerFlags(fs, &dockers)
	var tunnels tunnelFlags
	addTunnelFlags(fs, &tunnels)
	remove := fs.Bool("remove", false, "remove the container profile")
	test := fs.Bool("test", false, "check that the container and postgres are reachable")
	all := fs.Bool("all", false, "list every container, not only postgres")
	if err := parseFlags(fs, args); err != nil {
		return err
	}

	if fs.NArg() == 1 && fs.Arg(0) == "discover" {
		return cmdDockerDiscover(fs, &tunnels, *all)
	}
	if fs.NArg() != 1 {
		return errors.New(
			"usage: pgvault docker <name> [--docker <container>] [--docker-port N] [--test|--remove]\n" +
				"       pgvault docker discover [--tunnel ...] [--all]",
		)
	}
	name := fs.Arg(0)

	if *remove && *test {
		return errors.New("docker: give either --remove or --test, not both")
	}
	if flagsChanged(fs, "tunnel") {
		return errors.New(
			"docker: tunnel flags only apply to `pgvault docker discover`; " +
				"set the tunnel with `pgvault tunnel " + name + " --tunnel ...`",
		)
	}

	return openApp(func(a *app.App) error {
		database, err := a.Store.GetDatabase(name)
		if err != nil {
			return err
		}

		if *remove {
			if flagsChanged(fs, "docker") {
				return errors.New("docker: give either --docker or --remove, not both")
			}
			if err := a.Store.DeleteDocker(database.ID); err != nil {
				return err
			}
			fmt.Printf("removed docker container for %s\n", name)
			return nil
		}

		tunnelSpec, err := a.Store.GetTunnel(database.ID)
		if err != nil {
			return err
		}

		if *test {
			if flagsChanged(fs, "docker") {
				return errors.New("docker: give either --docker or --test, not both")
			}
			return testDocker(a, name, database.ID, tunnelSpec)
		}

		if !flagsChanged(fs, "docker") {
			return printDockerStatus(a, name, database.ID)
		}

		ctx, cancel := inspectContext()
		profile, err := dockerProfile(ctx, dockers, database.ID, tunnelSpec)
		cancel()
		if err != nil {
			return err
		}

		if err := a.Store.UpsertDocker(profile); err != nil {
			return err
		}
		printDockerSummary(name, profile, tunnelSpec)
		return nil
	})
}

// printDockerStatus shows the container profile of a database.
func printDockerStatus(a *app.App, name, databaseID string) error {
	profile, err := a.Store.GetDocker(databaseID)
	if err != nil {
		return err
	}
	if profile == nil {
		fmt.Printf("no container configured for %s\n", name)
		return nil
	}

	tunnel, err := a.Store.GetTunnel(databaseID)
	if err != nil {
		return err
	}

	fmt.Printf("container for %s\n", name)
	printDockerProfile(name, *profile, tunnel)
	return nil
}

// testDocker verifies that the container runs and that postgres on the
// container-internal port accepts connections. pg_isready does not
// authenticate, so this is not a substitute for a backup.
func testDocker(
	a *app.App,
	name, databaseID string,
	tunnel *metadata.Tunnel,
) error {
	profile, err := a.Store.GetDocker(databaseID)
	if err != nil {
		return err
	}
	if profile == nil {
		return fmt.Errorf("no container configured for %s", name)
	}

	ctx, cancel := inspectContext()
	defer cancel()

	host := dockerHost(tunnel)
	where := "locally"
	if tunnel != nil {
		where = "on " + tunnelTargetString(*tunnel)
	}
	fmt.Printf("testing container %s (%s)\n", profile.Container, where)

	running, err := docker.Running(ctx, host, profile.Container)
	if err != nil {
		return err
	}
	if !running {
		return fmt.Errorf("container %s is not running", profile.Container)
	}
	fmt.Println("  container: running")

	hostAddr := profile.Host
	if hostAddr == "" {
		hostAddr = docker.DefaultHost
	}
	port := profile.Port
	if port == 0 {
		port = docker.DefaultPort
	}

	output, err := host.Run(
		ctx,
		"exec", profile.Container, "pg_isready",
		"-h", hostAddr,
		"-p", strconv.Itoa(port),
		"-t", "5",
	)
	if err != nil {
		return fmt.Errorf("postgres is not accepting connections: %w", err)
	}

	fmt.Printf("  postgres:  %s\n", strings.TrimSpace(string(output)))
	fmt.Println("container is healthy")
	return nil
}

// cmdDockerDiscover lists postgres containers on a docker host: this
// machine, or the bastion given with the tunnel flags.
func cmdDockerDiscover(
	fs *pflag.FlagSet,
	tunnels *tunnelFlags,
	all bool,
) error {
	if flagsChanged(fs, "docker") || fs.Changed("remove") || fs.Changed("test") {
		return errors.New("docker discover: only tunnel flags and --all apply")
	}

	var (
		host   docker.Host
		target string
	)
	if flagsChanged(fs, "tunnel") {
		profile, err := tunnels.spec("")
		if err != nil {
			return err
		}
		cfg := app.TunnelConfig(&profile)
		host.Tunnel = &cfg
		target = tunnelTargetString(profile)
	} else {
		target = "this machine"
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	containers, err := docker.List(ctx, host, all)
	if err != nil {
		return err
	}
	if len(containers) == 0 {
		fmt.Printf("no postgres containers found on %s\n", target)
		return nil
	}

	rows := make([][]string, 0, len(containers))
	for _, container := range containers {
		rows = append(rows, []string{
			container.Name,
			container.Image,
			container.Ports,
			container.Status,
		})
	}
	printTable([]string{"NAME", "IMAGE", "PORTS", "STATUS"}, rows)

	fmt.Println()
	fmt.Println("suggested (fill in USER, PASSWORD and DB):")
	for _, container := range containers {
		suggestion := fmt.Sprintf(
			"  pgvault add %s --url 'postgres://USER:PASSWORD@127.0.0.1/DB'",
			docker.SuggestName(container.Name),
		)
		if host.Tunnel != nil {
			suggestion += " --tunnel " + target
		}
		suggestion += " --docker " + container.Name
		if container.Port != 0 && container.Port != docker.DefaultPort {
			suggestion += fmt.Sprintf(" --docker-port %d", container.Port)
		}
		fmt.Println(suggestion)
	}

	return nil
}

// printTunnelStatus shows the tunnel profile of a database.
func printTunnelStatus(a *app.App, name, databaseID string) error {
	spec, err := a.Store.GetTunnel(databaseID)
	if err != nil {
		return err
	}
	if spec == nil {
		fmt.Printf("no tunnel configured for %s\n", name)
		return nil
	}

	fmt.Printf("tunnel for %s\n", name)
	printTunnelProfile(*spec)
	return nil
}

func cmdRemove(args []string) error {
	fs := newFlagSet("remove")
	yes := fs.Bool("yes", false, "confirm removal")
	purge := fs.Bool("purge", false, "also delete the stored backup objects")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: pgvault remove <name> --yes [--purge]")
	}
	name := fs.Arg(0)

	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

	return openApp(func(a *app.App) error {
		database, err := a.Store.GetDatabase(name)
		if err != nil {
			return err
		}

		records, err := a.Store.ListBackups(name)
		if err != nil {
			return err
		}

		policy, err := a.Store.GetPolicy(database.ID)
		if err != nil {
			return err
		}

		tunnel, err := a.Store.GetTunnel(database.ID)
		if err != nil {
			return err
		}

		container, err := a.Store.GetDocker(database.ID)
		if err != nil {
			return err
		}

		printRemovalSummary(name, records, tunnel, container, *purge)

		if !*yes {
			return errors.New(
				"remove: pass --yes to confirm (this deletes the " +
					"database registration and its history)",
			)
		}

		if *purge {
			if err := purgeBackups(ctx, a, records); err != nil {
				return err
			}
		}

		if err := a.Store.DeleteDatabase(database.ID); err != nil {
			return err
		}

		if policy != nil && policy.Enabled && policy.Schedule != "" {
			fmt.Println(
				"note: restart pgvault daemon to unregister the schedule",
			)
		}

		fmt.Printf("removed %s (%d backup records)\n", name, len(records))
		return nil
	})
}

// printRemovalSummary describes what removing a database deletes and
// what it keeps.
func printRemovalSummary(
	name string,
	records []metadata.BackupRecord,
	tunnel *metadata.Tunnel,
	container *metadata.Docker,
	purge bool,
) {
	objects := 0
	for _, record := range records {
		if record.Path != "" {
			objects++
		}
	}

	fmt.Printf("remove %s:\n", name)
	fmt.Printf("  backup records: %d\n", len(records))
	if purge {
		fmt.Printf("  objects:        delete %d from storage\n", objects)
	} else {
		fmt.Printf("  objects:        keep %d in storage\n", objects)
	}
	if tunnel != nil {
		fmt.Printf("  tunnel:         %s\n", tunnelTargetString(*tunnel))
	}
	if container != nil {
		fmt.Printf("  container:      %s\n", container.Container)
	}

	// Kept objects are listed so their paths survive the removal and
	// can be cleaned up by hand.
	if !purge {
		for _, record := range records {
			if record.Path != "" {
				fmt.Printf(
					"  object:         %s (%s)\n",
					record.Path,
					record.StorageBackend,
				)
			}
		}
	}
}

// purgeBackups deletes every stored object of a database, grouping
// records by their storage backend.
func purgeBackups(
	ctx context.Context,
	a *app.App,
	records []metadata.BackupRecord,
) error {
	stores := make(map[string]storage.Storage)

	for _, record := range records {
		if record.Path == "" {
			continue
		}

		store, ok := stores[record.StorageBackend]
		if !ok {
			var err error
			store, err = a.Storage(record.StorageBackend)
			if err != nil {
				return err
			}
			stores[record.StorageBackend] = store
		}

		if err := store.Delete(ctx, record.Path); err != nil {
			// A missing object is already in the desired state.
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return fmt.Errorf("delete %s: %w", record.Path, err)
		}

		fmt.Printf("deleted %s\n", record.Path)
	}

	return nil
}

func cmdBackup(args []string) error {
	fs := newFlagSet("backup")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: pgvault backup <name>")
	}
	name := fs.Arg(0)

	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

	return openApp(func(a *app.App) error {
		result, err := a.RunBackup(ctx, name, "manual")
		if err != nil {
			if result != nil {
				return fmt.Errorf("backup %s failed: %w", result.ID, err)
			}
			return err
		}
		printBackup(result)
		return nil
	})
}

func cmdBackups(args []string) error {
	fs := newFlagSet("backups")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() > 1 {
		return errors.New("usage: pgvault backups [name]")
	}
	var name string
	if fs.NArg() == 1 {
		name = fs.Arg(0)
	}

	return openApp(func(a *app.App) error {
		records, err := a.Store.ListBackups(name)
		if err != nil {
			return err
		}
		if len(records) == 0 {
			fmt.Println("no backups found")
			return nil
		}

		rows := make([][]string, 0, len(records))
		for _, record := range records {
			rows = append(rows, []string{
				record.ID,
				record.DatabaseName,
				record.Status,
				sizeOrDash(record),
				localTime(record.StartedAt),
				durationOrDash(record),
			})
		}

		printTable(
			[]string{"BACKUP ID", "DATABASE", "STATUS", "SIZE", "STARTED", "DURATION"},
			rows,
		)
		return nil
	})
}

func cmdInspect(args []string) error {
	fs := newFlagSet("inspect")
	verify := fs.Bool("verify", false, "stream the object and verify its checksum")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: pgvault inspect <backup-id> [--verify]")
	}
	id := fs.Arg(0)

	return openApp(func(a *app.App) error {
		record, err := a.Store.GetBackup(id)
		if err != nil {
			return err
		}

		fmt.Println("Backup:    ", record.ID)
		fmt.Println("Database:  ", record.DatabaseName)
		fmt.Println("Status:    ", record.Status)
		if record.Reason != "" {
			fmt.Println("Reason:    ", record.Reason)
		}
		fmt.Println("Started:   ", localTime(record.StartedAt))
		fmt.Println("Completed: ", localTime(record.CompletedAt))
		fmt.Println("Duration:  ", durationOrDash(*record))
		if record.SizeBytes > 0 {
			fmt.Printf(
				"Size:       %s (%d bytes)\n",
				formatBytes(record.SizeBytes),
				record.SizeBytes,
			)
		}
		fmt.Println("Path:      ", record.Path)
		fmt.Println("Storage:   ", record.StorageBackend)
		if record.Trigger != "" {
			fmt.Println("Trigger:   ", record.Trigger)
		}
		if record.Checksum != "" {
			fmt.Println("Checksum:  ", "sha256:"+record.Checksum)
		}
		if record.Encryption != "" {
			fmt.Printf(
				"Encryption: %s (key version %d)\n",
				record.Encryption,
				record.KeyVersion,
			)
		} else {
			fmt.Println("Encryption: none")
		}
		if record.Error != "" {
			fmt.Println("Error:     ", record.Error)
		}

		store, err := a.Storage(record.StorageBackend)
		if err != nil {
			return err
		}

		object, err := store.Get(context.Background(), record.Path)
		if err != nil {
			return err
		}
		defer object.Close()

		hasher := sha256.New()
		var source io.Reader = object
		if *verify {
			source = io.TeeReader(object, hasher)
		}

		header, err := archive.ReadHeader(source)
		if err != nil {
			return fmt.Errorf("read object header: %w", err)
		}

		fmt.Printf("Format:     pgvault/%d (%s, %s)\n",
			header.Version,
			header.Type,
			header.Compression,
		)
		fmt.Println("Created:   ", header.CreatedAt.Local().Format(time.RFC3339))
		if header.Encryption != nil {
			fmt.Printf(
				"Object encryption: %s (key version %d, chunk size %d)\n",
				header.Encryption.Algorithm,
				header.Encryption.KeyVersion,
				header.Encryption.ChunkSize,
			)
		}

		if !*verify {
			return nil
		}

		if record.Checksum == "" {
			return errors.New("no checksum recorded for this backup")
		}
		if _, err := io.Copy(io.Discard, source); err != nil {
			return fmt.Errorf("read object: %w", err)
		}

		sum := hex.EncodeToString(hasher.Sum(nil))
		if sum != record.Checksum {
			return fmt.Errorf(
				"checksum mismatch: object is %s, metadata says %s",
				sum,
				record.Checksum,
			)
		}

		fmt.Println("Checksum verified.")
		return nil
	})
}

func cmdSchedule(args []string) error {
	fs := newFlagSet("schedule")
	backend := fs.String("storage", "", "storage backend: local or s3")
	encrypt := fs.Bool("encryption", true, "encrypt backups")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return errors.New(`usage: pgvault schedule <name> "<cron>"`)
	}
	name, spec := fs.Arg(0), fs.Arg(1)

	if err := scheduler.ValidateSchedule(spec); err != nil {
		return fmt.Errorf("invalid schedule %q: %w", spec, err)
	}

	return openApp(func(a *app.App) error {
		database, err := a.Store.GetDatabase(name)
		if err != nil {
			return err
		}

		policy, err := a.Store.GetPolicy(database.ID)
		if err != nil {
			return err
		}

		updated := metadata.Policy{
			DatabaseID:     database.ID,
			StorageBackend: a.Config.DefaultStorage,
			Encryption:     true,
		}
		if policy != nil {
			updated = *policy
		}
		updated.Schedule = spec
		updated.Enabled = true

		if fs.Changed("storage") {
			resolved, err := a.ResolveStorage(*backend)
			if err != nil {
				return err
			}
			updated.StorageBackend = resolved
		}
		if fs.Changed("encryption") {
			updated.Encryption = *encrypt
		}

		if err := a.Store.UpsertPolicy(updated); err != nil {
			return err
		}

		fmt.Printf("scheduled %s: %s\n", name, spec)
		return nil
	})
}

func cmdDaemon(args []string) error {
	fs := newFlagSet("daemon")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: pgvault daemon")
	}

	return openApp(func(a *app.App) error {
		logger := log.New(os.Stderr, "pgvault: ", log.LstdFlags)

		sched := scheduler.New(a, a.Store, logger)
		if err := sched.Reload(); err != nil {
			return err
		}

		ctx, stop := signal.NotifyContext(
			context.Background(),
			os.Interrupt,
			syscall.SIGTERM,
		)
		defer stop()

		sched.Start()
		logger.Printf("daemon started")

		<-ctx.Done()
		logger.Printf("daemon stopping")

		stopCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := sched.Stop(stopCtx); err != nil {
			return fmt.Errorf("stop scheduler: %w", err)
		}
		return nil
	})
}

func printBackup(result *backup.Backup) {
	fmt.Println("Backup complete")
	fmt.Println("ID:", result.ID)
	fmt.Println("Path:", result.Path)
	fmt.Printf(
		"Size: %s (%d bytes)\n",
		formatBytes(result.SizeBytes),
		result.SizeBytes,
	)
	if result.Checksum != "" {
		fmt.Println("Checksum: sha256:" + result.Checksum)
	}
	if result.Encryption != "" {
		fmt.Printf(
			"Encryption: %s (key version %d)\n",
			result.Encryption,
			result.KeyVersion,
		)
	} else {
		fmt.Println("Encryption: none")
	}
	fmt.Println("Started:", localTime(result.StartedAt))
	fmt.Println("Completed:", localTime(result.CompletedAt))
}

func printTable(headers []string, rows [][]string) {
	writer := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(writer, strings.Join(headers, "\t"))
	for _, row := range rows {
		fmt.Fprintln(writer, strings.Join(row, "\t"))
	}
	writer.Flush()
}

func sizeOrDash(record metadata.BackupRecord) string {
	if record.SizeBytes <= 0 {
		return "-"
	}
	return formatBytes(record.SizeBytes)
}

func durationOrDash(record metadata.BackupRecord) string {
	if record.StartedAt.IsZero() || record.CompletedAt.IsZero() {
		return "-"
	}
	return record.CompletedAt.Sub(record.StartedAt).Round(time.Millisecond).String()
}

func localTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.Local().Format("2006-01-02 15:04:05")
}

// formatBytes renders a byte count using binary units.
func formatBytes(n int64) string {
	const unit = 1024

	if n < unit {
		return fmt.Sprintf("%d B", n)
	}

	units := []string{"KiB", "MiB", "GiB", "TiB", "PiB"}

	value := float64(n)
	i := -1

	for value >= unit && i < len(units)-1 {
		value /= unit
		i++
	}

	return fmt.Sprintf("%.1f %s", value, units[i])
}
