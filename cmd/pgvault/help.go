package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

// helpWriter is where explicit help output goes; tests can replace it.
var helpWriter io.Writer = os.Stdout

// usage is the overview shown by "pgvault help", printed on stderr
// when no command is given, and for unknown commands.
const usage = `pgvault — encrypted PostgreSQL backups

Usage:
  pgvault <command> [arguments]

Commands:
  add <name> --url <url>         register a database
  databases                      list registered databases
  backup <name>                  back up a database now
  backups [name]                 list backup history
  inspect <backup-id> [--verify] show details and verify a backup
  tunnel <name>                  manage the ssh tunnel profile
  docker <name>                  manage the container profile
  docker discover                list postgres containers on a docker host
  schedule <name> <cron>         set the backup schedule
  remove <name> --yes [--purge]  unregister a database
  daemon                         run the scheduler
  help [command]                 show this help or a command's help

Run "pgvault help <command>" for flags, examples and sample output.
Run "pgvault help environment" for environment variables.

Storage backends: local (default) or s3.
Backups are stored as encrypted, compressed .pgv objects; see "pgvault help backup".
`

// helpExample is one worked scenario: what to type and what to expect.
type helpExample struct {
	Title   string // what the scenario shows
	Command string // shell input; continuation lines keep their indent
	Output  string // exact expected output
	Note    string // optional remark after the output
}

// helpTopic is the help page of one command.
type helpTopic struct {
	Name     string
	Summary  string
	Usage    string
	Details  []string
	Flags    string // already indented, may be empty
	Examples []helpExample
	SeeAlso  []string
}

// helpAliases maps command aliases to their help topic.
var helpAliases = map[string]string{
	"dbs": "databases",
}

var helpTopics = map[string]helpTopic{
	"add": {
		Name:    "add",
		Summary: "register a database",
		Usage:   "pgvault add <name> --url <url> [flags]",
		Details: []string{
			"Registers a database together with its storage and encryption policy and, optionally, how backups reach it: through an ssh bastion (--tunnel) and/or inside a docker container (--docker).",
			"With --docker the host and port in --url are ignored: pg_dump runs inside the container and connects to the container-internal address (--docker-port, detected automatically, default 5432). user, password, dbname and every other parameter are kept.",
			"Tunnel secrets should come from the environment (PGVAULT_SSH_PASSWORD, PGVAULT_SSH_KEY_PASSPHRASE); a password passed with --tunnel-password is stored in plaintext in the metadata database.",
		},
		Flags: `  --url <url>                    postgres connection string (required)
  --storage local|s3             storage backend (default PGVAULT_STORAGE or local)
  --encryption=true|false        encrypt this database's backups (default true)
  --tunnel [user@]host[:port]    back up through an ssh bastion
  --tunnel-user <user>           ssh user for the bastion
  --tunnel-port <port>           ssh port (default 22)
  --tunnel-auth auto|password|key|agent
                                 bastion authentication (default auto)
  --tunnel-key <path>            private key for the bastion
  --tunnel-key-passphrase <s>    passphrase for the key
                                 (prefer PGVAULT_SSH_KEY_PASSPHRASE)
  --tunnel-password <password>   bastion password (prefer PGVAULT_SSH_PASSWORD)
  --tunnel-known-hosts <path>    known_hosts file (default ~/.ssh/known_hosts)
  --tunnel-insecure              skip ssh host key verification (insecure)
  --docker <container>           run pg_dump inside this container
  --docker-port <port>           postgres port inside the container
                                 (default 5432, or detected)
`,
		Examples: []helpExample{
			{
				Title:   "Local database",
				Command: `pgvault add prod --url 'postgres://app:secret@127.0.0.1:5432/app'`,
				Output:  `registered prod (storage: local, encryption: true)`,
			},
			{
				Title: "Store in S3 without encryption",
				Command: `pgvault add prod --url 'postgres://app:secret@127.0.0.1:5432/app' \
    --storage s3 --encryption=false`,
				Output: `registered prod (storage: s3, encryption: false)`,
			},
			{
				Title: "Remote database through an ssh bastion (key authentication)",
				Command: `pgvault add prod --url 'postgres://app:secret@db.internal:5432/app' \
    --tunnel alice@bastion.example.com:22 --tunnel-key ~/.ssh/id_ed25519`,
				Output: `registered prod (storage: local, encryption: true)
tunnel saved for prod
  bastion:  alice@bastion.example.com:22
  auth:     key /home/alice/.ssh/id_ed25519
  host key: checked against /home/alice/.ssh/known_hosts at backup time`,
			},
			{
				Title: "Password authentication from the environment (preferred)",
				Command: `PGVAULT_SSH_PASSWORD='secret' pgvault add prod \
    --url 'postgres://app:secret@db.internal:5432/app' \
    --tunnel bastion.example.com --tunnel-auth password`,
				Output: `registered prod (storage: local, encryption: true)
tunnel saved for prod
  bastion:  ubuntu@bastion.example.com:22
  auth:     password (from PGVAULT_SSH_PASSWORD)
  host key: checked against /home/alice/.ssh/known_hosts at backup time`,
			},
			{
				Title: "Password authentication stored in the metadata database",
				Command: `pgvault add prod --url 'postgres://app:secret@db.internal:5432/app' \
    --tunnel bastion.example.com --tunnel-auth password --tunnel-password 'secret'`,
				Output: `registered prod (storage: local, encryption: true)
pgvault: note: the ssh password is stored in plaintext in the metadata database (prefer PGVAULT_SSH_PASSWORD)
tunnel saved for prod
  bastion:  ubuntu@bastion.example.com:22
  auth:     password (stored in metadata)
  host key: checked against /home/alice/.ssh/known_hosts at backup time`,
			},
			{
				Title: "Dockerized database on the bastion (no pg_dump on the VM host)",
				Command: `pgvault add qa-robocalling \
    --url 'postgres://admin:secret@127.0.0.1/robocalling_new' \
    --tunnel ubuntu@vps.example.com --tunnel-auth password \
    --docker qa-postgres`,
				Output: `registered qa-robocalling (storage: local, encryption: true)
tunnel saved for qa-robocalling
  bastion:  ubuntu@vps.example.com:22
  auth:     password (from PGVAULT_SSH_PASSWORD)
  host key: checked against /home/alice/.ssh/known_hosts at backup time
docker saved for qa-robocalling
  container: qa-postgres
  connects:  127.0.0.1:5432 inside the container
  runs on:   ubuntu@vps.example.com:22 (ssh)
  verify:    pgvault docker qa-robocalling --test`,
				Note: `With --docker the host and port in --url (127.0.0.1) are ignored; the
container port is detected from the container (5432 here).`,
			},
			{
				Title:   "Errors",
				Command: `pgvault add prod --url 'postgres://app:secret@127.0.0.1:5432/app'`,
				Output:  `pgvault: database "prod" is already registered`,
				Note:    `pgvault add prod  ->  pgvault: add: --url is required`,
			},
		},
		SeeAlso: []string{"pgvault help tunnel", "pgvault help docker", "pgvault help backup"},
	},

	"databases": {
		Name:    "databases",
		Summary: "list registered databases",
		Usage:   "pgvault databases",
		Details: []string{
			"Lists every registered database with its enabled state, schedule, storage backend, encryption setting and how backups reach it (ssh tunnel and/or container).",
		},
		Examples: []helpExample{
			{
				Title:   "All registered databases",
				Command: "pgvault databases",
				Output: `NAME            ENABLED  SCHEDULE      STORAGE  ENCRYPTION  TUNNEL                     DOCKER
prod            yes      0 */6 * * *   local    true        -                          -
qa-robocalling  yes      -             local    true        ubuntu@vps.example.com:22  qa-postgres`,
			},
			{
				Title:   "Nothing registered yet",
				Command: "pgvault databases",
				Output:  `no databases registered`,
			},
		},
	},

	"backup": {
		Name:    "backup",
		Summary: "back up a database now",
		Usage:   "pgvault backup <name>",
		Details: []string{
			"Runs pg_dump and streams the archive through compression and encryption straight into the storage backend; no temporary file is written.",
			"Without a container profile pg_dump runs on this machine, against the local end of the ssh tunnel when one is configured. With a container profile it runs inside the container: on the ssh bastion when the database also has a tunnel profile, otherwise on this machine.",
			"Every run is recorded in the history, including failures. The printed ID can be inspected with \"pgvault inspect <id>\".",
		},
		Examples: []helpExample{
			{
				Title:   "Successful backup",
				Command: `pgvault backup qa-robocalling`,
				Output: `Backup complete
ID: d30af415-7727-4879-9b3b-2990cdbef03f
Path: qa-robocalling/d30af415-7727-4879-9b3b-2990cdbef03f.pgv
Size: 797.7 KiB (816838 bytes)
Checksum: sha256:bb84fd6af664caf27c5e3612923455e3d1e8f71cc6588b60cd8afc365fec814b
Encryption: aes-256-gcm (key version 1)
Started: 2026-10-01 13:51:00
Completed: 2026-10-01 13:52:27`,
				Note: `The object is stored under <storage>/<database>/<backup-id>.pgv; with the
local backend that is ~/.pgvault/backups/.`,
			},
			{
				Title:   "Wrong database credentials",
				Command: `pgvault backup qa-robocalling`,
				Output:  `pgvault: backup 03cfe8d4-82b9-4d97-8b03-fae3c226f37c failed: docker exec qa-postgres: ssh exec: Process exited with status 1: pg_dump: error: connection to server at "127.0.0.1", port 5432 failed: FATAL:  role "postgres" does not exist`,
				Note: `pgvault docker <name> --test only checks that the container and server are
reachable; it does not authenticate. Wrong credentials surface here, at
backup time.`,
			},
		},
		SeeAlso: []string{"pgvault help backups", "pgvault help inspect"},
	},

	"backups": {
		Name:    "backups",
		Summary: "list backup history",
		Usage:   "pgvault backups [name]",
		Details: []string{
			"Lists backup history, newest first, optionally filtered to one database.",
		},
		Examples: []helpExample{
			{
				Title:   "History of one database",
				Command: "pgvault backups qa-robocalling",
				Output: `BACKUP ID                             DATABASE        STATUS   SIZE       STARTED              DURATION
d30af415-7727-4879-9b3b-2990cdbef03f  qa-robocalling  success  797.7 KiB  2026-10-01 13:51:00  1m27s
03cfe8d4-82b9-4d97-8b03-fae3c226f37c  qa-robocalling  failed   -          2026-10-01 13:44:12  0.4s`,
			},
		},
		SeeAlso: []string{"pgvault help inspect"},
	},

	"inspect": {
		Name:    "inspect",
		Summary: "show details and verify a backup",
		Usage:   "pgvault inspect <backup-id> [--verify]",
		Details: []string{
			"Shows the recorded metadata and the object header. With --verify the whole object is streamed and its sha256 compared with the recorded checksum.",
			".pgv objects are compressed and encrypted; pg_restore cannot read them directly, and pgvault has no export or restore command yet.",
		},
		Flags: `  --verify                       stream the object and verify its checksum
`,
		Examples: []helpExample{
			{
				Title:   "Inspect and verify",
				Command: "pgvault inspect d30af415-7727-4879-9b3b-2990cdbef03f --verify",
				Output: `Backup:     d30af415-7727-4879-9b3b-2990cdbef03f
Database:   qa-robocalling
Status:     success
Started:    2026-10-01 13:51:00
Completed:  2026-10-01 13:52:27
Duration:   1m27s
Size:       797.7 KiB (816838 bytes)
Path:       qa-robocalling/d30af415-7727-4879-9b3b-2990cdbef03f.pgv
Storage:    local
Trigger:    manual
Checksum:   sha256:bb84fd6af664caf27c5e3612923455e3d1e8f71cc6588b60cd8afc365fec814b
Encryption: aes-256-gcm (key version 1)
Format:     pgvault/1 (logical, zstd)
Created:    2026-10-01T13:51:00+05:00
Object encryption: aes-256-gcm (key version 1, chunk size 8388608)
Checksum verified.`,
			},
		},
		SeeAlso: []string{"pgvault help backup"},
	},

	"tunnel": {
		Name:    "tunnel",
		Summary: "manage the ssh tunnel profile",
		Usage:   "pgvault tunnel <name> [--tunnel ...] [--remove]",
		Details: []string{
			"Backups of a tunneled database are taken through an ssh bastion: pg_dump runs on this machine and dials the local end of the tunnel, or, when the database also has a container profile, the docker command runs on the bastion itself.",
			"--tunnel-auth auto (default) picks a key file, then the ssh agent, then a password. Passwords may be stored with --tunnel-password or read from PGVAULT_SSH_PASSWORD at backup time; key passphrases come from PGVAULT_SSH_KEY_PASSPHRASE. Host keys are verified against ~/.ssh/known_hosts (PGVAULT_SSH_KNOWN_HOSTS to override); --tunnel-insecure skips verification.",
		},
		Flags: `  --tunnel [user@]host[:port]    bastion address (required when setting)
  --tunnel-user <user>           ssh user for the bastion
  --tunnel-port <port>           ssh port (default 22)
  --tunnel-auth auto|password|key|agent
                                 bastion authentication (default auto)
  --tunnel-key <path>            private key for the bastion
  --tunnel-key-passphrase <s>    passphrase for the key
                                 (prefer PGVAULT_SSH_KEY_PASSPHRASE)
  --tunnel-password <password>   bastion password (prefer PGVAULT_SSH_PASSWORD)
  --tunnel-known-hosts <path>    known_hosts file (default ~/.ssh/known_hosts)
  --tunnel-insecure              skip ssh host key verification (insecure)
  --remove                       remove the tunnel profile
`,
		Examples: []helpExample{
			{
				Title:   "Show the stored profile",
				Command: "pgvault tunnel prod",
				Output: `tunnel for prod
  bastion:  alice@bastion.example.com:22
  auth:     key /home/alice/.ssh/id_ed25519
  host key: checked against /home/alice/.ssh/known_hosts at backup time`,
			},
			{
				Title: "Set or replace the profile",
				Command: `PGVAULT_SSH_PASSWORD='secret' pgvault tunnel prod \
    --tunnel bastion.example.com --tunnel-auth password`,
				Output: `tunnel saved for prod
  bastion:  ubuntu@bastion.example.com:22
  auth:     password (from PGVAULT_SSH_PASSWORD)
  host key: checked against /home/alice/.ssh/known_hosts at backup time`,
			},
			{
				Title:   "No password available yet",
				Command: `pgvault tunnel prod --tunnel bastion.example.com --tunnel-auth password`,
				Output: `pgvault: note: no password given; backups need PGVAULT_SSH_PASSWORD set
tunnel saved for prod
  bastion:  ubuntu@bastion.example.com:22
pgvault: note: not usable right now: password authentication needs a password (set --tunnel-password or PGVAULT_SSH_PASSWORD)`,
				Note: `The profile is saved either way; set PGVAULT_SSH_PASSWORD (or add
--tunnel-password) before backing up.`,
			},
			{
				Title:   "Remove it",
				Command: "pgvault tunnel prod --remove",
				Output:  `removed tunnel for prod`,
			},
		},
		SeeAlso: []string{"pgvault help add", "pgvault help docker"},
	},

	"docker": {
		Name:    "docker",
		Summary: "manage the container profile",
		Usage:   "pgvault docker <name> [--docker <container>] [--test|--remove]\n  pgvault docker discover [--tunnel ...] [--all]",
		Details: []string{
			"Manages the container profile: pg_dump runs inside <container> instead of on the docker host. With a tunnel profile the docker command runs on the ssh bastion; otherwise on this machine.",
			"docker discover lists the postgres containers on a docker host (this machine, or the bastion given with --tunnel flags) and prints suggested add commands.",
		},
		Flags: `  --docker <container>           container name or ID
  --docker-port <port>           postgres port inside the container
                                 (default 5432, or detected)
  --test                         check the container and postgres without a backup
  --remove                       remove the container profile
  --all                          discover: list every container, not only postgres
  --tunnel [user@]host[:port]    discover: ssh bastion to list through
  ...                            discover: other --tunnel-* flags, see
                                 "pgvault help tunnel"
`,
		Examples: []helpExample{
			{
				Title:   "Show the stored container profile",
				Command: "pgvault docker qa-robocalling",
				Output: `container for qa-robocalling
  container: qa-postgres
  connects:  127.0.0.1:5432 inside the container
  runs on:   ubuntu@vps.example.com:22 (ssh)
  verify:    pgvault docker qa-robocalling --test`,
			},
			{
				Title:   "Attach a container to a registered database",
				Command: "pgvault docker qa-robocalling --docker qa-postgres",
				Output: `docker saved for qa-robocalling
  container: qa-postgres
  connects:  127.0.0.1:5432 inside the container
  runs on:   ubuntu@vps.example.com:22 (ssh)
  verify:    pgvault docker qa-robocalling --test`,
			},
			{
				Title:   "Health check (container up + postgres listening)",
				Command: "pgvault docker qa-robocalling --test",
				Output: `testing container qa-postgres (on ubuntu@vps.example.com:22)
  container: running
  postgres:  127.0.0.1:5432 - accepting connections
container is healthy`,
				Note: `pg_isready does not authenticate; wrong database credentials only show up
at backup time.`,
			},
			{
				Title:   "Discover postgres containers on the VM",
				Command: "PGVAULT_SSH_PASSWORD='secret' pgvault docker discover --tunnel ubuntu@vps.example.com --tunnel-auth password",
				Output: `NAME         IMAGE        PORTS                     STATUS
qa-postgres  postgres:17  127.0.0.1:9532->5432/tcp  Up 12 days (healthy)

suggested (fill in USER, PASSWORD and DB):
  pgvault add qa --url 'postgres://USER:PASSWORD@127.0.0.1/DB' --tunnel ubuntu@vps.example.com --docker qa-postgres`,
			},
			{
				Title:   "Remove the profile",
				Command: "pgvault docker qa-robocalling --remove",
				Output:  `removed docker container for qa-robocalling`,
			},
		},
		SeeAlso: []string{"pgvault help add", "pgvault help backup"},
	},

	"schedule": {
		Name:    "schedule",
		Summary: "set the backup schedule",
		Usage:   `pgvault schedule <name> "<cron>" [flags]`,
		Details: []string{
			"Sets or replaces the cron schedule of a database. The schedule is used by the daemon (\"pgvault daemon\"), not by one-off backups.",
			"Accepts standard five-field cron expressions and descriptors such as \"@every 1h\".",
		},
		Flags: `  --storage local|s3             storage backend for scheduled backups
  --encryption=true|false        encrypt scheduled backups (default true)
`,
		Examples: []helpExample{
			{
				Title:   "Every six hours",
				Command: `pgvault schedule prod "0 */6 * * *"`,
				Output:  `scheduled prod: 0 */6 * * *`,
			},
			{
				Title:   "Invalid schedule",
				Command: `pgvault schedule prod "every six hours"`,
				Output:  `pgvault: invalid schedule "every six hours": expected exactly 5 fields, found 3: [every six hours]`,
			},
		},
		SeeAlso: []string{"pgvault help daemon"},
	},

	"daemon": {
		Name:    "daemon",
		Summary: "run the scheduler",
		Usage:   "pgvault daemon",
		Details: []string{
			"Runs the scheduler in the foreground: every enabled schedule is registered at startup and backups run in the background. Stop with Ctrl-C or SIGTERM; a running backup is given 30 seconds to finish.",
			"Restart the daemon after changing schedules with \"pgvault schedule\".",
		},
		Examples: []helpExample{
			{
				Title:   "Run the scheduler",
				Command: "pgvault daemon",
				Output: `pgvault: 2026/10/01 13:00:00 scheduled prod: 0 */6 * * *
pgvault: 2026/10/01 13:00:00 daemon started
pgvault: 2026/10/01 13:00:00 backup start: prod
pgvault: 2026/10/01 13:00:04 backup complete: prod id=d30af415-7727-4879-9b3b-2990cdbef03f size=816838B duration=4.21s`,
			},
		},
	},

	"remove": {
		Name:    "remove",
		Summary: "unregister a database",
		Usage:   "pgvault remove <name> --yes [--purge]",
		Details: []string{
			"Removes the database registration; its policy, tunnel profile, container profile and backup history are deleted with it.",
			"Stored objects are kept by default and listed so they can be cleaned up by hand. With --purge they are deleted from the storage backend too.",
			"Without --yes, pgvault only prints what would be removed and exits 1.",
		},
		Flags: `  --yes                          confirm the removal
  --purge                        also delete the stored backup objects
`,
		Examples: []helpExample{
			{
				Title:   "Preview the removal",
				Command: "pgvault remove qa-robocalling",
				Output: `remove qa-robocalling:
  backup records: 2
  objects:        keep 2 in storage
  tunnel:         ubuntu@vps.example.com:22
  container:      qa-postgres
  object:         qa-robocalling/d30af415-7727-4879-9b3b-2990cdbef03f.pgv (local)
  object:         qa-robocalling/03cfe8d4-82b9-4d97-8b03-fae3c226f37c.pgv (local)
pgvault: remove: pass --yes to confirm (this deletes the database registration and its history)`,
			},
			{
				Title:   "Remove and delete the stored objects",
				Command: "pgvault remove qa-robocalling --yes --purge",
				Output: `deleted qa-robocalling/d30af415-7727-4879-9b3b-2990cdbef03f.pgv
deleted qa-robocalling/03cfe8d4-82b9-4d97-8b03-fae3c226f37c.pgv
removed qa-robocalling (2 backup records)`,
			},
		},
	},

	"environment": {
		Name:    "environment",
		Summary: "environment variables",
		Usage:   "pgvault help environment",
		Details: []string{
			"Environment variables read by pgvault. They apply to every command, including the daemon.",
		},
		Flags: `  PGVAULT_DIR                   data directory (default ~/.pgvault)
  PGVAULT_STORAGE               default storage backend (default local)
  PGVAULT_MASTER_KEY            backup encryption key (32 bytes, hex or base64)
  PGVAULT_SSH_PASSWORD          ssh password for bastions (overrides the stored one)
  PGVAULT_SSH_KEY_PASSPHRASE    passphrase for encrypted ssh keys
  PGVAULT_SSH_KNOWN_HOSTS       known_hosts file (default ~/.ssh/known_hosts)
  PGVAULT_SSH_INSECURE          set to 1 to skip ssh host key verification
  PGVAULT_S3_BUCKET             S3 bucket name
  PGVAULT_S3_REGION             S3 region (default us-east-1)
  PGVAULT_S3_ENDPOINT           S3-compatible endpoint (MinIO, R2, B2, Spaces)
  PGVAULT_S3_PREFIX             key prefix inside the bucket
  PGVAULT_S3_PATH_STYLE         force path-style addressing
  AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY   S3 credentials
`,
		Examples: []helpExample{
			{
				Title:   "Password authentication without storing the password",
				Command: "PGVAULT_SSH_PASSWORD='secret' pgvault backup qa-robocalling",
				Output: `Backup complete
ID: d30af415-7727-4879-9b3b-2990cdbef03f
...`,
			},
			{
				Title:   "Store backups elsewhere",
				Command: `PGVAULT_DIR=/srv/pgvault pgvault databases`,
				Output:  `no databases registered`,
			},
		},
		SeeAlso: []string{"pgvault help add", "pgvault help tunnel"},
	},

	"help": {
		Name:    "help",
		Summary: "show help for a command",
		Usage:   "pgvault help [command]",
		Details: []string{
			"With no argument, prints the overview. With a command name, prints that command's page with flags, examples and sample output.",
		},
		Examples: []helpExample{
			{
				Title:   "Overview",
				Command: "pgvault help",
				Output: `pgvault — encrypted PostgreSQL backups

Usage:
  pgvault <command> [arguments]

Commands:
  add <name> --url <url>         register a database
  ...
`,
			},
			{
				Title:   "One command",
				Command: "pgvault help add",
				Output: `pgvault add — register a database

Usage:
  pgvault add <name> --url <url> [flags]
...`,
			},
		},
	},
}

// cmdHelp prints the overview or one command's help page.
func cmdHelp(args []string) error {
	switch len(args) {
	case 0:
		printGlobalHelp(helpWriter)
		return nil
	case 1:
		if !printTopic(helpWriter, args[0]) {
			return fmt.Errorf(
				"no help for %q (commands: %s)",
				args[0],
				strings.Join(commandNames(), ", "),
			)
		}
		return nil
	default:
		return errors.New("usage: pgvault help [command]")
	}
}

// printGlobalHelp writes the overview.
func printGlobalHelp(w io.Writer) {
	fmt.Fprint(w, usage)
}

// commandNames returns the help topics that are commands, sorted.
func commandNames() []string {
	names := make([]string, 0, len(helpTopics))
	for name := range helpTopics {
		if name == "environment" {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// printTopic writes one help page; it reports whether the topic exists.
func printTopic(w io.Writer, name string) bool {
	if topicName, ok := helpAliases[name]; ok {
		name = topicName
	}

	topic, ok := helpTopics[name]
	if !ok {
		return false
	}

	fmt.Fprintf(w, "pgvault %s — %s\n", topic.Name, topic.Summary)
	fmt.Fprintf(w, "\nUsage:\n  %s\n", topic.Usage)

	for _, paragraph := range topic.Details {
		fmt.Fprintln(w)
		for _, line := range wrapText(paragraph, 76) {
			fmt.Fprintln(w, line)
		}
	}

	if topic.Flags != "" {
		fmt.Fprintf(w, "\nFlags:\n%s", topic.Flags)
	}

	if len(topic.Examples) > 0 {
		fmt.Fprint(w, "\nExamples:\n")
		for _, example := range topic.Examples {
			fmt.Fprintln(w)
			writeExample(w, example)
		}
	}

	if len(topic.SeeAlso) > 0 {
		fmt.Fprintf(w, "\nSee also: %s\n", strings.Join(topic.SeeAlso, ", "))
	}

	return true
}

// writeExample renders one scenario with a "$" prompt.
func writeExample(w io.Writer, example helpExample) {
	if example.Title != "" {
		fmt.Fprintf(w, "  %s\n", example.Title)
	}

	lines := strings.Split(example.Command, "\n")
	fmt.Fprintf(w, "  $ %s\n", lines[0])
	for _, line := range lines[1:] {
		fmt.Fprintf(w, "  %s\n", line)
	}

	for _, line := range strings.Split(strings.TrimRight(example.Output, "\n"), "\n") {
		if line == "" {
			fmt.Fprintln(w)
			continue
		}
		fmt.Fprintf(w, "  %s\n", line)
	}

	if example.Note != "" {
		fmt.Fprintln(w)
		for _, line := range wrapText(example.Note, 76) {
			fmt.Fprintf(w, "  %s\n", line)
		}
	}
}

// wrapText wraps text to width columns, breaking on spaces. Existing
// line breaks in the input are ignored.
func wrapText(text string, width int) []string {
	var (
		lines []string
		line  string
	)
	for _, word := range strings.Fields(text) {
		switch {
		case line == "":
			line = word
		case len(line)+1+len(word) <= width:
			line += " " + word
		default:
			lines = append(lines, line)
			line = word
		}
	}
	if line != "" {
		lines = append(lines, line)
	}
	return lines
}
