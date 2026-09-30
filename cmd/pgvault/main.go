package main

import (
	"errors"
	"fmt"
	"os"
)

const usage = `usage: pgvault <command> [arguments]

Commands:
  add <name> --url <url>         register a database
  databases                      list registered databases
  backup <name>                  back up a registered database now
  backups [name]                 list backup history
  inspect <backup-id> [--verify] show details and optionally verify the checksum
  schedule <name> <cron>         set the backup schedule (for example "0 */6 * * *")
  daemon                         run the scheduler

Storage backends: local, s3

Environment:
  PGVAULT_DIR             data directory (default ~/.pgvault)
  PGVAULT_STORAGE         default storage backend (default local)
  PGVAULT_MASTER_KEY      master key for backup encryption (32 bytes, hex or base64)
  PGVAULT_S3_BUCKET       S3 bucket name
  PGVAULT_S3_REGION       S3 region (default us-east-1)
  PGVAULT_S3_ENDPOINT     S3-compatible endpoint (MinIO, R2, B2, Spaces)
  PGVAULT_S3_PREFIX       key prefix inside the bucket
  PGVAULT_S3_PATH_STYLE   force path-style addressing (default: on when an endpoint is set)
  AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY   S3 credentials
`

func main() {
	err := run(os.Args[1:])
	if err == nil {
		return
	}
	if errors.Is(err, errHelp) {
		os.Exit(0)
	}
	fmt.Fprintln(os.Stderr, "pgvault:", err)
	os.Exit(1)
}

func run(args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return errors.New("no command given")
	}

	command, rest := args[0], args[1:]

	switch command {
	case "add":
		return cmdAdd(rest)
	case "databases", "dbs":
		return cmdDatabases(rest)
	case "backup":
		return cmdBackup(rest)
	case "backups":
		return cmdBackups(rest)
	case "inspect":
		return cmdInspect(rest)
	case "schedule":
		return cmdSchedule(rest)
	case "daemon":
		return cmdDaemon(rest)
	case "help", "-h", "--help":
		fmt.Print(usage)
		return nil
	default:
		fmt.Fprint(os.Stderr, usage)
		return fmt.Errorf("unknown command %q", command)
	}
}
