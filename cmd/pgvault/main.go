package main

import (
	"errors"
	"fmt"
	"os"
)

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
		return errors.New(`no command given (run "pgvault help")`)
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
	case "tunnel":
		return cmdTunnel(rest)
	case "docker":
		return cmdDocker(rest)
	case "remove":
		return cmdRemove(rest)
	case "schedule":
		return cmdSchedule(rest)
	case "daemon":
		return cmdDaemon(rest)
	case "help", "-h", "--help":
		return cmdHelp(rest)
	default:
		fmt.Fprint(os.Stderr, usage)
		return fmt.Errorf("unknown command %q (run \"pgvault help\")", command)
	}
}
