package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// helpTestWriter swaps the help output for the duration of a test.
func helpTestWriter(t *testing.T) *bytes.Buffer {
	t.Helper()

	var out bytes.Buffer
	old := helpWriter
	helpWriter = &out
	t.Cleanup(func() { helpWriter = old })
	return &out
}

func TestHelpTopics(t *testing.T) {
	commands := []string{
		"add", "databases", "backup", "backups", "inspect", "tunnel",
		"docker", "schedule", "remove", "daemon", "help", "environment",
	}

	for _, name := range commands {
		topic, ok := helpTopics[name]
		if !ok {
			t.Errorf("%s: no help topic", name)
			continue
		}
		if topic.Summary == "" {
			t.Errorf("%s: empty summary", name)
		}
		if topic.Usage == "" {
			t.Errorf("%s: empty usage", name)
		}
		if len(topic.Examples) == 0 {
			t.Errorf("%s: no examples", name)
		}

		for i, example := range topic.Examples {
			if example.Title == "" {
				t.Errorf("%s: example %d has no title", name, i)
			}
			if strings.TrimSpace(example.Command) == "" {
				t.Errorf("%s: example %d has no command", name, i)
			}
			if strings.TrimSpace(example.Output) == "" {
				t.Errorf("%s: example %d has no output", name, i)
			}
			if first, _, _ := strings.Cut(example.Command, "\n"); !strings.Contains(first, "pgvault ") {
				t.Errorf("%s: example %d does not invoke pgvault: %q", name, i, first)
			}
		}
	}
}

func TestHelpContainsNoRealSecrets(t *testing.T) {
	// Real values from development must never leak into help text.
	forbidden := []string{"15.204.12.103", "vps-09bf6134", "Mo4vin"}

	for name, topic := range helpTopics {
		text := topic.Usage + topic.Flags + topic.Summary
		for _, paragraph := range topic.Details {
			text += paragraph
		}
		for _, example := range topic.Examples {
			text += example.Command + example.Output + example.Note
		}

		for _, secret := range forbidden {
			if strings.Contains(text, secret) {
				t.Errorf("%s: help text contains %q", name, secret)
			}
		}
	}
}

func TestGlobalHelpListsCommands(t *testing.T) {
	var out bytes.Buffer
	printGlobalHelp(&out)

	for name := range helpTopics {
		if !strings.Contains(out.String(), name) {
			t.Errorf("global help does not mention %q", name)
		}
	}
}

func TestPrintTopic(t *testing.T) {
	var out bytes.Buffer
	if !printTopic(&out, "add") {
		t.Fatal("add topic not found")
	}

	text := out.String()
	for _, want := range []string{
		"pgvault add — register a database",
		"Usage:",
		"Flags:",
		"Examples:",
		"pgvault add qa-robocalling",
		"docker saved for qa-robocalling",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("add help does not contain %q", want)
		}
	}

	// Aliases resolve to their topic.
	out.Reset()
	if !printTopic(&out, "dbs") {
		t.Fatal("dbs alias not resolved")
	}
	if !strings.Contains(out.String(), "pgvault databases") {
		t.Fatal("dbs alias does not render the databases topic")
	}

	if printTopic(&out, "nope") {
		t.Fatal("unknown topic reported as found")
	}
}

func TestRunHelp(t *testing.T) {
	out := helpTestWriter(t)

	if err := run([]string{"help"}); err != nil {
		t.Fatalf("help: %v", err)
	}
	if !strings.Contains(out.String(), "Commands:") {
		t.Fatal("global help missing from output")
	}

	out.Reset()
	if err := run([]string{"help", "docker"}); err != nil {
		t.Fatalf("help docker: %v", err)
	}
	if !strings.Contains(out.String(), "pgvault docker") {
		t.Fatal("docker help missing from output")
	}

	if err := run([]string{"help", "nope"}); err == nil {
		t.Fatal("expected an error for an unknown topic")
	} else if !strings.Contains(err.Error(), "no help for") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCommandHelpFlag(t *testing.T) {
	out := helpTestWriter(t)

	for _, command := range []string{"add", "backup", "docker", "tunnel"} {
		out.Reset()

		err := run([]string{command, "--help"})
		if !errors.Is(err, errHelp) {
			t.Fatalf("%s --help: got %v, want errHelp", command, err)
		}
		if !strings.Contains(out.String(), "pgvault "+command) {
			t.Errorf("%s --help did not print the command page", command)
		}
	}
}
