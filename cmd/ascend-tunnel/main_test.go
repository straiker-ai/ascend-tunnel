package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestKeyPrintsTheBlobToPaste(t *testing.T) {
	dir := t.TempDir()
	var out, errOut bytes.Buffer
	if code := run([]string{"key", "--state-dir", dir}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	key := strings.TrimSpace(out.String())
	if !strings.HasPrefix(key, "AAAAC3NzaC1lZDI1NTE5") || strings.Contains(key, " ") {
		t.Fatalf("want the bare ed25519 blob, got %q", key)
	}
	if !strings.Contains(errOut.String(), "_tunnel_agent_keys") {
		t.Fatalf("the hint goes to stderr: %q", errOut.String())
	}
	out.Reset()
	run([]string{"key", "--state-dir", dir}, &out, &errOut)
	if strings.TrimSpace(out.String()) != key {
		t.Fatal("the key is stable across runs")
	}
}

func TestAConfigFileWithNoSubcommandRuns(t *testing.T) {
	// The form earlier agents and their containers use: `-c /path/agent.yaml`. A config error proves the
	// file was read as a run (exit 2), without dialling anything.
	p := filepath.Join(t.TempDir(), "agent.yaml")
	if err := os.WriteFile(p, []byte("tenant: '1'\nallow: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := run([]string{"-c", p}, &out, &errOut); code != 2 || !strings.Contains(errOut.String(), "allow must list") {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
}

func TestUsageAndVersion(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"version"}, &out, &errOut); code != 0 || !strings.HasPrefix(out.String(), "ascend-tunnel ") {
		t.Fatalf("version: %d %q", code, out.String())
	}
	if code := run([]string{"nope"}, &out, &errOut); code != 2 || !strings.Contains(errOut.String(), "unknown command") {
		t.Fatalf("unknown command: %d %q", code, errOut.String())
	}
	t.Setenv("TUNNEL_TENANT", "")
	if code := run([]string{"run", "--allow", "h:1"}, &out, &errOut); code != 2 || !strings.Contains(errOut.String(), "org id") {
		t.Fatalf("a missing org id is a usage error: %d %q", code, errOut.String())
	}
}
