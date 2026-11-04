package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/straiker-ai/ascend-tunnel/internal/config"
)

func TestKeyPrintsTheBlobToPaste(t *testing.T) {
	dir := t.TempDir()
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"key", "--state-dir", dir}, &out, &errOut); code != 0 {
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
	run(context.Background(), []string{"key", "--state-dir", dir}, &out, &errOut)
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
	if code := run(context.Background(), []string{"-c", p}, &out, &errOut); code != 2 || !strings.Contains(errOut.String(), "allow must list") {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
}

func TestUsageAndVersion(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"version"}, &out, &errOut); code != 0 || !strings.HasPrefix(out.String(), "ascend-tunnel ") {
		t.Fatalf("version: %d %q", code, out.String())
	}
	if code := run(context.Background(), []string{"nope"}, &out, &errOut); code != 2 || !strings.Contains(errOut.String(), "unknown command") {
		t.Fatalf("unknown command: %d %q", code, errOut.String())
	}
	t.Setenv("TUNNEL_TENANT", "")
	if code := run(context.Background(), []string{"run", "--allow", "h:1"}, &out, &errOut); code != 2 || !strings.Contains(errOut.String(), "org id") {
		t.Fatalf("a missing org id is a usage error: %d %q", code, errOut.String())
	}
}

func TestCheckAppNeedsNoOrgAndMakesNoKey(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	var out, errOut bytes.Buffer
	// 127.0.0.1:1 is closed: the check fails there, without contacting Straiker.
	code := run(context.Background(), []string{"check", "app", "--allow", "127.0.0.1:1", "--state-dir", dir}, &out, &errOut)
	if code != 1 || !strings.Contains(out.String(), "== Apps") || strings.Contains(out.String(), "== Tunnel") {
		t.Fatalf("exit %d:\n%s%s", code, out.String(), errOut.String())
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("checking apps never creates an agent key")
	}
}

func TestTheServiceRunsWhatWasCheckedAtInstall(t *testing.T) {
	cfg, err := config.Load("", config.Overrides{Tenant: "1", Env: "dev", StateDir: "state", Allow: []string{"chat.corp.internal", "app2:80"}},
		func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	if err := absPaths(cfg); err != nil || !filepath.IsAbs(cfg.StateDir) || !filepath.IsAbs(cfg.AuditLog) {
		t.Fatalf("a service does not start in this directory: %v %+v", err, cfg)
	}
	got := strings.Join(serviceArgs(cfg), " ")
	for _, want := range []string{"run --org 1 --relay wss://ascendai-bridge.dev.straiker.ai/tunnel --state-dir " + cfg.StateDir,
		"--host-key " + config.Environments["dev"].HostKey, "--allow chat.corp.internal:443 --allow app2:80"} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in %q", want, got)
		}
	}
}

func TestServiceInstallRefusesABadAllowlistBeforeInstallingAnything(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"service", "install", "--org", "1", "--allow", "bad host!"}, &out, &errOut); code != 2 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
}
