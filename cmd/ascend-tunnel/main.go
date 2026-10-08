// Command ascend-tunnel is the Straiker Ascend tunnel agent: it lets Ascend reach AI apps inside a
// private network through one outbound HTTPS connection. See README.md.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"

	"github.com/straiker-ai/ascend-tunnel/internal/agent"
	"github.com/straiker-ai/ascend-tunnel/internal/config"
	"github.com/straiker-ai/ascend-tunnel/internal/identity"
)

// Set at build time (-ldflags "-X main.version=... -X main.commit=...").
var (
	version = "dev"
	commit  = "none"
)

const usage = `ascend-tunnel - the Straiker Ascend tunnel agent

Usage:
  ascend-tunnel [run] [flags]   run the agent (the default)
  ascend-tunnel check [flags]   check the setup: relay, proxy, TLS, key, targets
  ascend-tunnel key             print this agent's key, to paste into Ascend apps
  ascend-tunnel version         print the version

Quick start:
  ascend-tunnel --org <your Straiker org id> --allow chat.corp.internal:443

Run "ascend-tunnel run -h" for every flag. Flags override TUNNEL_* environment
variables, which override the config file (-c, default %s).
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	cmd := "run"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	switch cmd {
	case "run", "check":
		return runAgent(cmd, args, stdout, stderr)
	case "key":
		return printKey(args, stdout, stderr)
	case "version":
		fmt.Fprintf(stdout, "ascend-tunnel %s (%s) %s %s/%s\n", version, commit, runtime.Version(), runtime.GOOS, runtime.GOARCH)
		return 0
	case "help":
		fmt.Fprintf(stdout, usage, config.DefaultPath())
		return 0
	}
	fmt.Fprintf(stderr, "unknown command %q\n\n"+usage, cmd, config.DefaultPath())
	return 2
}

type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

func runAgent(cmd string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	var path string
	var o config.Overrides
	var allow listFlag
	fs.StringVar(&path, "c", "", "config file (YAML)")
	fs.StringVar(&path, "config", "", "config file (YAML)")
	fs.StringVar(&o.Tenant, "org", "", "your Straiker org id")
	fs.StringVar(&o.Tenant, "tenant", "", "same as -org")
	fs.Var(&allow, "allow", "a target this agent may reach, host:port (repeat for more)")
	fs.StringVar(&o.Env, "env", "", "Straiker environment (default "+config.DefaultEnv+")")
	fs.StringVar(&o.Relay, "relay", "", "relay URL (wss://...), instead of -env")
	fs.StringVar(&o.HostKey, "host-key", "", "the relay's SSH host key to pin")
	fs.StringVar(&o.StateDir, "state-dir", "", "where this agent keeps its key (default "+config.DefaultStateDir()+")")
	fs.StringVar(&o.CAFile, "ca-file", "", "extra CA to trust (PEM), e.g. your proxy's")
	fs.StringVar(&o.AuditLog, "audit-log", "", "audit log file (default <state-dir>/connections.jsonl)")
	fs.IntVar(&o.Fanout, "fanout", 0, "links to the relay, for throughput (1-16, default 1)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	o.Allow = allow
	cfg, err := config.Load(configPath(path), o, os.Getenv)
	if err != nil {
		fmt.Fprintln(stderr, "ascend-tunnel:", err)
		return 2
	}
	id, err := identity.Load(cfg.Tenant, cfg.StateDir)
	if err != nil {
		fmt.Fprintln(stderr, "ascend-tunnel:", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if cmd == "check" {
		a, err := agent.New(cfg, id, nil)
		if err != nil {
			fmt.Fprintln(stderr, "ascend-tunnel:", err)
			return 1
		}
		if !a.Check(ctx, stdout) {
			return 1
		}
		return 0
	}
	a, err := agent.New(cfg, id, agent.NewAudit(cfg.AuditLog, stdout))
	if err != nil {
		fmt.Fprintln(stderr, "ascend-tunnel:", err)
		return 1
	}
	a.Run(ctx)
	return 0
}

// configPath is the file to read: the flag, else TUNNEL_CONFIG, else the default path if it exists.
func configPath(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	if env := os.Getenv("TUNNEL_CONFIG"); env != "" {
		return env
	}
	if p := config.DefaultPath(); p != "" {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func printKey(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("key", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := os.Getenv("TUNNEL_STATE_DIR")
	if dir == "" {
		dir = config.DefaultStateDir()
	}
	fs.StringVar(&dir, "state-dir", dir, "where this agent keeps its key")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	id, err := identity.Load("", dir)
	if err != nil {
		fmt.Fprintln(stderr, "ascend-tunnel:", err)
		return 1
	}
	fmt.Fprintln(stdout, identity.PasteForm(id.PublicKey))
	fmt.Fprintf(stderr, "# agent id %s: paste the line above into each Ascend app's _tunnel_agent_keys\n", id.AgentID)
	return 0
}
