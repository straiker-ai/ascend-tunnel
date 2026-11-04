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
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/straiker-ai/ascend-tunnel/internal/agent"
	"github.com/straiker-ai/ascend-tunnel/internal/config"
	"github.com/straiker-ai/ascend-tunnel/internal/identity"
	"github.com/straiker-ai/ascend-tunnel/internal/service"
)

// Set at build time (-ldflags "-X main.version=... -X main.commit=...").
var (
	version = "dev"
	commit  = "none"
)

const usage = `ascend-tunnel - the Straiker Ascend tunnel agent

Usage:
  ascend-tunnel [run] [flags]          run the agent (the default)
  ascend-tunnel check [flags]          check the setup: the tunnel to Straiker, then your apps
  ascend-tunnel check tunnel [flags]   only this machine to Straiker (no -allow needed)
  ascend-tunnel check app [flags]      only this machine to your apps (no -org needed)
  ascend-tunnel key                    print this agent's key, to paste into Ascend apps
  ascend-tunnel service install [flags]
                                       keep it running as a service (same flags as run): Windows service,
                                       macOS LaunchAgent, or Linux systemd user service
  ascend-tunnel service status         whether the service runs
  ascend-tunnel service uninstall      remove the service (the key stays)
  ascend-tunnel version                print the version

Quick start:
  ascend-tunnel --org <your Straiker org id> --allow chat.corp.internal

Run "ascend-tunnel run -h" for every flag. Flags override TUNNEL_* environment
variables, which override the config file (-c, default %s).
`

func main() {
	if code, ok := service.RunIfService(func(ctx context.Context) int {
		return run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	}); ok {
		os.Exit(code)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	cmd := "run"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	switch cmd {
	case "run", "check":
		return runAgent(ctx, cmd, args, stdout, stderr)
	case "service":
		return serviceCmd(args, stdout, stderr)
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

// agentFlags are run's flags, which check and service install take too.
func agentFlags(cmd string, stderr io.Writer) (*flag.FlagSet, *string, *config.Overrides, *listFlag) {
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	var path string
	var o config.Overrides
	var allow listFlag
	fs.StringVar(&path, "c", "", "config file (YAML)")
	fs.StringVar(&path, "config", "", "config file (YAML)")
	fs.StringVar(&o.Tenant, "org", "", "your Straiker org id")
	fs.StringVar(&o.Tenant, "tenant", "", "same as -org")
	fs.Var(&allow, "allow", "a target this agent may reach, host or host:port, port 443 if omitted (repeat for more)")
	fs.StringVar(&o.Env, "env", "", "Straiker environment (default "+config.DefaultEnv+")")
	fs.StringVar(&o.Relay, "relay", "", "relay URL (wss://...), instead of -env")
	fs.StringVar(&o.HostKey, "host-key", "", "the relay's SSH host key to pin")
	fs.StringVar(&o.StateDir, "state-dir", "", "where this agent keeps its key (default "+config.DefaultStateDir()+")")
	fs.StringVar(&o.CAFile, "ca-file", "", "extra CA to trust (PEM), e.g. your proxy's")
	fs.StringVar(&o.AuditLog, "audit-log", "", "audit log file (default <state-dir>/connections.jsonl)")
	fs.IntVar(&o.Fanout, "fanout", 0, "links to the relay, for throughput (1-16, default 1)")
	return fs, &path, &o, &allow
}

func runAgent(ctx context.Context, cmd string, args []string, stdout, stderr io.Writer) int {
	scope := agent.CheckAll
	if cmd == "check" && len(args) > 0 {
		switch args[0] {
		case "tunnel":
			scope, args = agent.CheckTunnel, args[1:]
		case "app", "apps":
			scope, args = agent.CheckApps, args[1:]
		}
	}
	fs, pathp, op, allowp := agentFlags(cmd, stderr)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	path, o, allow := *pathp, *op, *allowp
	o.Allow = allow
	o.NoTenant = cmd == "check" && scope == agent.CheckApps
	o.NoAllow = cmd == "check" && scope == agent.CheckTunnel
	cfg, err := config.Load(configPath(path), o, os.Getenv)
	if err != nil {
		fmt.Fprintln(stderr, "ascend-tunnel:", err)
		return 2
	}
	var id *identity.Identity
	switch {
	case cmd != "check":
		id, err = identity.Load(cfg.Tenant, cfg.StateDir)
	case scope != agent.CheckApps: // a check never creates the agent's key; apps need none at all
		id, err = identity.Peek(cfg.Tenant, cfg.StateDir)
	}
	if err != nil {
		fmt.Fprintln(stderr, "ascend-tunnel:", err)
		return 1
	}
	if cmd == "check" {
		a, err := agent.New(cfg, id, nil)
		if err != nil {
			fmt.Fprintln(stderr, "ascend-tunnel:", err)
			return 1
		}
		if !a.Check(ctx, stdout, scope) {
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

// serviceCmd installs, inspects or removes the service that keeps the agent running without a terminal.
func serviceCmd(args []string, stdout, stderr io.Writer) int {
	sub := ""
	if len(args) > 0 {
		sub, args = args[0], args[1:]
	}
	switch sub {
	case "install":
		return serviceInstall(args, stdout, stderr)
	case "uninstall":
		if err := service.Uninstall(stdout); err != nil {
			fmt.Fprintln(stderr, "ascend-tunnel:", err)
			return 1
		}
		fmt.Fprintln(stdout, "Removed the ascend-tunnel service. The agent key stays (ascend-tunnel key).")
		return 0
	case "status":
		st, err := service.Status()
		if err != nil {
			fmt.Fprintln(stderr, "ascend-tunnel:", err)
			return 1
		}
		fmt.Fprintln(stdout, "ascend-tunnel service:", st)
		return 0
	}
	fmt.Fprintln(stderr, "usage: ascend-tunnel service install [run's flags] | status | uninstall")
	return 2
}

func serviceInstall(args []string, stdout, stderr io.Writer) int {
	fs, path, o, allow := agentFlags("service install", stderr)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	o.Allow = *allow
	cfg, err := config.Load(configPath(*path), *o, os.Getenv)
	if err == nil {
		err = absPaths(cfg)
	}
	if err != nil {
		fmt.Fprintln(stderr, "ascend-tunnel:", err)
		return 2
	}
	// The key the service uses: this machine's, created now if it has none, so it can be pasted before the service runs.
	id, err := identity.Load(cfg.Tenant, cfg.StateDir)
	if err != nil {
		fmt.Fprintln(stderr, "ascend-tunnel:", err)
		return 1
	}
	env, err := service.ProxyEnv(os.Getenv)
	if err != nil {
		fmt.Fprintln(stderr, "ascend-tunnel:", err)
		return 2
	}
	exe, err := service.Executable()
	if err != nil {
		fmt.Fprintln(stderr, "ascend-tunnel:", err)
		return 1
	}
	if err := service.Install(service.Spec{Exe: exe, Args: serviceArgs(cfg), StateDir: cfg.StateDir, Env: env}, stdout); err != nil {
		fmt.Fprintln(stderr, "ascend-tunnel:", err)
		return 1
	}
	fmt.Fprintf(stdout, "Installed ascend-tunnel as %s.\n", service.Kind)
	fmt.Fprintf(stdout, "  org %s, agent %s\n  agent key (each app's _tunnel_agent_keys): %s\n", cfg.Tenant, id.AgentID,
		identity.PasteForm(id.PublicKey))
	for _, f := range cfg.Forwards {
		fmt.Fprintf(stdout, "  %s -> app URL %s (plus the app's path)\n", f.Addr(), f.AppURL())
	}
	fmt.Fprintf(stdout, "  log: %s\n  ascend-tunnel service status | ascend-tunnel service uninstall\n", cfg.AuditLog)
	return 0
}

// absPaths makes the config's files absolute: a service does not start in the installer's directory.
func absPaths(cfg *config.Config) error {
	for _, p := range []*string{&cfg.StateDir, &cfg.CAFile, &cfg.AuditLog} {
		if *p == "" {
			continue
		}
		abs, err := filepath.Abs(*p)
		if err != nil {
			return err
		}
		*p = abs
	}
	return nil
}

// serviceArgs is run's command line for cfg, with every value resolved: the service reads no config file or
// TUNNEL_* variable, so what was checked at install is what runs.
func serviceArgs(cfg *config.Config) []string {
	a := []string{"run", "--org", cfg.Tenant, "--relay", cfg.Relay, "--state-dir", cfg.StateDir, "--audit-log", cfg.AuditLog}
	if cfg.HostKey != "" {
		a = append(a, "--host-key", cfg.HostKey)
	}
	if cfg.CAFile != "" {
		a = append(a, "--ca-file", cfg.CAFile)
	}
	if cfg.Fanout > 1 {
		a = append(a, "--fanout", strconv.Itoa(cfg.Fanout))
	}
	for _, f := range cfg.Forwards {
		a = append(a, "--allow", f.Addr())
	}
	return a
}
