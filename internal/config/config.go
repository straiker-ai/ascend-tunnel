// Package config is the agent's configuration: an optional YAML file, then TUNNEL_* environment
// variables, then command-line flags, each overriding the one before. Validation is strict: the
// allowlist is the security boundary, so anything ambiguous is refused at start.
package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/straiker-ai/ascend-tunnel/internal/identity"
)

// Environment is a Straiker deployment the agent can connect to without being told its address.
type Environment struct {
	Relay   string // the relay's WebSocket URL
	HostKey string // the relay's SSH host key, pinned; empty until published for that environment
}

// Environments are built in, so a customer configures only their org id and allowlist.
var Environments = map[string]Environment{
	"prod": {Relay: "wss://ascendai-bridge.prod.straiker.ai/tunnel"},
}

// DefaultEnv is the environment used when neither a relay nor an environment is given.
const DefaultEnv = "prod"

const (
	maxSocketPath = 107 // sun_path is 108 bytes including the NUL
	maxFanout     = 16
)

var (
	tenantRE = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)
	hostRE   = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$`)
)

// Forward is one allowlisted target: the relay sends its tunnel name to this agent's sockets, and the
// agent dials Host:Port here. The allowlist IS the list of forwards - nothing else is ever reached.
type Forward struct {
	Host string
	Port int
}

// Addr is the target's dial address.
func (f Forward) Addr() string { return net.JoinHostPort(f.Host, strconv.Itoa(f.Port)) }

// Config is the validated configuration.
type Config struct {
	Tenant   string
	Relay    string
	HostKey  string // the relay's pinned host key line; empty means not pinned
	StateDir string
	CAFile   string // an extra CA to trust (e.g. a TLS-inspecting proxy's), besides the system store
	AuditLog string
	Fanout   int
	Forwards []Forward
}

// Overrides are values from the command line; zero values mean "not given".
type Overrides struct {
	Tenant, Relay, HostKey, StateDir, CAFile, AuditLog, Env string
	Fanout                                                  int
	Allow                                                   []string // host:port
}

type file struct {
	Tenant   string      `yaml:"tenant"`
	Env      string      `yaml:"env"`
	Relay    string      `yaml:"relay"`
	HostKey  string      `yaml:"host_key"`
	StateDir string      `yaml:"state_dir"`
	CAFile   string      `yaml:"ca_file"`
	AuditLog string      `yaml:"audit_log"`
	Fanout   int         `yaml:"fanout"`
	Allow    []allowItem `yaml:"allow"`
}

// allowItem accepts `{host: h, port: p}` or the string "h:p".
type allowItem struct{ raw string }

func (a *allowItem) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		a.raw = n.Value
		return nil
	}
	var m struct {
		Host string `yaml:"host"`
		Port string `yaml:"port"`
	}
	if err := n.Decode(&m); err != nil {
		return err
	}
	a.raw = m.Host + "\x00" + m.Port
	return nil
}

// Load reads path (optional: "" means no file), applies env (via getenv) and o, and validates.
func Load(path string, o Overrides, getenv func(string) string) (*Config, error) {
	var f file
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("config: %w", err)
		}
		if err := yaml.Unmarshal(data, &f); err != nil {
			return nil, fmt.Errorf("config %s: %w", path, err)
		}
	}
	pick := func(flag, env, fromFile string) string {
		for _, v := range []string{flag, getenv(env), fromFile} {
			if v = strings.TrimSpace(v); v != "" {
				return v
			}
		}
		return ""
	}
	c := &Config{
		Tenant:   pick(o.Tenant, "TUNNEL_TENANT", f.Tenant),
		Relay:    pick(o.Relay, "TUNNEL_RELAY", f.Relay),
		HostKey:  pick(o.HostKey, "TUNNEL_HOST_KEY", f.HostKey),
		StateDir: pick(o.StateDir, "TUNNEL_STATE_DIR", f.StateDir),
		CAFile:   pick(o.CAFile, "TUNNEL_CA_FILE", f.CAFile),
		AuditLog: pick(o.AuditLog, "TUNNEL_AUDIT_LOG", f.AuditLog),
	}
	if !tenantRE.MatchString(c.Tenant) {
		return nil, errors.New("tenant (your Straiker org id) is required")
	}
	if err := c.resolveRelay(pick(o.Env, "TUNNEL_ENV", f.Env)); err != nil {
		return nil, err
	}
	fanout, err := pickInt(o.Fanout, getenv("TUNNEL_FANOUT"), f.Fanout)
	if err != nil || fanout < 1 || fanout > maxFanout {
		return nil, fmt.Errorf("fanout must be 1..%d", maxFanout)
	}
	c.Fanout = fanout
	if c.StateDir == "" {
		c.StateDir = DefaultStateDir()
	}
	if c.AuditLog == "" {
		c.AuditLog = filepath.Join(c.StateDir, "connections.jsonl")
	}
	allow := o.Allow
	if len(allow) == 0 {
		if env := getenv("TUNNEL_ALLOW"); env != "" {
			allow = strings.Split(env, ",")
		} else {
			for _, a := range f.Allow {
				allow = append(allow, a.raw)
			}
		}
	}
	if c.Forwards, err = parseForwards(allow, c.Fanout); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Config) resolveRelay(env string) error {
	if c.Relay == "" {
		if env == "" {
			env = DefaultEnv
		}
		e, ok := Environments[env]
		if !ok {
			return fmt.Errorf("unknown environment %q: give the relay URL instead", env)
		}
		c.Relay = e.Relay
	}
	if !strings.HasPrefix(c.Relay, "wss://") {
		return errors.New("relay must be a wss:// URL")
	}
	if c.HostKey == "" {
		for _, e := range Environments {
			if e.Relay == c.Relay {
				c.HostKey = e.HostKey
			}
		}
	}
	return nil
}

func pickInt(flag int, env string, fromFile int) (int, error) {
	switch {
	case flag != 0:
		return flag, nil
	case env != "":
		return strconv.Atoi(strings.TrimSpace(env))
	case fromFile != 0:
		return fromFile, nil
	}
	return 1, nil
}

func parseForwards(allow []string, fanout int) ([]Forward, error) {
	var out []Forward
	seen := map[string]bool{}
	for i, raw := range allow {
		host, port, ok := strings.Cut(raw, "\x00") // a {host, port} mapping
		if !ok {
			var err error
			if host, port, err = net.SplitHostPort(strings.TrimSpace(raw)); err != nil {
				return nil, fmt.Errorf("allow[%d] needs host and port: %q", i, raw)
			}
		}
		if host == "" || port == "" {
			return nil, fmt.Errorf("allow[%d] needs host and port", i)
		}
		f := Forward{Host: strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")}
		p, err := strconv.Atoi(strings.TrimSpace(port))
		if err != nil || p < 1 || p > 65535 || !hostRE.MatchString(f.Host) {
			return nil, fmt.Errorf("invalid forward %s:%s", host, port)
		}
		f.Port = p
		if len(identity.SocketPath(identity.SocketDir("", ""), f.Host, fanout-1)) > maxSocketPath {
			return nil, fmt.Errorf("host %q is too long for a relay socket name", f.Host)
		}
		if seen[f.Host] {
			return nil, errors.New("one allow entry per host: the tunnel name carries no port")
		}
		seen[f.Host] = true
		out = append(out, f)
	}
	if len(out) == 0 {
		return nil, errors.New("allow must list at least one target (host:port)")
	}
	return out, nil
}

// DefaultStateDir is where the agent keeps its key when not told: a per-user directory on a laptop,
// /var/lib/straiker-tunnel for a Linux service running as root.
func DefaultStateDir() string {
	switch runtime.GOOS {
	case "windows":
		if d := os.Getenv("LOCALAPPDATA"); d != "" {
			return filepath.Join(d, "Straiker", "ascend-tunnel")
		}
	case "darwin":
		if h, err := os.UserHomeDir(); err == nil {
			return filepath.Join(h, "Library", "Application Support", "Straiker", "ascend-tunnel")
		}
	}
	if os.Geteuid() == 0 {
		return "/var/lib/straiker-tunnel"
	}
	if d := os.Getenv("XDG_STATE_HOME"); d != "" {
		return filepath.Join(d, "ascend-tunnel")
	}
	if h, err := os.UserHomeDir(); err == nil {
		return filepath.Join(h, ".local", "state", "ascend-tunnel")
	}
	return "/var/lib/straiker-tunnel"
}

// DefaultPath is the config file read when none is named, if it exists.
func DefaultPath() string {
	if runtime.GOOS == "windows" {
		if d := os.Getenv("ProgramData"); d != "" {
			return filepath.Join(d, "Straiker", "ascend-tunnel", "agent.yaml")
		}
		return ""
	}
	return "/etc/straiker/agent.yaml"
}
