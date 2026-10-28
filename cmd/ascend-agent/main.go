// Command ascend-agent is the local half of the Straiker Ascend Agent: an MCP server on a machine inside the customer's
// network that serves tools to Straiker's cloud agents over one outbound HTTPS connection, under a
// policy the customer owns. See docs/ascend-agent.md. Experimental.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/straiker-ai/ascend-tunnel/internal/agent"
	"github.com/straiker-ai/ascend-tunnel/internal/agenthost"
	"github.com/straiker-ai/ascend-tunnel/internal/agenthost/mcp"
	"github.com/straiker-ai/ascend-tunnel/internal/agenthost/netx"
	"github.com/straiker-ai/ascend-tunnel/internal/agenthost/packs"
	"github.com/straiker-ai/ascend-tunnel/internal/agenthost/policy"
	"github.com/straiker-ai/ascend-tunnel/internal/agenthost/stream"
	"github.com/straiker-ai/ascend-tunnel/internal/agenthost/token"
	"github.com/straiker-ai/ascend-tunnel/internal/agenthost/wire"
	"github.com/straiker-ai/ascend-tunnel/internal/config"
	"github.com/straiker-ai/ascend-tunnel/internal/identity"
)

// Set at build time (-ldflags "-X main.version=... -X main.commit=...").
var (
	version = "dev"
	commit  = "none"
)

const usage = `ascend-agent - Straiker Ascend's agent in your terminal (experimental)

Talk to Ascend Agent; while it runs, this machine serves the tools Straiker's agents use,
over one outbound HTTPS connection, for the sites you approve.

Usage:
  ascend-agent                         start a conversation (signs you in the first time)
  ascend-agent login                   sign in with a Straiker personal access token
  ascend-agent logout                  forget the saved token
  ascend-agent run -policy <file>      serve tools unattended, under a policy file (a service)
  ascend-agent policy check|show       validate or explain a policy file
  ascend-agent key                     print this machine's key (the same key ascend-tunnel uses)
  ascend-agent version                 print the version

A policy file is optional for a conversation: it caps what you may approve. It is -policy, else
ASCEND_AGENT_POLICY, else %s if present.
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return chat(ctx, args, stdin, stdout, stderr) // like `claude`: no command opens a session
	}
	cmd, args := args[0], args[1:]
	switch cmd {
	case "run":
		return runHost(ctx, args, stdout, stderr)
	case "serve":
		return serve(ctx, args, stdin, stdout, stderr)
	case "policy":
		return policyCmd(args, stdout, stderr)
	case "key":
		return printKey(args, stdout, stderr)
	case "chat":
		return chat(ctx, args, stdin, stdout, stderr)
	case "login":
		return login(ctx, args, stdin, stdout, stderr)
	case "logout":
		return logout(stdout, stderr)
	case "version":
		fmt.Fprintf(stdout, "ascend-agent %s (%s) %s %s/%s protocol %s\n", version, commit, runtime.Version(), runtime.GOOS, runtime.GOARCH, wire.Version)
		return 0
	case "help", "-h", "-help", "--help":
		fmt.Fprintf(stdout, usage, defaultPolicyPath())
		return 0
	}
	fmt.Fprintf(stderr, "unknown command %q\n\n"+usage, cmd, defaultPolicyPath())
	return 2
}

// settings are the flags, the policy file and the defaults, resolved in that order.
type settings struct {
	policyPath  string
	pol         *policy.Policy
	org         string
	env         string
	api         string
	sessionKeys []ed25519.PublicKey
	stateDir    string
	auditLog    string
	caFile      string
}

type flags struct {
	policy, org, env, api, sessionKey, stateDir, auditLog, caFile string
}

func (f *flags) register(fs *flag.FlagSet, full bool) {
	fs.StringVar(&f.policy, "policy", "", "policy file (YAML)")
	fs.StringVar(&f.stateDir, "state-dir", "", "where this machine's key is kept (default "+config.DefaultStateDir()+", shared with ascend-tunnel)")
	fs.StringVar(&f.auditLog, "audit-log", "", "audit log file (default <state-dir>/ascend-agent-audit.jsonl)")
	if full {
		fs.StringVar(&f.org, "org", "", "your Straiker org id (default: the policy's org)")
		fs.StringVar(&f.env, "env", "", "Straiker environment: prod, stage or dev (default: the policy's env, else prod)")
		fs.StringVar(&f.api, "api", "", "agent API base URL, instead of -env")
		fs.StringVar(&f.sessionKey, "session-key", "", "Straiker's session-token key to pin (default: the policy's session_key and session_keys)")
		fs.StringVar(&f.caFile, "ca-file", "", "extra CA to trust (PEM), e.g. your proxy's (default: the policy's ca_file)")
	}
}

func resolve(f flags, needCloud bool) (*settings, error) {
	s := &settings{policyPath: f.policy}
	if s.policyPath == "" {
		s.policyPath = os.Getenv("ASCEND_AGENT_POLICY")
	}
	if s.policyPath == "" {
		if p := defaultPolicyPath(); p != "" {
			if _, err := os.Stat(p); err == nil {
				s.policyPath = p
			}
		}
	}
	if s.policyPath == "" {
		return nil, errors.New("no policy file: pass -policy <file> (docs/ascend-agent.md has an example)")
	}
	pol, err := policy.Load(s.policyPath)
	if err != nil {
		return nil, err
	}
	s.pol = pol
	s.org = pick(f.org, pol.Org)
	s.env = pick(f.env, pol.Env, config.DefaultEnv)
	s.caFile = pick(f.caFile, pol.CAFile)
	s.stateDir = pick(f.stateDir, os.Getenv("TUNNEL_STATE_DIR"), config.DefaultStateDir())
	s.auditLog = pick(f.auditLog, pol.Audit.File, filepath.Join(s.stateDir, "ascend-agent-audit.jsonl"))
	if !needCloud {
		return s, nil
	}
	if s.org == "" {
		return nil, errors.New("no org: set org in the policy, or pass -org")
	}
	s.api = pick(f.api, pol.API, wire.DefaultBase[s.env])
	if s.api == "" {
		return nil, fmt.Errorf("unknown env %q: use prod, stage or dev, or pass -api", s.env)
	}
	if err := checkAPI(s.api); err != nil {
		return nil, err
	}
	keys := pol.AllSessionKeys()
	if f.sessionKey != "" {
		keys = []string{f.sessionKey}
	}
	if len(keys) == 0 {
		return nil, errors.New("no session key: set session_key in the policy to the key Straiker publishes for your environment")
	}
	if s.sessionKeys, err = parseKeys(keys); err != nil {
		return nil, err
	}
	return s, nil
}

// parseKeys reads every pinned session key; one bad key fails the whole set.
func parseKeys(raw []string) ([]ed25519.PublicKey, error) {
	keys := make([]ed25519.PublicKey, 0, len(raw))
	for _, r := range raw {
		k, err := token.ParsePublicKey(r)
		if err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, nil
}

// checkAPI allows https, and plain http only to this machine (a local stand-in API for testing).
func checkAPI(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("api: %w", err)
	}
	switch {
	case u.Scheme == "https" && u.Host != "":
		return nil
	case u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1"):
		return nil
	}
	return fmt.Errorf("api %s: must be https (plain http only to localhost)", raw)
}

func runHost(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var f flags
	f.register(fs, true)
	if code, done := parse(fs, args); done {
		return code
	}
	s, err := resolve(f, true)
	if err != nil {
		fmt.Fprintln(stderr, "ascend-agent:", err)
		return 2
	}
	id, err := identity.Load(s.org, s.stateDir)
	if err != nil {
		fmt.Fprintln(stderr, "ascend-agent:", err)
		return 1
	}
	audit := agent.NewAudit(s.auditLog, stdout)
	h, err := newHost(s, id, audit, nil)
	if err != nil {
		fmt.Fprintln(stderr, "ascend-agent:", err)
		return 2
	}
	h.run(ctx)
	return 0
}

// host is the host role, ready to connect: `run` in the foreground, or `chat` in the background.
type host struct {
	e      *agenthost.Host
	client *stream.Client
	names  []string
	audit  *agent.Audit
}

// newHost builds the host role. ap lets the person at the terminal approve sites (chat); nil for a service.
func newHost(s *settings, id *identity.Identity, audit *agent.Audit, ap packs.Approver) (*host, error) {
	tc, err := netx.TLSConfig(s.caFile)
	if err != nil {
		return nil, err
	}
	tools := packs.New(s.pol, packs.Info{Version: version, HostID: id.AgentID, Org: s.org, API: s.api},
		&http.Client{Transport: netx.Transport(tc)}, tc.RootCAs, ap)
	client := &stream.Client{
		Base:    s.api,
		HTTP:    &http.Client{Transport: netx.Transport(tc)},
		Token:   func() (string, error) { return token.MintHost(id.Signer, id.AgentID, s.org, time.Now()) },
		OnState: audit.Log,
	}
	e := agenthost.New(agenthost.Config{
		Policy: s.pol, Tools: tools, HostID: id.AgentID, Org: s.org, SessionKeys: s.sessionKeys,
		Info: mcp.ServerInfo{Name: "ascend-agent", Version: version}, API: client, Audit: audit,
	})
	audit.Log("host.start", "version", version, "host_id", id.AgentID, "key", identity.PasteForm(id.PublicKey),
		"org", s.org, "api", s.api, "proxy", netx.ProxyFor(s.api), "policy", s.policyPath,
		"policy_digest", s.pol.Digest(), "tools", tools.Names(), "targets", s.pol.TargetIDs())
	return &host{e: e, client: client, names: tools.Names(), audit: audit}, nil
}

func (h *host) run(ctx context.Context) {
	h.e.Run(ctx, h.client, h.e.Hello(version, h.names))
	h.audit.Log("host.stop")
}

// serve runs the same tools over MCP's stdio transport, for a person to inspect with any MCP client
// before turning the host on. It reaches only the policy's targets, with every enabled tool visible.
func serve(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var f flags
	var stdio bool
	f.register(fs, false)
	fs.BoolVar(&stdio, "stdio", false, "serve MCP over stdin/stdout (the only transport for now)")
	if code, done := parse(fs, args); done {
		return code
	}
	if !stdio {
		fmt.Fprintln(stderr, "ascend-agent: serve needs -stdio")
		return 2
	}
	s, err := resolve(f, false)
	if err != nil {
		fmt.Fprintln(stderr, "ascend-agent:", err)
		return 2
	}
	tc, err := netx.TLSConfig(s.pol.CAFile)
	if err != nil {
		fmt.Fprintln(stderr, "ascend-agent:", err)
		return 2
	}
	audit := agent.NewAudit(s.auditLog, stderr) // stdout is the protocol
	tools := packs.New(s.pol, packs.Info{Version: version, Org: s.org}, &http.Client{Transport: netx.Transport(tc)}, tc.RootCAs, nil)
	sess := mcp.NewSession(tools, s.pol.AllowLocal, mcp.ServerInfo{Name: "ascend-agent", Version: version})
	audit.Log("host.serve_stdio", "version", version, "policy", s.policyPath, "tools", tools.Names())
	if err := serveStdio(ctx, sess, stdin, stdout, audit); err != nil {
		fmt.Fprintln(stderr, "ascend-agent:", err)
		return 1
	}
	return 0
}

// serveStdio is MCP's stdio transport: one JSON-RPC message per line each way. Requests run
// concurrently; responses are written whole, one per line.
func serveStdio(ctx context.Context, sess *mcp.Session, in io.Reader, out io.Writer, audit *agent.Audit) error {
	var mu sync.Mutex
	write := func(m *mcp.Message) {
		data, err := json.Marshal(m)
		if err != nil {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		_, _ = out.Write(append(data, '\n'))
	}
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 64<<10), 4<<20)
	var wg sync.WaitGroup
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var m mcp.Message
		if err := json.Unmarshal(line, &m); err != nil {
			write(mcp.ErrorReply(nil, mcp.ErrParse, "not a JSON-RPC message"))
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			start := time.Now()
			if resp := sess.Handle(ctx, m); resp != nil {
				write(resp)
			}
			if tool := mcp.ToolName(m); tool != "" {
				audit.Log("host.call", "sid", "stdio", "tool", tool, "ms", time.Since(start).Milliseconds())
			}
		}()
	}
	wg.Wait()
	return sc.Err()
}

func policyCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || (args[0] != "check" && args[0] != "show") {
		fmt.Fprintln(stderr, "usage: ascend-agent policy check|show [-policy file]")
		return 2
	}
	sub := args[0]
	fs := flag.NewFlagSet("policy "+sub, flag.ContinueOnError)
	fs.SetOutput(stderr)
	var f flags
	f.register(fs, false)
	if code, done := parse(fs, args[1:]); done {
		return code
	}
	s, err := resolve(f, false)
	if err != nil {
		fmt.Fprintln(stderr, "ascend-agent:", err)
		return 1
	}
	var warnings []string
	if s.org == "" {
		warnings = append(warnings, "no org: `run` needs one (set org, or pass -org)")
	}
	if keys := s.pol.AllSessionKeys(); len(keys) == 0 {
		warnings = append(warnings, "no session_key: `run` needs the key Straiker publishes for your environment")
	} else if _, err := parseKeys(keys); err != nil {
		fmt.Fprintln(stderr, "ascend-agent: policy", s.policyPath+":", err)
		return 1
	}
	if len(s.pol.Agents) == 0 {
		warnings = append(warnings, "no agents: Straiker's agents can call nothing (serve -stdio still works)")
	}
	if sub == "check" {
		fmt.Fprintf(stdout, "ok: %s (digest %s)\n", s.policyPath, s.pol.Digest())
		for _, w := range warnings {
			fmt.Fprintln(stdout, "warning:", w)
		}
		return 0
	}
	tools := packs.New(s.pol, packs.Info{}, http.DefaultClient, nil, nil)
	fmt.Fprintf(stdout, "policy   %s (digest %s)\norg      %s\nenv      %s\n", s.policyPath, s.pol.Digest(), orNone(s.org), s.env)
	fmt.Fprintf(stdout, "limits   %d concurrent calls, %d calls per minute\n", s.pol.Limits.ConcurrentCalls, s.pol.Limits.CallsPerMinute)
	fmt.Fprintln(stdout, "targets")
	for _, id := range s.pol.TargetIDs() {
		t, _ := s.pol.Target(id)
		fmt.Fprintf(stdout, "  %-20s %s\n", id, t.URL)
	}
	fmt.Fprintf(stdout, "tools    %s\n", strings.Join(tools.Names(), ", "))
	fmt.Fprintln(stdout, "agents   (what each may call, if Straiker also grants it)")
	for _, a := range sortedKeys(s.pol.Agents) {
		var may []string
		for _, n := range tools.Names() {
			if s.pol.Allowed(a, []string{n}, n) {
				may = append(may, n)
			}
		}
		fmt.Fprintf(stdout, "  %-20s %s\n", a, orNone(strings.Join(may, ", ")))
	}
	for _, w := range warnings {
		fmt.Fprintln(stdout, "warning:", w)
	}
	return 0
}

func printKey(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("key", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := pick(os.Getenv("TUNNEL_STATE_DIR"), config.DefaultStateDir())
	fs.StringVar(&dir, "state-dir", dir, "where this machine's key is kept")
	if code, done := parse(fs, args); done {
		return code
	}
	id, err := identity.Load("", dir)
	if err != nil {
		fmt.Fprintln(stderr, "ascend-agent:", err)
		return 1
	}
	fmt.Fprintln(stdout, identity.PasteForm(id.PublicKey))
	fmt.Fprintf(stderr, "# host id %s: the key ascend-tunnel uses in %s, too\n", id.AgentID, dir)
	return 0
}

// defaultPolicyPath is the policy file read when none is named, if it exists.
func defaultPolicyPath() string {
	if runtime.GOOS == "windows" {
		if d := os.Getenv("ProgramData"); d != "" {
			return filepath.Join(d, "Straiker", "ascend-agent", "host.yaml")
		}
		return ""
	}
	return "/etc/straiker/ascend-agent.yaml"
}

func parse(fs *flag.FlagSet, args []string) (code int, done bool) {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0, true
		}
		return 2, true
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(fs.Output(), "unexpected argument %q\n", fs.Arg(0))
		return 2, true
	}
	return 0, false
}

func pick(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

func sortedKeys(m map[string][]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
