package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/straiker-ai/ascend-tunnel/internal/agent"
	"github.com/straiker-ai/ascend-tunnel/internal/agentclient"
	"github.com/straiker-ai/ascend-tunnel/internal/agenthost/browser"
	"github.com/straiker-ai/ascend-tunnel/internal/agenthost/netx"
	"github.com/straiker-ai/ascend-tunnel/internal/agenthost/policy"
	"github.com/straiker-ai/ascend-tunnel/internal/agenthost/wire"
	"github.com/straiker-ai/ascend-tunnel/internal/config"
	"github.com/straiker-ai/ascend-tunnel/internal/identity"
)

const (
	onlineWait  = 20 * time.Second
	approveWait = 2 * time.Minute
)

// appIDRE is an application id as the Ascend console shows it.
var appIDRE = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// chat is the person's side: a conversation with Ascend Agent, with this machine serving the agents' tools for as
// long as it runs (unless `ascend-agent run` already does). It needs a login and nothing else: without a policy
// file, the person approves each site an agent wants to reach.
func chat(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("chat", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var f flags
	var resume string
	f.register(fs, false)
	fs.StringVar(&resume, "resume", "", "reattach to a session by id")
	if code, done := parse(fs, args); done {
		return code
	}
	in := bufio.NewReader(stdin)
	tc, err := netx.TLSConfig("")
	if err != nil {
		fmt.Fprintln(stderr, "ascend-agent:", err)
		return 2
	}
	cfg, err := agentclient.LoadConfig()
	if errors.Is(err, agentclient.ErrNotSignedIn) {
		fmt.Fprintln(stdout, "Sign in to Straiker first.")
		if cfg, err = signIn(ctx, in, stdin, stdout, tc); err != nil {
			fmt.Fprintln(stderr, "ascend-agent:", err)
			return 2
		}
	} else if err != nil {
		fmt.Fprintln(stderr, "ascend-agent:", err)
		return 2
	}
	s, err := chatSettings(f, cfg)
	if err != nil {
		fmt.Fprintf(stderr, "ascend-agent: %v\n(ascend-agent help lists the commands)\n", err)
		return 2
	}
	if s.caFile != "" {
		if tc, err = netx.TLSConfig(s.caFile); err != nil {
			fmt.Fprintln(stderr, "ascend-agent:", err)
			return 2
		}
	}
	// No client timeout: session streams are long-lived; every call carries its own context.
	api := &agentclient.Client{Base: cfg.Gateway, PAT: cfg.Token, HTTP: &http.Client{Transport: netx.Transport(tc)}}
	me, err := pinSessionKey(ctx, api, cfg, s)
	if err != nil {
		fmt.Fprintln(stderr, "ascend-agent:", err)
		return 1
	}
	id, err := identity.Load(s.org, s.stateDir)
	if err != nil {
		fmt.Fprintln(stderr, "ascend-agent:", err)
		return 1
	}
	online, err := ensureEnrolled(ctx, api, s, id, in, stdout)
	if err != nil {
		fmt.Fprintln(stderr, "ascend-agent:", err)
		return 1
	}

	hctx, stopHost := context.WithCancel(ctx)
	defer stopHost()
	ap := &termApprover{org: s.org, api: api}
	mode := "served by ascend-agent run: approvals off"
	if !online {
		h, err := newHost(s, id, agent.NewAudit(s.auditLog, io.Discard), ap)
		if err != nil {
			fmt.Fprintln(stderr, "ascend-agent:", err)
			return 2
		}
		go h.run(hctx)
		fmt.Fprintf(stdout, "Connecting this machine (host %s)…\n", id.AgentID)
		if err := waitOnline(ctx, api, id.AgentID); err != nil {
			fmt.Fprintf(stderr, "ascend-agent: %v (the audit log %s says why)\n", err, s.auditLog)
			return 1
		}
		mode = "served from this terminal"
	}

	m := newChatModel(ctx, api, chatConfig{
		hostID: id.AgentID, hostMode: mode, env: s.env, resume: resume, targets: s.pol.TargetIDs(),
		user: cfg.User, org: s.org, policyPath: s.policyPath, approvals: !online && len(s.pol.Interactive.AllowHosts) > 0,
		allowHosts: s.pol.Interactive.AllowHosts, budget: me.Budget,
	})
	p := tea.NewProgram(m, tea.WithContext(ctx), tea.WithInput(stdin), tea.WithOutput(stdout))
	ap.setSend(p.Send)
	final, err := p.Run()
	ap.setSend(nil)
	if err != nil && !errors.Is(err, tea.ErrProgramKilled) && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(stderr, "ascend-agent:", err)
		return 1
	}
	if cm, ok := final.(*chatModel); ok && cm.sid != "" && !cm.ended {
		fmt.Fprintf(stdout, "The session continues in the cloud for a while; reattach with:\n  ascend-agent -resume %s\n", cm.sid)
	}
	return 0
}

// chatSettings are the login's identity and the optional policy file (the contract that caps approvals), with
// the built-in default when there is no file.
func chatSettings(f flags, cfg *agentclient.Config) (*settings, error) {
	s := &settings{policyPath: pick(f.policy, os.Getenv("ASCEND_AGENT_POLICY"))}
	if s.policyPath == "" {
		if p := defaultPolicyPath(); p != "" {
			if _, err := os.Stat(p); err == nil {
				s.policyPath = p
			}
		}
	}
	s.pol = policy.Default()
	if s.policyPath != "" {
		pol, err := policy.Load(s.policyPath)
		if err != nil {
			return nil, err
		}
		s.pol = pol
	}
	if s.pol.Org != "" && s.pol.Org != cfg.Org {
		return nil, fmt.Errorf("you are signed in to org %s, but %s is for org %s", cfg.Org, s.policyPath, s.pol.Org)
	}
	if s.pol.Env != "" && s.pol.Env != cfg.Env {
		return nil, fmt.Errorf("you are signed in to %s, but %s is for %s", cfg.Env, s.policyPath, s.pol.Env)
	}
	s.org, s.env, s.caFile = cfg.Org, cfg.Env, s.pol.CAFile
	s.api = pick(s.pol.API, cfg.AgentAPI, wire.DefaultBase[cfg.Env])
	if err := checkAPI(s.api); err != nil {
		return nil, err
	}
	s.stateDir = pick(f.stateDir, os.Getenv("TUNNEL_STATE_DIR"), config.DefaultStateDir())
	s.auditLog = pick(f.auditLog, s.pol.Audit.File, s.stateDir+string(os.PathSeparator)+"ascend-agent-audit.jsonl")
	return s, nil
}

// pinSessionKey trusts Straiker's session-token key on first use, over the signed-in TLS connection, and refuses a
// different key after that unless the policy file pins it (a rotation Straiker announced).
func pinSessionKey(ctx context.Context, api *agentclient.Client, cfg *agentclient.Config, s *settings) (*agentclient.Me, error) {
	cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	me, err := api.Whoami(cctx)
	if err != nil {
		return nil, err
	}
	if me.Tenant != cfg.Org {
		return nil, fmt.Errorf("this token now signs in to org %s, not %s: run `ascend-agent login` again", me.Tenant, cfg.Org)
	}
	if cfg.SessionKeys == nil {
		cfg.SessionKeys = map[string]string{}
	}
	pinned := cfg.SessionKeys[cfg.Env]
	if pinned == "" {
		cfg.SessionKeys[cfg.Env] = me.SessionKey
		if _, err := cfg.Save(); err != nil {
			return nil, err
		}
		pinned = me.SessionKey
	}
	if me.SessionKey != pinned && !containsString(s.pol.AllSessionKeys(), me.SessionKey) {
		return nil, fmt.Errorf("Straiker's session key for %s changed (pinned %s, now %s). If Straiker announced a key "+
			"rotation, run `ascend-agent login` again", cfg.Env, short(pinned), short(me.SessionKey))
	}
	keys, err := parseKeys(append([]string{pinned}, s.pol.AllSessionKeys()...))
	if err != nil {
		return nil, err
	}
	s.sessionKeys = keys
	return me, nil
}

func containsString(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func short(k string) string {
	if len(k) > 12 {
		return k[:12] + "…"
	}
	return k
}

// ensureEnrolled enrols this machine under the signed-in user's org, with consent, and reports whether a host is
// already connected for it (`ascend-agent run`).
func ensureEnrolled(ctx context.Context, api *agentclient.Client, s *settings, id *identity.Identity, in *bufio.Reader,
	stdout io.Writer) (bool, error) {
	cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	h, err := api.Host(cctx, id.AgentID)
	switch {
	case errors.Is(err, agentclient.ErrNotFound):
		fmt.Fprintf(stdout, "This machine (host %s) is not enrolled for your organisation yet.\n", id.AgentID)
		if !confirm(in, stdout, "Enrol it, so Straiker's agents can use it for what you approve? [Y/n] ") {
			return false, errors.New("not enrolled")
		}
		name, _ := os.Hostname()
		e, err := api.Enroll(cctx, identity.PasteForm(id.PublicKey), safeName(name))
		if err != nil {
			return false, fmt.Errorf("enrol: %w", err)
		}
		if e.Tenant != s.org {
			return false, fmt.Errorf("enrolled under org %s, but you are signed in to %s", e.Tenant, s.org)
		}
		fmt.Fprintf(stdout, "Enrolled host %s (%s).\n", e.HostID, e.Fingerprint)
		return false, nil
	case err != nil:
		return false, err
	case h.Tenant != s.org:
		return false, fmt.Errorf("this machine is enrolled for org %s, but you are signed in to %s", h.Tenant, s.org)
	}
	return h.Online, nil
}

func waitOnline(ctx context.Context, api *agentclient.Client, hostID string) error {
	deadline := time.Now().Add(onlineWait)
	for time.Now().Before(deadline) {
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		h, err := api.Host(cctx, hostID)
		cancel()
		if err == nil && h.Online {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return errors.New("this machine did not connect to Straiker")
}

func confirm(in *bufio.Reader, stdout io.Writer, prompt string) bool {
	fmt.Fprint(stdout, prompt)
	line, _ := in.ReadString('\n')
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "" || answer == "y" || answer == "yes"
}

// safeName keeps what enrolment accepts as a host name.
func safeName(s string) string {
	b := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune(" _.-", r) {
			return r
		}
		return -1
	}, s)
	if len(b) > 64 {
		b = b[:64]
	}
	return b
}

// login saves a personal access token, and the environment and org it signs in to.
func login(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if code, done := parse(fs, args); done {
		return code
	}
	tc, err := netx.TLSConfig("")
	if err != nil {
		fmt.Fprintln(stderr, "ascend-agent:", err)
		return 2
	}
	if _, err := signIn(ctx, bufio.NewReader(stdin), stdin, stdout, tc); err != nil {
		fmt.Fprintln(stderr, "ascend-agent:", err)
		return 1
	}
	return 0
}

// signIn reads a token, finds its environment and org, and saves the login.
func signIn(ctx context.Context, in *bufio.Reader, stdin io.Reader, stdout io.Writer, tc *tls.Config) (*agentclient.Config, error) {
	token := strings.TrimSpace(os.Getenv(agentclient.PATEnv))
	if token == "" {
		fmt.Fprint(stdout, "Paste a Straiker personal access token (Settings → API keys), then Enter: ")
		var err error
		token, err = readSecret(stdin, in)
		fmt.Fprintln(stdout)
		if err != nil || token == "" {
			return nil, errors.New("no token read")
		}
	}
	env, gateway, err := agentclient.TargetEnv()
	if err != nil {
		return nil, err
	}
	cctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	cfg, err := agentclient.SignIn(cctx, &http.Client{Transport: netx.Transport(tc)}, token, env, gateway)
	if err != nil {
		return nil, err
	}
	path, err := cfg.Save()
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(stdout, "Signed in as %s, org %s (%s). Saved to %s.\n", orNone(cfg.User), cfg.Org, cfg.Env, path)
	return cfg, nil
}

func logout(stdout, stderr io.Writer) int {
	path, err := agentclient.Logout()
	if err != nil {
		fmt.Fprintln(stderr, "ascend-agent:", err)
		return 1
	}
	fmt.Fprintf(stdout, "Signed out (removed %s).\n", path)
	return 0
}

// termApprover asks the person in the chat terminal before an agent reaches a site the policy does not name, and
// opens the capture browser for them.
type termApprover struct {
	org       string
	api       *agentclient.Client // the person's login: the ascend pack reads their Ascend data with it
	mu        sync.Mutex
	send      func(tea.Msg)
	capturing bool
	session   map[string]bool // sites allowed for this session ([y]); [a] keeps them in sites.json
}

// Capture opens a visible browser with Ascend's own profile at u and records what the person does in it. It
// returns at once; the TUI ends the capture (/done, or the window closing) and uploads the redacted HAR.
func (a *termApprover) Capture(ctx context.Context, agentName string, u *url.URL, appID, instructions string) (map[string]any, error) {
	a.mu.Lock()
	send, busy := a.send, a.capturing
	if send != nil && !busy {
		a.capturing = true
	}
	a.mu.Unlock()
	switch {
	case send == nil:
		return nil, errors.New("nobody is at the terminal to use a browser")
	case busy:
		return nil, errors.New("a browser capture is already running: the person finishes it with /done first")
	}
	release := func() { a.mu.Lock(); a.capturing = false; a.mu.Unlock() }
	exe, err := browser.Find()
	if err != nil {
		release()
		return nil, fmt.Errorf("%v: ask the person to export a HAR from their browser's DevTools and attach it with /har", err)
	}
	home, err := agentclient.Home()
	if err != nil {
		release()
		return nil, err
	}
	cp, err := browser.Start(ctx, exe, filepath.Join(home, "browser"), u.String(), version)
	if err != nil {
		release()
		return nil, err
	}
	send(captureMsg{cp: cp, url: u.Redacted(), host: u.Hostname(), appID: appID, instructions: instructions,
		agent: agentName, release: release})
	return map[string]any{"recording": true, "url": u.Redacted(), "browser": filepath.Base(exe),
		"next": "Tell the person what to do in the window (ask_user). When they type /done or close the window, the HAR " +
			"(redacted on their machine) arrives as their message, and a new build starts from it."}, nil
}

// PlatformGet serves the ascend pack: Straiker's API, read as the signed-in person.
func (a *termApprover) PlatformGet(ctx context.Context, path string, query url.Values, out any) error {
	return a.api.GetJSON(ctx, path, query, out)
}

func (a *termApprover) setSend(send func(tea.Msg)) {
	a.mu.Lock()
	a.send = send
	a.mu.Unlock()
}

func (a *termApprover) Approve(ctx context.Context, agentName, tool string, u *url.URL) bool {
	host := strings.ToLower(u.Hostname())
	if agentclient.SiteAllowed(a.org, host) {
		return true
	}
	a.mu.Lock()
	send, allowed := a.send, a.session[host]
	a.mu.Unlock()
	if allowed {
		return true
	}
	if send == nil {
		return false
	}
	reply := make(chan approval, 1)
	send(approvalMsg{agent: agentName, tool: tool, url: u.Redacted(), host: host, reply: reply, ctx: ctx})
	select {
	case ans := <-reply:
		switch ans {
		case approveAlways:
			_ = agentclient.AllowSite(a.org, host)
		case approveOnce:
			a.mu.Lock()
			if a.session == nil {
				a.session = map[string]bool{}
			}
			a.session[host] = true
			a.mu.Unlock()
		}
		return ans != approveNo
	case <-ctx.Done():
	case <-time.After(approveWait):
	}
	return false
}
