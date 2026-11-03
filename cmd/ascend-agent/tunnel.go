package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	brokeragent "github.com/straiker-ai/straiker-broker/pkg/agent"
	brokerconfig "github.com/straiker-ai/straiker-broker/pkg/config"
	brokerid "github.com/straiker-ai/straiker-broker/pkg/identity"

	"github.com/straiker-ai/ascend-tunnel/internal/agentclient"
	"github.com/straiker-ai/ascend-tunnel/internal/agenthost/packs"
)

// brokerProfile is straiker-broker's built-in profile, under ascend-agent's name: the relays, their pinned SSH host
// keys and the target suffix are copied from cmd/straiker-broker/profile.go (v0.1.0), which is package main.
var brokerProfile = &brokerconfig.Profile{
	Name: "ascend-agent",
	Environments: map[string]brokerconfig.Environment{
		"dev": {
			Relay:   "wss://broker.dev.straiker.ai",
			HostKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGMwv9358a+DxXGIaL/IkmuhRdX4tQZEkGOxFJoNJX2J",
		},
		"stage": {
			Relay:   "wss://broker.stage.straiker.ai",
			HostKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEr6fa9H5wVGWwztKRYWRd7Ih3fIE/1omc0tXY058//u",
		},
		"prod": {
			Relay:   "wss://broker.prod.straiker.ai",
			HostKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOnEHRPDE0nEYTyisHLYPhmnb1JZIfiBqTR0BXDwON2x",
		},
	},
	DefaultEnv:   "prod",
	TargetSuffix: packs.BrokerSuffix,
	Register:     "tunnel.open registers it with your login",
}

// ascendProduct is the Straiker Broker grant that lets Ascend route to a target.
const ascendProduct = "ascend"

// shellSafe is a word a shell reads as itself.
var shellSafe = regexp.MustCompile(`^[A-Za-z0-9_./:@%+=,-]+$`)

// tunnels is Straiker Broker's agent running inside the chat, with its own key, for the targets the person opened
// (tunnel.open), until they close them (/tunnel close) or the chat ends. tunnel.open registers each target with
// Straiker as the signed-in person; opening or closing one restarts the agent with the new allowlist.
type tunnels struct {
	ctx                        context.Context     // the chat's: the tunnel ends with it
	api                        *agentclient.Client // the person's login: registers the broker and its targets
	org, env, stateDir, caFile string              // stateDir is the broker's own: its key and connection log
	label                      string              // the broker's and its targets' label in Straiker
	id                         *brokerid.Identity
	audit                      *brokeragent.Audit
	run                        func(*brokeragent.Agent, context.Context) // (*brokeragent.Agent).Run; a seam for tests
	now                        func() time.Time

	opening sync.Mutex // one open at a time, so mu stays free for the status bar while Straiker answers
	mu      sync.Mutex
	allow   []string             // host:port, in the order opened
	since   map[string]time.Time // when each target was opened
	targets map[string]string    // each target's Straiker Broker target id
	stop    context.CancelFunc
	done    chan struct{}

	// useMu guards conns alone: the audit log's writer takes it, so it must never wait on mu (which is held while the
	// tunnel stops, and stopping can log).
	useMu sync.Mutex
	conns map[string]*tunnelUse
}

// tunnelUse counts Straiker's connections through one target, from the tunnel's audit events.
type tunnelUse struct{ ok, failed int }

// tunnelInfo is one open target, for the status bar and /tunnel.
type tunnelInfo struct {
	addr          string
	since         time.Time
	conns, failed int
}

// newTunnels loads the broker's key from <state>/broker, apart from this machine's host key, creating it on first use.
func newTunnels(ctx context.Context, s *settings, api *agentclient.Client) (*tunnels, error) {
	dir, err := filepath.Abs(filepath.Join(s.stateDir, "broker"))
	if err != nil {
		return nil, err
	}
	caFile := s.caFile
	if caFile != "" {
		if caFile, err = filepath.Abs(caFile); err != nil {
			return nil, err
		}
	}
	id, err := brokerid.Load(s.org, dir)
	if err != nil {
		return nil, err
	}
	name, _ := os.Hostname()
	t := &tunnels{ctx: ctx, api: api, org: s.org, env: s.env, stateDir: dir, caFile: caFile,
		label: "ascend-agent " + safeName(name), id: id, run: (*brokeragent.Agent).Run, now: time.Now,
		since: map[string]time.Time{}, targets: map[string]string{}, conns: map[string]*tunnelUse{}}
	t.audit = brokeragent.NewAudit(filepath.Join(dir, "connections.jsonl"), useCounter{t})
	return t, nil
}

// open registers host:port with Straiker Broker and adds it to the running broker. It returns the target's id and
// the allowlist now open.
func (t *tunnels) open(ctx context.Context, host string, port int) (string, []string, error) {
	if t.ctx.Err() != nil {
		return "", nil, errors.New("the chat is ending")
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	t.opening.Lock()
	defer t.opening.Unlock()
	t.mu.Lock()
	target, allow := t.targets[addr], slices.Clone(t.allow)
	t.mu.Unlock()
	if target != "" {
		return target, allow, nil
	}
	for _, a := range allow {
		if hostOf(a) == host {
			return "", nil, errors.New("the broker already reaches " + a + ": one port per host (the broker name carries no port)")
		}
	}
	target, err := t.register(ctx, host, port)
	if err != nil {
		return "", nil, err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	allow = append(slices.Clone(t.allow), addr)
	if err := t.restart(allow); err != nil {
		return "", nil, err
	}
	t.since[addr], t.targets[addr] = t.now(), target
	t.useMu.Lock()
	t.conns[addr] = &tunnelUse{}
	t.useMu.Unlock()
	return target, allow, nil
}

// register makes Straiker route host to this broker for Ascend, as the signed-in person, reusing what is already
// there: the broker registered with this key, its target for host, and the target's ascend grant.
func (t *tunnels) register(ctx context.Context, host string, port int) (string, error) {
	brokerID, err := t.broker(ctx)
	if err != nil {
		return "", t.explain(err)
	}
	target, err := t.target(ctx, brokerID, host, port)
	if err != nil {
		return "", t.explain(err)
	}
	if !slices.Contains(target.Products, ascendProduct) {
		// PUT replaces the grants, so the products already there go back with it.
		if err := t.api.SetBrokerGrants(ctx, target.ID, append(slices.Clone(target.Products), ascendProduct)); err != nil {
			return "", t.explain(err)
		}
	}
	return target.ID, nil
}

// broker is the id of the active broker registered with this key, registering it when there is none.
func (t *tunnels) broker(ctx context.Context) (string, error) {
	find := func() (active string, revoked bool, err error) {
		list, err := t.api.Brokers(ctx)
		for _, b := range list {
			if brokerid.PasteForm(b.PublicKey) != brokerid.PasteForm(t.id.PublicKey) {
				continue
			}
			if b.Status == agentclient.BrokerActive {
				return b.ID, false, nil
			}
			revoked = true
		}
		return "", revoked, err
	}
	id, revoked, err := find()
	switch {
	case err != nil:
		return "", err
	case id != "":
		return id, nil
	case revoked:
		return "", t.revoked()
	}
	b, err := t.api.RegisterBroker(ctx, t.id.PublicKey, t.label)
	if apiCode(err) == "broker_exists" { // registered meanwhile
		if id, _, ferr := find(); ferr == nil && id != "" {
			return id, nil
		}
	}
	if err != nil {
		return "", err
	}
	return b.ID, nil
}

// target is the broker's target for host, declared when there is none. A broker holds each host once, whatever the
// port: the allowlist decides what it dials.
func (t *tunnels) target(ctx context.Context, brokerID, host string, port int) (*agentclient.BrokerTarget, error) {
	find := func() (*agentclient.BrokerTarget, error) {
		list, err := t.api.BrokerTargets(ctx)
		for i := range list {
			if list[i].BrokerID == brokerID && list[i].Name == host {
				return &list[i], nil
			}
		}
		return nil, err
	}
	if found, err := find(); found != nil || err != nil {
		return found, err
	}
	created, err := t.api.CreateBrokerTarget(ctx, brokerID, host, port, t.label)
	if apiCode(err) == "target_exists" { // declared meanwhile
		if found, ferr := find(); ferr == nil && found != nil {
			return found, nil
		}
	}
	return created, err
}

// explain says what to do about Straiker refusing a registration; any other refusal's message stands.
func (t *tunnels) explain(err error) error {
	var e *agentclient.APIError
	switch {
	case !errors.As(err, &e):
		return err
	case e.Status == http.StatusForbidden:
		return fmt.Errorf("%w: Straiker Broker needs a login whose personal access token has the integration:write "+
			"(and ascend:write) scope; exit, run `ascend-agent login` with such a token, and start again", err)
	case e.Code == "broker_revoked":
		return fmt.Errorf("%w: %v", err, t.revoked())
	}
	return err
}

// revoked is why a revoked broker's key cannot be used again, and how to get a new one.
func (t *tunnels) revoked() error {
	return fmt.Errorf("this machine's Straiker Broker key belongs to a revoked broker and cannot be used again; "+
		"for a new key, exit, delete %s, and start again", t.stateDir)
}

func apiCode(err error) string {
	var e *agentclient.APIError
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

// shut closes one target, or every target when addr is "", and returns what it closed.
func (t *tunnels) shut(addr string) ([]string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	var keep, gone []string
	for _, a := range t.allow {
		if addr == "" || a == addr || hostOf(a) == addr {
			gone = append(gone, a)
		} else {
			keep = append(keep, a)
		}
	}
	if len(gone) == 0 {
		return nil, errors.New("no open tunnel reaches " + addr)
	}
	if err := t.restart(keep); err != nil {
		return nil, err
	}
	t.useMu.Lock()
	for _, a := range gone {
		delete(t.since, a)
		delete(t.targets, a)
		delete(t.conns, a)
	}
	t.useMu.Unlock()
	return gone, nil
}

// restart runs the broker for allow, stopping the one before; nothing runs for an empty allowlist. t.mu is held.
func (t *tunnels) restart(allow []string) error {
	var a *brokeragent.Agent
	if len(allow) > 0 {
		cfg, err := brokerconfig.Load(brokerProfile, "", brokerconfig.Overrides{Tenant: t.org, Env: t.env,
			StateDir: t.stateDir, CAFile: t.caFile, Allow: allow}, func(string) string { return "" })
		if err != nil {
			return err
		}
		if a, err = brokeragent.New(cfg, t.id, t.audit); err != nil {
			return err
		}
	}
	t.halt()
	t.allow = allow
	if a == nil {
		return nil
	}
	ctx, stop := context.WithCancel(t.ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		t.run(a, ctx)
	}()
	t.stop, t.done = stop, done
	return nil
}

// halt stops the running broker and waits for it; t.mu is held.
func (t *tunnels) halt() {
	if t.stop != nil {
		t.stop()
		<-t.done
		t.stop, t.done = nil, nil
	}
}

// list is every open target, in the order opened.
func (t *tunnels) list() []tunnelInfo {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.useMu.Lock()
	defer t.useMu.Unlock()
	out := make([]tunnelInfo, 0, len(t.allow))
	for _, a := range t.allow {
		info := tunnelInfo{addr: a, since: t.since[a]}
		if u := t.conns[a]; u != nil {
			info.conns, info.failed = u.ok, u.failed
		}
		out = append(out, info)
	}
	return out
}

// close stops the broker when the chat ends and returns what it still reached, for the goodbye line.
func (t *tunnels) close() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.halt()
	return t.allow
}

// keepCommand is straiker-broker's command that keeps targets reachable as a service, with the same key and CA.
func (t *tunnels) keepCommand(allow []string) string {
	cmd := "straiker-broker service install --org " + t.org
	for _, a := range allow {
		cmd += " --allow " + a
	}
	if t.env != "" && t.env != brokerProfile.DefaultEnv {
		cmd += " --env " + t.env
	}
	if t.caFile != "" {
		cmd += " --ca-file " + shellWord(t.caFile)
	}
	return cmd + " --state-dir " + shellWord(t.stateDir)
}

// shellWord is s as one shell word, quoted when it needs it (a macOS state dir has a space).
func shellWord(s string) string {
	if shellSafe.MatchString(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func hostOf(addr string) string {
	h, _, _ := net.SplitHostPort(addr)
	return h
}

// useCounter reads the broker's audit lines as they are written and counts each target's connections.
type useCounter struct{ t *tunnels }

func (c useCounter) Write(p []byte) (int, error) {
	var e struct {
		Event string `json:"event"`
		Dest  string `json:"dest"`
		Error string `json:"error"`
	}
	if json.Unmarshal(p, &e) == nil && e.Event == "connection" {
		c.t.useMu.Lock()
		if u := c.t.conns[e.Dest]; u != nil {
			if e.Error != "" {
				u.failed++
			} else {
				u.ok++
			}
		}
		c.t.useMu.Unlock()
	}
	return len(p), nil
}
