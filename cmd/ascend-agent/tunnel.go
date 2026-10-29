package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/straiker-ai/ascend-tunnel/internal/agent"
	"github.com/straiker-ai/ascend-tunnel/internal/config"
	"github.com/straiker-ai/ascend-tunnel/internal/identity"
)

// tunnels is ascend-tunnel's agent running inside the chat, with this machine's key, for the targets the person
// opened (tunnel.open), until they close them (/tunnel close) or the chat ends. Opening or closing a target restarts
// it with the new allowlist.
type tunnels struct {
	ctx                        context.Context // the chat's: the tunnel ends with it
	org, env, stateDir, caFile string
	auditLog                   string // the tunnel's own log, where ascend-tunnel keeps it
	id                         *identity.Identity
	audit                      *agent.Audit
	run                        func(*agent.Agent, context.Context) // (*agent.Agent).Run; a seam for tests
	now                        func() time.Time

	mu    sync.Mutex
	allow []string             // host:port, in the order opened
	since map[string]time.Time // when each target was opened
	stop  context.CancelFunc
	done  chan struct{}

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

func newTunnels(ctx context.Context, s *settings, id *identity.Identity) *tunnels {
	t := &tunnels{ctx: ctx, org: s.org, env: s.env, stateDir: s.stateDir, caFile: s.caFile, id: id,
		auditLog: filepath.Join(s.stateDir, "connections.jsonl"), run: (*agent.Agent).Run, now: time.Now,
		since: map[string]time.Time{}, conns: map[string]*tunnelUse{}}
	t.audit = agent.NewAudit(t.auditLog, useCounter{t})
	return t
}

// open adds host:port to the running tunnel and returns the key an application lists for it.
func (t *tunnels) open(host string, port int) (string, error) {
	if t.ctx.Err() != nil {
		return "", errors.New("the chat is ending")
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	t.mu.Lock()
	defer t.mu.Unlock()
	if slices.Contains(t.allow, addr) {
		return identity.PasteForm(t.id.PublicKey), nil
	}
	for _, a := range t.allow {
		if h, _, _ := net.SplitHostPort(a); h == host {
			return "", errors.New("this tunnel already reaches " + a + ": one port per host (the tunnel name carries no port)")
		}
	}
	if err := t.restart(append(slices.Clone(t.allow), addr)); err != nil {
		return "", err
	}
	t.since[addr] = t.now()
	t.useMu.Lock()
	t.conns[addr] = &tunnelUse{}
	t.useMu.Unlock()
	return identity.PasteForm(t.id.PublicKey), nil
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
		delete(t.conns, a)
	}
	t.useMu.Unlock()
	return gone, nil
}

// restart runs the agent for allow, stopping the one before; nothing runs for an empty allowlist. t.mu is held.
func (t *tunnels) restart(allow []string) error {
	var a *agent.Agent
	if len(allow) > 0 {
		cfg, err := config.Load("", config.Overrides{Tenant: t.org, Env: t.env, StateDir: t.stateDir, CAFile: t.caFile,
			AuditLog: t.auditLog, Allow: allow}, func(string) string { return "" })
		if err != nil {
			return err
		}
		if a, err = agent.New(cfg, t.id, t.audit); err != nil {
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

// halt stops the running tunnel and waits for it; t.mu is held.
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

// close stops the tunnel when the chat ends and returns what it still reached, for the goodbye line.
func (t *tunnels) close() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.halt()
	return t.allow
}

// keepCommand is ascend-tunnel's command that keeps targets reachable as a service, with this machine's key.
func (t *tunnels) keepCommand(allow []string) string {
	cmd := "ascend-tunnel service install --org " + t.org
	for _, a := range allow {
		cmd += " --allow " + a
	}
	if t.env != "" && t.env != config.DefaultEnv {
		cmd += " --env " + t.env
	}
	return strings.TrimSpace(cmd)
}

func hostOf(addr string) string {
	h, _, _ := net.SplitHostPort(addr)
	return h
}

// useCounter reads the tunnel's audit lines as they are written and counts each target's connections.
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
