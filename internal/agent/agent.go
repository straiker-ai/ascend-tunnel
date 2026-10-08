// Package agent runs the tunnel: it dials OUT to Straiker's relay over a WebSocket (ordinary HTTPS),
// runs an SSH session inside it, and reverse-forwards one relay-side socket per allowlisted target
// back to itself. Straiker reaches each target through its socket; the agent dials the target and
// splices bytes, never seeing the plaintext (TLS is end to end, Straiker to the app) and never
// reaching anything outside its allowlist.
package agent

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/straiker-ai/ascend-tunnel/internal/config"
	"github.com/straiker-ai/ascend-tunnel/internal/identity"
)

const (
	reconnectMin, reconnectMax = 2 * time.Second, 30 * time.Second
	// Refused because no app lists this key (yet, or any more): retried at a steady pace, so a key
	// listed at any time - at setup, or when Straiker re-lists an idle app - is picked up in seconds.
	unlistedRetry, unlistedLogEvery = 5 * time.Second, time.Minute
	keepaliveEvery, keepaliveWait   = 30 * time.Second, 15 * time.Second
	targetDialTimeout               = 10 * time.Second
)

// Agent is one running tunnel agent.
type Agent struct {
	cfg   *config.Config
	id    *identity.Identity
	audit *Audit
	tls   *tls.Config

	// Seams for tests.
	session    func(ctx context.Context, link int) error
	sleep      func(ctx context.Context, d time.Duration) error
	now        func() time.Time
	jitter     func(max time.Duration) time.Duration
	dialTarget func(ctx context.Context, network, addr string) (net.Conn, error)
}

// New prepares an agent; nothing is dialled until Run.
func New(cfg *config.Config, id *identity.Identity, audit *Audit) (*Agent, error) {
	tc, err := tlsConfig(cfg.CAFile)
	if err != nil {
		return nil, err
	}
	a := &Agent{cfg: cfg, id: id, audit: audit, tls: tc, now: time.Now,
		sleep: sleepCtx,
		jitter: func(max time.Duration) time.Duration {
			if max <= 0 {
				return 0
			}
			return time.Duration(rand.Int64N(int64(max)))
		},
		dialTarget: (&net.Dialer{Timeout: targetDialTimeout}).DialContext,
	}
	a.session = a.runSession
	return a, nil
}

// Run keeps one reconnecting link per fan-out index until ctx ends. Each link binds its own socket
// per target, so a target's connections spread across links for throughput.
func (a *Agent) Run(ctx context.Context) {
	a.audit.Log("identity", "tenant", a.id.Tenant, "agent_id", a.id.AgentID,
		"agent_key", identity.PasteForm(a.id.PublicKey),
		"hint", "paste agent_key into each Ascend app's _tunnel_agent_keys that this agent serves")
	if a.cfg.HostKey == "" {
		a.audit.Log("warning", "error", "the relay's host key is not pinned (set host_key)")
	}
	if p := relayProxy(a.cfg.Relay); p != "" {
		a.audit.Log("proxy", "relay", a.cfg.Relay, "via", p)
	}
	var wg sync.WaitGroup
	for link := 0; link < a.cfg.Fanout; link++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a.linkLoop(ctx, link)
		}()
	}
	wg.Wait()
}

func (a *Agent) linkLoop(ctx context.Context, link int) {
	backoff := reconnectMin
	var loggedAt time.Time
	logged := false
	for {
		err := a.session(ctx, link)
		if ctx.Err() != nil {
			return
		}
		switch {
		case err == nil:
			a.audit.Log("disconnected", "link", link, "error", "session ended")
			backoff, logged = reconnectMin, false
		case isUnlisted(err):
			if !logged || a.now().Sub(loggedAt) >= unlistedLogEvery {
				loggedAt, logged = a.now(), true
				a.audit.Log("waiting", "link", link, "agent_id", a.id.AgentID,
					"retry_every_s", unlistedRetry.Seconds(),
					"error", "no Ascend app lists this agent's key in _tunnel_agent_keys yet (or it was removed)")
			}
			if a.sleep(ctx, unlistedRetry+a.jitter(time.Second)) != nil {
				return
			}
			continue
		default:
			logged = false
			a.audit.Log("disconnected", "link", link, "error", err.Error())
		}
		if a.sleep(ctx, backoff+a.jitter(backoff/2)) != nil {
			return
		}
		backoff = min(backoff*2, reconnectMax)
	}
}

// isUnlisted is the relay refusing this key: no app lists it.
func isUnlisted(err error) bool {
	return err != nil && strings.Contains(err.Error(), "unable to authenticate")
}

type forward struct {
	socket string
	target config.Forward
}

// linkForwards is what link binds: one socket per target, named for this link.
func (a *Agent) linkForwards(link int) []forward {
	out := make([]forward, 0, len(a.cfg.Forwards))
	for _, f := range a.cfg.Forwards {
		out = append(out, forward{socket: identity.SocketPath(a.id.SocketDir, f.Host, link), target: f})
	}
	return out
}

// sshConfig logs in as this agent's relay user with its key. A pinned host key is the only one
// accepted; observed, when set, sees the key the relay presents.
func (a *Agent) sshConfig(observed func(ssh.PublicKey)) (*ssh.ClientConfig, error) {
	c := &ssh.ClientConfig{
		User:    a.id.User,
		Auth:    []ssh.AuthMethod{ssh.PublicKeys(a.id.Signer)},
		Timeout: handshakeTimeout,
	}
	var pinned ssh.PublicKey
	if a.cfg.HostKey != "" {
		pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(a.cfg.HostKey))
		if err != nil {
			return nil, fmt.Errorf("host_key: %w", err)
		}
		pinned = pk
		c.HostKeyAlgorithms = []string{pk.Type()}
	}
	c.HostKeyCallback = func(host string, remote net.Addr, key ssh.PublicKey) error {
		if observed != nil {
			observed(key)
		}
		if pinned == nil {
			return nil // unpinned: warned at start
		}
		if ssh.FixedHostKey(pinned)(host, remote, key) != nil {
			return fmt.Errorf("relay host key %s not trusted: pinned %s",
				ssh.FingerprintSHA256(key), ssh.FingerprintSHA256(pinned))
		}
		return nil
	}
	return c, nil
}

func (a *Agent) relayAddr() string {
	if u, err := url.Parse(a.cfg.Relay); err == nil && u.Host != "" {
		return u.Host
	}
	return a.cfg.Relay
}

// runSession is one link: WebSocket, SSH login, one forward per target, until the link drops.
func (a *Agent) runSession(ctx context.Context, link int) error {
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	conn, _, err := dialRelay(sctx, a.cfg.Relay, a.tls)
	if err != nil {
		return err
	}
	defer conn.Close()
	conf, err := a.sshConfig(nil)
	if err != nil {
		return err
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, a.relayAddr(), conf)
	if err != nil {
		return err
	}
	client := ssh.NewClient(c, chans, reqs)
	defer client.Close()
	go func() {
		<-sctx.Done()
		client.Close()
	}()

	forwards := a.linkForwards(link)
	hosts := make([]string, 0, len(forwards))
	for _, f := range forwards {
		hosts = append(hosts, f.target.Host)
	}
	a.audit.Log("connected", "relay", a.cfg.Relay, "link", link, "targets", hosts)
	for _, f := range forwards {
		ln, err := client.ListenUnix(f.socket)
		if err != nil {
			return fmt.Errorf("forward %s: %w", f.socket, err)
		}
		a.audit.Log("forward", "link", link, "socket", f.socket, "dest", f.target.Addr())
		go a.serve(sctx, ln, f, link)
	}
	go a.keepalive(sctx, client)
	err = client.Wait()
	if sctx.Err() != nil || err == nil || errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

// keepalive notices a dead link (a silently dropped NAT or proxy path) and closes it, so it reconnects.
func (a *Agent) keepalive(ctx context.Context, client *ssh.Client) {
	t := time.NewTicker(keepaliveEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		done := make(chan error, 1)
		go func() {
			_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
			done <- err
		}()
		select {
		case err := <-done:
			if err != nil {
				client.Close()
				return
			}
		case <-time.After(keepaliveWait):
			client.Close()
			return
		case <-ctx.Done():
			return
		}
	}
}

func (a *Agent) serve(ctx context.Context, ln net.Listener, f forward, link int) {
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go a.handle(ctx, c, f, link)
	}
}

// handle splices one relay connection to its target - only ever the target this socket was bound for.
func (a *Agent) handle(ctx context.Context, c net.Conn, f forward, link int) {
	defer c.Close()
	start := a.now()
	t, err := a.dialTarget(ctx, "tcp", f.target.Addr())
	if err != nil {
		a.audit.Log("connection", "link", link, "dest", f.target.Addr(), "error", err.Error())
		return
	}
	defer t.Close()
	toTarget, fromTarget := splice(c, t)
	a.audit.Log("connection", "link", link, "dest", f.target.Addr(), "bytes_to_target", toTarget,
		"bytes_from_target", fromTarget, "duration_ms", a.now().Sub(start).Milliseconds())
}

// splice copies both ways until both directions end, half-closing each side as its source ends.
func splice(x, y net.Conn) (xToY, yToX int64) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		xToY, _ = io.Copy(y, x)
		closeWrite(y)
	}()
	go func() {
		defer wg.Done()
		yToX, _ = io.Copy(x, y)
		closeWrite(x)
	}()
	wg.Wait()
	return xToY, yToX
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = c.Close()
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
