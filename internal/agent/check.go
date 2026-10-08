package agent

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/straiker-ai/ascend-tunnel/internal/identity"
)

const checkDialTimeout = 5 * time.Second

// Check runs the setup preflight - the relay through any proxy, its TLS, its host key, whether an
// app lists this agent's key, and each allowlisted target - and prints one line per step to w, a
// block a customer can paste to Straiker. It returns false if any step failed.
func (a *Agent) Check(ctx context.Context, w io.Writer) bool {
	ok := true
	line := func(status, format string, args ...any) {
		if status == "FAIL" {
			ok = false
		}
		fmt.Fprintf(w, "%-5s %s\n", status, fmt.Sprintf(format, args...))
	}
	line("INFO", "org %s, agent %s", a.id.Tenant, a.id.AgentID)
	line("INFO", "agent key (paste into the app's _tunnel_agent_keys): %s", identity.PasteForm(a.id.PublicKey))
	for _, f := range a.cfg.Forwards {
		line("INFO", "app URL for %s: %s/... (the Ascend app's URL, with its path)", f.Addr(), f.AppURL())
	}
	if p := relayProxy(a.cfg.Relay); p != "" {
		line("INFO", "relay %s via proxy %s", a.cfg.Relay, p)
	} else {
		line("INFO", "relay %s, direct (no HTTPS_PROXY)", a.cfg.Relay)
	}

	a.checkRelay(ctx, line)
	for _, f := range a.cfg.Forwards {
		c, err := (&net.Dialer{Timeout: checkDialTimeout}).DialContext(ctx, "tcp", f.Addr())
		if err != nil {
			line("FAIL", "target %s not reachable from this machine: %v", f.Addr(), err)
			continue
		}
		c.Close()
		line("PASS", "target %s reachable", f.Addr())
	}
	return ok
}

func (a *Agent) checkRelay(ctx context.Context, line func(status, format string, args ...any)) {
	conn, resp, err := dialRelay(ctx, a.cfg.Relay, a.tls)
	if err != nil {
		line("FAIL", "relay WebSocket: %v (allow outbound HTTPS to it; set HTTPS_PROXY if you use a proxy)", err)
		return
	}
	defer conn.Close()
	line("PASS", "relay WebSocket upgraded over HTTPS")
	if resp != nil && resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		cert := resp.TLS.PeerCertificates[0]
		line("INFO", "relay TLS certificate issued by %q (a TLS-inspecting proxy shows its own CA here; that is fine)",
			cert.Issuer.String())
	}

	var seen ssh.PublicKey
	conf, err := a.sshConfig(func(k ssh.PublicKey) { seen = k })
	if err != nil {
		line("FAIL", "%v", err)
		return
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, a.relayAddr(), conf)
	switch {
	case seen == nil:
		line("FAIL", "relay SSH handshake: %v", err)
		return
	case a.cfg.HostKey == "":
		line("WARN", "relay host key %s is not pinned (set host_key)", ssh.FingerprintSHA256(seen))
	case err != nil && !isUnlisted(err):
		line("FAIL", "relay host key %s does not match the pinned key: %v", ssh.FingerprintSHA256(seen), err)
		return
	default:
		line("PASS", "relay host key matches the pinned key")
	}
	switch {
	case err == nil:
		ssh.NewClient(c, chans, reqs).Close()
		line("PASS", "an Ascend app lists this agent's key: the relay accepts it")
	case isUnlisted(err):
		line("WAIT", "no Ascend app lists this agent's key yet: paste it into the app, then test the connection")
	default:
		line("FAIL", "relay SSH login: %v", err)
	}
}
