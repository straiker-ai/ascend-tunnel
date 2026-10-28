package packs

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"syscall"

	"github.com/straiker-ai/ascend-tunnel/internal/agenthost/mcp"
	"github.com/straiker-ai/ascend-tunnel/internal/agenthost/policy"
)

// Approver asks the person at this machine whether an agent may reach a site its policy does not name. Only an
// interactive session (ascend-agent chat) has one; a service has none, and reaches only the policy's targets.
type Approver interface {
	Approve(ctx context.Context, agent, tool string, u *url.URL) bool
}

// Capturer opens a visible browser for the person and records what they do in it. An interactive session's
// Approver may also be one; browser.capture is served only then.
type Capturer interface {
	Capture(ctx context.Context, agent string, u *url.URL, appID, instructions string) (map[string]any, error)
}

type agentKey struct{}

// WithAgent records which Straiker agent a call comes from, for an approval prompt.
func WithAgent(ctx context.Context, agent string) context.Context {
	return context.WithValue(ctx, agentKey{}, agent)
}

func agentFrom(ctx context.Context) string {
	a, _ := ctx.Value(agentKey{}).(string)
	return a
}

// urlSchema is the "url" argument: a site to reach that the person approves, when the host can ask them.
const urlSchema = `{"type":"string","description":"an http(s) URL, when no target covers it; the person at this machine approves new sites"}`

// site resolves a call's target id or URL to the URL to reach, refusing what the policy and the person do not
// allow. label names it in results.
func site(ctx context.Context, p *policy.Policy, ap Approver, tool, target, raw string) (u *url.URL, label string, refusal mcp.Result, ok bool) {
	switch {
	case target != "" && raw != "":
		return nil, "", refuse("give a target or a url, not both"), false
	case target != "":
		t, refusal, ok := lookupTarget(p, target)
		if !ok {
			return nil, "", refusal, false
		}
		return t.Parsed(), target, mcp.Result{}, true
	case raw == "":
		return nil, "", refuse("give a target id or a url"), false
	}
	u, err := url.Parse(raw)
	switch {
	case err != nil:
		return nil, "", refuse("url: " + err.Error()), false
	case u.Scheme != "https" && u.Scheme != "http":
		return nil, "", refuse("url must be http or https"), false
	case u.Hostname() == "" || u.User != nil:
		return nil, "", refuse("url must name a host and carry no credentials"), false
	case blockedHost(u.Hostname()):
		return nil, "", refuse("that address is never reachable from this host (link-local or cloud metadata)"), false
	}
	u.Fragment = ""
	if id, ok := p.TargetFor(u); ok {
		return u, id, mcp.Result{}, true
	}
	if ap == nil {
		return nil, "", refuse("this host reaches only its policy's targets: " + strings.Join(p.TargetIDs(), ", ")), false
	}
	if !p.MayApprove(u.Hostname()) {
		return nil, "", refuse(fmt.Sprintf("the policy on this machine does not let a person approve %s", u.Hostname())), false
	}
	if !ap.Approve(ctx, agentFrom(ctx), tool, u) {
		return nil, "", refuse(fmt.Sprintf("the person at this machine did not approve %s", u.Hostname())), false
	}
	return u, u.Hostname(), mcp.Result{}, true
}

func refuse(msg string) mcp.Result {
	return mcp.JSONResult(map[string]any{"error": msg}, true)
}

// blockedHost is a host name or literal that is never a target: cloud metadata and link-local addresses.
func blockedHost(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	if h == "metadata.google.internal" || h == "metadata" {
		return true
	}
	if a, err := netip.ParseAddr(h); err == nil {
		return blockedAddr(a)
	}
	return false
}

func blockedAddr(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a == netip.MustParseAddr("fd00:ec2::254")
}

var errBlocked = errors.New("refused: link-local or cloud metadata address")

// guard refuses connections to blocked addresses after DNS resolution, so a name that resolves to one is refused
// too (a proxy's address is what is checked when one is in use).
func guard(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	if a, err := netip.ParseAddr(host); err == nil && blockedAddr(a) {
		return errBlocked
	}
	return nil
}
