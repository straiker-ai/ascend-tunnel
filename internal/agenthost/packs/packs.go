// Package packs are the host's built-in tools. Every tool is fixed code in this binary: Straiker sends
// arguments, never code, and a tool only touches targets the customer's policy names, by id.
package packs

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"net"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/straiker-ai/ascend-tunnel/internal/agenthost/mcp"
	"github.com/straiker-ai/ascend-tunnel/internal/agenthost/policy"
)

// Info is what env.info reports about this host.
type Info struct {
	Version string
	HostID  string
	Org     string
	Env     string
	API     string
}

// tool is one tool: its definition and its implementation.
type tool struct {
	def mcp.Tool
	run func(ctx context.Context, args json.RawMessage) mcp.Result
}

// Registry serves the enabled packs' tools; it implements mcp.Tools.
type Registry struct {
	tools map[string]tool
}

// New builds the tools of every pack the policy enables. client is used by http.probe; roots verify
// certificates in net.check (nil: the system store); ap, when not nil, lets the person at this machine approve
// sites beyond the policy's targets, within its interactive cap.
func New(p *policy.Policy, info Info, client *http.Client, roots *x509.CertPool, ap Approver) *Registry {
	r := &Registry{tools: map[string]tool{}}
	add := func(t tool) {
		if pack, _, _ := strings.Cut(t.def.Name, "."); p.PackEnabled(pack) {
			r.tools[t.def.Name] = t
		}
	}
	if ap != nil && len(p.Interactive.AllowHosts) == 0 {
		ap = nil // the policy lets no one approve anything
	}
	add(envInfo(p, info, r, ap != nil))
	add(netCheck(p, roots, ap))
	add(httpProbe(p, guarded(client), info.Version, ap))
	if c, ok := ap.(Capturer); ok && ap != nil {
		add(browserCapture(p, ap, c))
	}
	if pl, ok := ap.(Platform); ok && ap != nil {
		for _, t := range ascendTools(pl) {
			add(t)
		}
		if cf, ok := ap.(Confirmer); ok {
			add(appCreate(pl, cf, info.Org))
			if pt, ok := ap.(Patcher); ok {
				add(appAdaptor(pl, pt, cf, info.Org))
			}
		}
	}
	if tn, ok := ap.(Tunneler); ok && ap != nil {
		if cf, ok := ap.(Confirmer); ok {
			add(tunnelOpen(p, cf, tn, info))
		}
	}
	return r
}

// guarded is client with connections to link-local and metadata addresses refused.
func guarded(client *http.Client) *http.Client {
	c := *client
	base, _ := c.Transport.(*http.Transport)
	if base == nil {
		base = http.DefaultTransport.(*http.Transport)
	}
	t := base.Clone()
	t.DialContext = (&net.Dialer{Timeout: 15 * time.Second, Control: guard}).DialContext
	c.Transport = t
	return &c
}

// List is every enabled tool, sorted by name.
func (r *Registry) List() []mcp.Tool {
	out := make([]mcp.Tool, 0, len(r.tools))
	for _, t := range r.tools {
		out = append(out, t.def)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Names are the enabled tools' names, sorted.
func (r *Registry) Names() []string {
	names := make([]string, 0, len(r.tools))
	for n := range r.tools {
		names = append(names, n)
	}
	slices.Sort(names)
	return names
}

// Call runs a tool. A caller has already checked the session may use it.
func (r *Registry) Call(ctx context.Context, name string, args json.RawMessage) mcp.Result {
	t, ok := r.tools[name]
	if !ok {
		return mcp.TextResult("unknown tool "+name, true)
	}
	return t.run(ctx, args)
}

// decode reads a tool's arguments strictly: unknown fields are an error the model can fix.
func decode(args json.RawMessage, v any) error {
	dec := json.NewDecoder(strings.NewReader(string(args)))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func schema(s string) json.RawMessage { return json.RawMessage(s) }

func failure(format string, err error) mcp.Result {
	return mcp.JSONResult(map[string]any{"error": format + ": " + err.Error()}, true)
}

// targetSchema is the shared "target" argument: an id from the policy, never a URL.
const targetSchema = `{"type":"string","description":"a target id from this host's policy (env.info lists them)"}`

func lookupTarget(p *policy.Policy, id string) (policy.Target, mcp.Result, bool) {
	t, ok := p.Target(id)
	if !ok {
		return policy.Target{}, mcp.JSONResult(map[string]any{
			"error":   "unknown target " + quote(id) + ": the host reaches only targets its policy names",
			"targets": p.TargetIDs(),
		}, true), false
	}
	return t, mcp.Result{}, true
}

func quote(s string) string { b, _ := json.Marshal(s); return string(b) }
