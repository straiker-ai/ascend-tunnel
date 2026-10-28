// Package policy is the customer's contract for the host: which targets its tools may touch, which
// packs are on, and which Straiker agent may call which tool. Like the tunnel's allowlist, it is the
// security boundary, so anything ambiguous is refused at load.
package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Packs are the built-in tool packs, by name. A pack's tools are named "<pack>.<tool>".
var Packs = []string{"env", "net", "http", "browser", "ascend"}

const (
	defaultConcurrentCalls = 4
	defaultCallsPerMinute  = 120
)

var (
	orgRE     = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)
	idRE      = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	patternRE = regexp.MustCompile(`^[a-z0-9_]+\.([a-z0-9_]+|\*)$`)
)

// Policy is a loaded, validated policy file.
type Policy struct {
	Org         string              `yaml:"org"`
	Env         string              `yaml:"env"`
	API         string              `yaml:"api"`
	SessionKey  string              `yaml:"session_key"`
	SessionKeys []string            `yaml:"session_keys"` // more than one during a rotation
	CAFile      string              `yaml:"ca_file"`
	Targets     map[string]Target   `yaml:"targets"`
	Packs       []string            `yaml:"packs"`
	Agents      map[string][]string `yaml:"agents"`
	Limits      Limits              `yaml:"limits"`
	Interactive Interactive         `yaml:"interactive"`
	Audit       struct {
		File string `yaml:"file"`
	} `yaml:"audit"`

	digest  string
	managed bool // read from a file, rather than the built-in default
}

// Interactive caps what a person at the terminal may approve beyond the targets. In a policy file it is
// off unless set; without a file (the built-in default) any site may be approved.
type Interactive struct {
	AllowHosts []string `yaml:"allow_hosts"` // "*", "example.com" (that host) or "*.example.com" (it and its subdomains)
}

// Target is a place the host's tools may reach, named by an id. The cloud only ever sends the id.
type Target struct {
	URL string `yaml:"url"`

	parsed *url.URL
}

// Parsed is the target's URL, validated at load.
func (t Target) Parsed() *url.URL { u := *t.parsed; return &u }

// Limits bound how hard Straiker can drive this host, whatever a session asks for.
type Limits struct {
	ConcurrentCalls int `yaml:"concurrent_calls"`
	CallsPerMinute  int `yaml:"calls_per_minute"`
}

// Load reads and validates a policy file.
func Load(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	p, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("policy %s: %w", path, err)
	}
	return p, nil
}

// Parse decodes and validates a policy. Unknown keys are refused: a misspelt key would otherwise
// silently loosen nothing and tighten nothing, and the customer would believe it did.
func Parse(data []byte) (*Policy, error) {
	var p Policy
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil {
		return nil, err
	}
	if err := p.validate(); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	p.digest = hex.EncodeToString(sum[:])[:12]
	p.managed = true
	return &p, nil
}

// DefaultAgents are what Straiker's agents may call under the built-in default.
var DefaultAgents = map[string][]string{"adaptor-builder": {"env.*", "net.*", "http.*", "browser.*", "ascend.*"}}

// Default is the policy when there is no file: every pack, no targets, and a person at the terminal approves
// each site the first time an agent wants to reach it.
func Default() *Policy {
	p := &Policy{Packs: slices.Clone(Packs), Agents: map[string][]string{}, Targets: map[string]Target{},
		Interactive: Interactive{AllowHosts: []string{"*"}}}
	for agent, tools := range DefaultAgents {
		p.Agents[agent] = slices.Clone(tools)
	}
	if err := p.validate(); err != nil {
		panic(err) // a bug in the default, caught by its test
	}
	p.digest = "default"
	return p
}

// Managed reports whether the policy came from a file (the customer's contract) rather than the default.
func (p *Policy) Managed() bool { return p.managed }

// MayApprove reports whether a person may approve reaching host. Hosts compare case-insensitively.
func (p *Policy) MayApprove(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, pat := range p.Interactive.AllowHosts {
		switch {
		case pat == "*":
			return true
		case strings.HasPrefix(pat, "*."):
			if d := pat[2:]; host == d || strings.HasSuffix(host, "."+d) {
				return true
			}
		case host == pat:
			return true
		}
	}
	return false
}

// TargetFor is the target whose URL covers u (same scheme, host and port, under its path), if any.
func (p *Policy) TargetFor(u *url.URL) (string, bool) {
	for _, id := range p.TargetIDs() {
		t := p.Targets[id].parsed
		if strings.EqualFold(t.Scheme, u.Scheme) && strings.EqualFold(t.Host, u.Host) &&
			strings.HasPrefix(u.EscapedPath()+"/", strings.TrimSuffix(t.EscapedPath(), "/")+"/") {
			return id, true
		}
	}
	return "", false
}

func (p *Policy) validate() error {
	if p.Org != "" && !orgRE.MatchString(p.Org) {
		return fmt.Errorf("org %q: letters, digits and _.:- only", p.Org)
	}
	for id, t := range p.Targets {
		if !idRE.MatchString(id) {
			return fmt.Errorf("target id %q: lower-case letters, digits and ._- only", id)
		}
		u, err := url.Parse(t.URL)
		if err != nil {
			return fmt.Errorf("target %s: %w", id, err)
		}
		switch {
		case u.Scheme != "http" && u.Scheme != "https":
			return fmt.Errorf("target %s: url must be http or https", id)
		case u.Host == "" || u.Hostname() == "":
			return fmt.Errorf("target %s: url has no host", id)
		case u.User != nil:
			return fmt.Errorf("target %s: url must not carry credentials", id)
		case u.RawQuery != "" || u.Fragment != "":
			return fmt.Errorf("target %s: url must not have a query or fragment", id)
		}
		t.parsed = u
		p.Targets[id] = t
	}
	for _, name := range p.Packs {
		if !slices.Contains(Packs, name) {
			return fmt.Errorf("pack %q: known packs are %s", name, strings.Join(Packs, ", "))
		}
	}
	for agent, tools := range p.Agents {
		if !idRE.MatchString(agent) {
			return fmt.Errorf("agent %q: lower-case letters, digits and ._- only", agent)
		}
		for _, pat := range tools {
			if !patternRE.MatchString(pat) {
				return fmt.Errorf("agent %s: %q is not <pack>.<tool> or <pack>.*", agent, pat)
			}
			if pack, _, _ := strings.Cut(pat, "."); !slices.Contains(p.Packs, pack) {
				return fmt.Errorf("agent %s: %q names pack %q, which is not enabled under packs", agent, pat, pack)
			}
		}
	}
	for i, pat := range p.Interactive.AllowHosts {
		pat = strings.ToLower(strings.TrimSpace(pat))
		host := strings.TrimPrefix(pat, "*.")
		if pat != "*" && (host == "" || strings.ContainsAny(host, "*/:@ ") || strings.HasPrefix(host, ".")) {
			return fmt.Errorf("interactive.allow_hosts: %q is not *, a host name, or *.domain", pat)
		}
		p.Interactive.AllowHosts[i] = pat
	}
	if p.Limits.ConcurrentCalls == 0 {
		p.Limits.ConcurrentCalls = defaultConcurrentCalls
	}
	if p.Limits.CallsPerMinute == 0 {
		p.Limits.CallsPerMinute = defaultCallsPerMinute
	}
	if p.Limits.ConcurrentCalls < 1 || p.Limits.ConcurrentCalls > 64 {
		return errors.New("limits.concurrent_calls must be 1-64")
	}
	if p.Limits.CallsPerMinute < 1 || p.Limits.CallsPerMinute > 6000 {
		return errors.New("limits.calls_per_minute must be 1-6000")
	}
	return nil
}

// AllSessionKeys is session_key and session_keys together, as written.
func (p *Policy) AllSessionKeys() []string {
	var out []string
	if p.SessionKey != "" {
		out = append(out, p.SessionKey)
	}
	return append(out, p.SessionKeys...)
}

// Digest identifies this policy's content (reported to Straiker, so a session knows which it ran under).
func (p *Policy) Digest() string { return p.digest }

// Target looks up a target by id.
func (p *Policy) Target(id string) (Target, bool) {
	t, ok := p.Targets[id]
	return t, ok
}

// TargetIDs are the target ids, sorted.
func (p *Policy) TargetIDs() []string {
	ids := make([]string, 0, len(p.Targets))
	for id := range p.Targets {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// PackEnabled reports whether a pack is on.
func (p *Policy) PackEnabled(name string) bool { return slices.Contains(p.Packs, name) }

// Allowed is the host's half of "cloud grant ∩ host policy": a tool is usable by a session only if
// its pack is enabled, the policy lists it for the session's agent, and the session's grants cover it.
func (p *Policy) Allowed(agent string, grants []string, tool string) bool {
	pack, _, ok := strings.Cut(tool, ".")
	if !ok || !p.PackEnabled(pack) {
		return false
	}
	return matchAny(p.Agents[agent], tool) && matchAny(grants, tool)
}

// AllowLocal is Allowed for the local inspection mode (serve --stdio): every enabled pack's tools.
func (p *Policy) AllowLocal(tool string) bool {
	pack, _, ok := strings.Cut(tool, ".")
	return ok && p.PackEnabled(pack)
}

func matchAny(patterns []string, tool string) bool {
	for _, pat := range patterns {
		if pat == tool {
			return true
		}
		if prefix, ok := strings.CutSuffix(pat, ".*"); ok && strings.HasPrefix(tool, prefix+".") {
			return true
		}
	}
	return false
}
