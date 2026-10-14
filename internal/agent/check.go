package agent

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"time"

	"github.com/straiker-ai/ascend-tunnel/internal/identity"
)

const checkDialTimeout = 5 * time.Second

// CheckScope picks what `check` tests: both halves, or one.
type CheckScope int

const (
	CheckAll    CheckScope = iota
	CheckTunnel            // this machine to Straiker's relay: the customer's network team
	CheckApps              // this machine to each allowlisted app: the app's owners
)

// Check runs the setup preflight and prints it to w, a block a customer can paste to Straiker: the
// tunnel (the path to the relay, hop by hop, and the agent's login) and the apps (each allowlisted
// target), each ending in a RESULT line. It returns false if any step failed.
func (a *Agent) Check(ctx context.Context, w io.Writer, scope CheckScope) bool {
	ok := true
	if scope != CheckApps {
		var s steps
		if a.id.Unsaved {
			s.add("INFO", "agent", fmt.Sprintf("org %s; no agent key yet in %s: the agent creates it when it first "+
				"runs (this check creates nothing)", a.id.Tenant, filepath.Dir(a.id.KeyPath)), "")
		} else {
			s.add("INFO", "agent", fmt.Sprintf("org %s, agent %s", a.id.Tenant, a.id.AgentID), "")
			s.add("INFO", "agent", "key (paste into each app's _tunnel_agent_keys): "+identity.PasteForm(a.id.PublicKey), "")
			s.add("INFO", "agent", "request template for a new Ascend app: "+identity.RequestTemplate(a.id.PublicKey), "")
		}
		if p := relayProxy(a.cfg.Relay); p != "" {
			s.add("INFO", "relay", fmt.Sprintf("%s via proxy %s", redact(a.cfg.Relay), p), "")
		} else {
			s.add("INFO", "relay", fmt.Sprintf("%s, direct (no HTTPS_PROXY)", redact(a.cfg.Relay)), "")
		}
		s = append(s, a.probeRelay(ctx, true)...)
		ok = printSection(w, "Tunnel: this machine -> Straiker", s, tunnelVerdict(s)) && ok
	}
	if scope != CheckTunnel {
		s := a.probeTargets(ctx)
		ok = printSection(w, "Apps: this machine -> your apps", s, appsVerdict(s, len(a.cfg.Forwards))) && ok
	}
	return ok
}

func printSection(w io.Writer, title string, s steps, v verdict) bool {
	fmt.Fprintf(w, "== %s\n", title)
	for _, st := range s {
		fmt.Fprintf(w, "%-6s %-9s %s\n", st.status, st.name, st.detail)
		if st.fix != "" {
			fmt.Fprintf(w, "%-16s -> %s\n", "", st.fix)
		}
	}
	see := ""
	if v.status == "FAIL" {
		see = " (see -> above)"
	}
	fmt.Fprintf(w, "RESULT %s: %s%s\n\n", v.status, v.text, see)
	return v.status != "FAIL"
}
