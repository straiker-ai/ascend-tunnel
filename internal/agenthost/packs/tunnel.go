package packs

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/straiker-ai/ascend-tunnel/internal/agenthost/mcp"
	"github.com/straiker-ai/ascend-tunnel/internal/agenthost/policy"
	"github.com/straiker-ai/ascend-tunnel/internal/config"
)

// Tunneler runs ascend-tunnel's agent inside this process, for the targets the person approves, until the chat
// ends. It returns the agent key an Ascend application lists in _tunnel_agent_keys.
type Tunneler interface {
	Tunnel(ctx context.Context, host string, port int) (agentKey string, err error)
}

// tunnelOpen lets Straiker's cloud reach an app only this network reaches, through this machine, for as long as the
// chat runs: the tunnel without installing it. The person confirms each target; the policy caps which.
func tunnelOpen(p *policy.Policy, cf Confirmer, tn Tunneler, info Info) tool {
	return tool{
		def: mcp.Tool{Name: "tunnel.open", Title: "Reach a private app through this machine",
			Description: "Let Straiker's cloud reach an app that only this network reaches, through this machine, for as " +
				"long as ascend-agent runs (ascend-tunnel, built in). The person confirms. Returns the endpoint to create " +
				"the Ascend application on and the agent key for its _tunnel_agent_keys.",
			InputSchema: schema(`{"type":"object","properties":{"endpoint":{"type":"string",` +
				`"description":"the app's own http(s) URL, as this machine reaches it"}},` +
				`"required":["endpoint"],"additionalProperties":false}`),
			Annotations: &mcp.Annotations{OpenWorldHint: true},
		},
		run: func(ctx context.Context, args json.RawMessage) mcp.Result {
			var in struct {
				Endpoint string `json:"endpoint"`
			}
			if err := decode(args, &in); err != nil {
				return failure("arguments", err)
			}
			u, err := url.Parse(strings.TrimSpace(in.Endpoint))
			switch {
			case err != nil:
				return refuse("endpoint: " + err.Error())
			case u.Scheme != "https" && u.Scheme != "http":
				return refuse("endpoint must be http or https")
			case u.Hostname() == "" || u.User != nil:
				return refuse("endpoint must name a host and carry no credentials")
			case strings.HasSuffix(strings.ToLower(u.Hostname()), "."+config.TunnelSuffix):
				return refuse("that is already a tunnel address: give the app's own URL")
			case blockedHost(u.Hostname()):
				return refuse("that address is never reachable from this host (link-local or cloud metadata)")
			case !p.MayApprove(u.Hostname()):
				return refuse(fmt.Sprintf("the policy on this machine does not let a person approve %s", u.Hostname()))
			}
			host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
			port := map[string]int{"http": 80, "https": 443}[u.Scheme]
			if s := u.Port(); s != "" {
				if port, err = strconv.Atoi(s); err != nil || port < 1 || port > 65535 {
					return refuse("endpoint has an invalid port")
				}
			}
			addr := net.JoinHostPort(host, strconv.Itoa(port))
			// Only worth asking if this machine reaches it; dialed like net.check (metadata addresses refused).
			dctx, cancel := context.WithTimeout(ctx, 2*netCheckTimeout)
			conn, err := dialer.DialContext(dctx, "tcp", addr)
			cancel()
			if err != nil {
				return mcp.JSONResult(map[string]any{"error": "this machine cannot reach " + addr + ": " + err.Error(),
					"next": "run ascend-tunnel on a machine that reaches it"}, true)
			}
			conn.Close()
			q := fmt.Sprintf("let Straiker's cloud reach %s through this machine while ascend-agent runs (org %s)", addr, info.Org)
			if !cf.Confirm(ctx, agentFrom(ctx), q) {
				return refuse("the person at this machine did not open the tunnel")
			}
			key, err := tn.Tunnel(ctx, host, port)
			if err != nil {
				return failure("tunnel", err)
			}
			tu := url.URL{Scheme: u.Scheme, Host: host + "." + config.TunnelSuffix, Path: u.Path, RawPath: u.RawPath,
				RawQuery: u.RawQuery}
			keep := fmt.Sprintf("ascend-tunnel service install --org %s --allow %s", info.Org, addr)
			if info.Env != "" && info.Env != config.DefaultEnv {
				keep += " --env " + info.Env
			}
			return mcp.JSONResult(map[string]any{
				"endpoint": tu.String(), "agentKey": key, "target": addr,
				"lifetime":    "until the person exits ascend-agent or closes it with /tunnel close; Straiker reaches the app only while it is open",
				"keepRunning": keep + "  (on this machine, so assessments run without the terminal; same agent key)",
				"next": "create the application on endpoint with tunnel_agent_keys [agentKey]; the tunnel connects " +
					"within seconds of the application listing the key",
			}, false)
		},
	}
}
