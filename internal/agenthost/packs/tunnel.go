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
)

// BrokerSuffix is the domain Straiker reaches a Straiker Broker target under: <host>.<suffix>.
const BrokerSuffix = "brk.straiker.ai"

// Tunneler runs Straiker Broker's agent inside this process, for the targets the person approves, until the chat
// ends. It registers each target with Straiker as the signed-in person and returns the target's id, with the command
// that keeps the open targets reachable as a service.
type Tunneler interface {
	Tunnel(ctx context.Context, host string, port int) (brokerTarget, keepRunning string, err error)
}

// tunnelOpen lets Straiker's cloud reach an app only this network reaches, through this machine, for as long as the
// chat runs: the tunnel without installing it. The person confirms each target; the policy caps which.
func tunnelOpen(p *policy.Policy, cf Confirmer, tn Tunneler, info Info) tool {
	return tool{
		def: mcp.Tool{Name: "tunnel.open", Title: "Reach a private app through this machine",
			Description: "Let Straiker's cloud reach an app that only this network reaches, through this machine, for as " +
				"long as ascend-agent runs (Straiker Broker, built in). The person confirms. Returns the endpoint to create " +
				"the Ascend application on and the Straiker Broker target for its _broker_targets.",
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
			case strings.HasSuffix(strings.ToLower(u.Hostname()), "."+BrokerSuffix):
				return refuse("that is already a Straiker Broker address: give the app's own URL")
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
					"next": "run straiker-broker on a machine that reaches it"}, true)
			}
			conn.Close()
			q := fmt.Sprintf("let Straiker's cloud reach %s through this machine while ascend-agent runs (Straiker Broker, org %s)", addr, info.Org)
			if !cf.Confirm(ctx, agentFrom(ctx), q) {
				return refuse("the person at this machine did not open the tunnel")
			}
			target, keep, err := tn.Tunnel(ctx, host, port)
			if err != nil {
				return failure("tunnel", err)
			}
			tu := url.URL{Scheme: u.Scheme, Host: host + "." + BrokerSuffix, Path: u.Path, RawPath: u.RawPath,
				RawQuery: u.RawQuery}
			return mcp.JSONResult(map[string]any{
				"endpoint": tu.String(), "brokerTarget": target, "target": addr, "keepRunning": keep,
				"lifetime": "until the person exits ascend-agent or closes it with /tunnel close; Straiker reaches the app only while it is open",
				"next": fmt.Sprintf("create the application on endpoint, its request_template carrying \"_broker_targets\": "+
					"{%q: %q}; keepRunning, run on this machine, keeps the open apps reachable without the terminal "+
					"(same broker key)", tu.Host, target),
			}, false)
		},
	}
}
