package packs

import (
	"context"
	"encoding/json"
	"runtime"

	"github.com/straiker-ai/ascend-tunnel/internal/agenthost/mcp"
	"github.com/straiker-ai/ascend-tunnel/internal/agenthost/netx"
	"github.com/straiker-ai/ascend-tunnel/internal/agenthost/policy"
)

func envInfo(p *policy.Policy, info Info, r *Registry, approvals bool) tool {
	return tool{
		def: mcp.Tool{
			Name:        "env.info",
			Title:       "Agent host environment",
			Description: "Describe this host: version, platform, the targets its policy names (ids only), the tools it serves, whether a person can approve other sites, and whether it reaches Straiker through a proxy.",
			InputSchema: schema(`{"type":"object","properties":{},"additionalProperties":false}`),
			Annotations: &mcp.Annotations{ReadOnlyHint: true},
		},
		run: func(_ context.Context, args json.RawMessage) mcp.Result {
			var in struct{}
			if err := decode(args, &in); err != nil {
				return failure("arguments", err)
			}
			return mcp.JSONResult(map[string]any{
				"host_version":  info.Version,
				"os":            runtime.GOOS,
				"arch":          runtime.GOARCH,
				"host_id":       info.HostID,
				"org":           info.Org,
				"targets":       p.TargetIDs(),
				"tools":         r.Names(),
				"policy_digest": p.Digest(),
				"approvals":     approvals,
				"proxy":         netx.ProxyFor(info.API),
			}, false)
		},
	}
}
