package packs

import (
	"context"
	"encoding/json"
	"regexp"

	"github.com/straiker-ai/ascend-tunnel/internal/agenthost/mcp"
	"github.com/straiker-ai/ascend-tunnel/internal/agenthost/policy"
)

var appIDRE = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func browserCapture(p *policy.Policy, ap Approver, c Capturer) tool {
	return tool{
		def: mcp.Tool{
			Name:  "browser.capture",
			Title: "Record the person using a browser",
			Description: "Open a visible browser window on this machine at a site, and record its network traffic while the person uses it; " +
				"nothing is clicked or typed for them. Returns at once: the person finishes in their terminal, and the HAR, redacted on this " +
				"machine, reaches the session as their message.",
			InputSchema: schema(`{"type":"object","properties":{"target":` + targetSchema + `,"url":` + urlSchema +
				`,"app_id":{"type":"string","description":"the Straiker application the capture is for"},` +
				`"instructions":{"type":"string","maxLength":300,"description":"what the person should do in the window, shown in their terminal"}},"additionalProperties":false}`),
			Annotations: &mcp.Annotations{OpenWorldHint: true},
		},
		run: func(ctx context.Context, args json.RawMessage) mcp.Result {
			var in struct {
				Target       string `json:"target"`
				URL          string `json:"url"`
				AppID        string `json:"app_id"`
				Instructions string `json:"instructions"`
			}
			if err := decode(args, &in); err != nil {
				return failure("arguments", err)
			}
			if in.AppID != "" && !appIDRE.MatchString(in.AppID) {
				return refuse("app_id must be the application's uuid")
			}
			if len(in.Instructions) > 300 {
				in.Instructions = in.Instructions[:300]
			}
			u, _, refusal, ok := site(ctx, p, ap, "browser.capture", in.Target, in.URL)
			if !ok {
				return refusal
			}
			out, err := c.Capture(ctx, agentFrom(ctx), u, in.AppID, in.Instructions)
			if err != nil {
				return refuse(err.Error())
			}
			return mcp.JSONResult(out, false)
		},
	}
}
