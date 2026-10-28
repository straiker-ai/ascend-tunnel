package packs

import (
	"context"
	"encoding/json"
	"net/url"
	"regexp"
	"strconv"

	"github.com/straiker-ai/ascend-tunnel/internal/agenthost/mcp"
)

// Platform reads Straiker's API as the person signed in at this terminal. The ascend pack's tools use it, so an
// agent reads only what that person's own login can, and no token leaves this machine.
type Platform interface {
	PlatformGet(ctx context.Context, path string, query url.Values, out any) error
}

var (
	publicAppRE = regexp.MustCompile(`^aapp_[A-Za-z0-9]{8,40}$`)
	publicRunRE = regexp.MustCompile(`^asmt_[A-Za-z0-9_-]{8,60}$`)
)

const (
	maxApps        = 300
	maxRunsPerPage = 50
	summaryChars   = 1500
)

// ascendTools are fixed, read-only calls on the person's Ascend data: the cloud sends ids, never a path.
func ascendTools(pl Platform) []tool {
	return []tool{
		{
			def: mcp.Tool{Name: "ascend.apps", Title: "The person's Ascend applications",
				Description: "List the Ascend applications the signed-in person can see: id, name and the host each one talks to.",
				InputSchema: schema(`{"type":"object","properties":{},"additionalProperties":false}`),
				Annotations: &mcp.Annotations{ReadOnlyHint: true}},
			run: func(ctx context.Context, args json.RawMessage) mcp.Result {
				var in struct{}
				if err := decode(args, &in); err != nil {
					return failure("arguments", err)
				}
				var apps []map[string]any
				after := ""
				for len(apps) < maxApps {
					q := url.Values{"limit": {"100"}}
					if after != "" {
						q.Set("starting_after", after)
					}
					var page struct {
						Data    []map[string]any `json:"data"`
						HasMore bool             `json:"has_more"`
					}
					if err := pl.PlatformGet(ctx, "/api/v3/ascend/applications", q, &page); err != nil {
						return failure("applications", err)
					}
					for _, a := range page.Data {
						apps = append(apps, map[string]any{"id": a["id"], "name": a["name"], "host": hostOf(a["url"])})
					}
					if !page.HasMore || len(page.Data) == 0 {
						break
					}
					after, _ = page.Data[len(page.Data)-1]["id"].(string)
				}
				return mcp.JSONResult(map[string]any{"applications": apps}, false)
			},
		},
		{
			def: mcp.Tool{Name: "ascend.runs", Title: "An application's assessment runs",
				Description: "List an application's assessment runs, newest first, with each run's status, score, totals, severity and per-category results.",
				InputSchema: schema(`{"type":"object","properties":{"app":{"type":"string","description":"an aapp_ id from ascend.apps"},` +
					`"limit":{"type":"integer","minimum":1,"maximum":50},"starting_after":{"type":"string"}},"required":["app"],"additionalProperties":false}`),
				Annotations: &mcp.Annotations{ReadOnlyHint: true}},
			run: func(ctx context.Context, args json.RawMessage) mcp.Result {
				var in struct {
					App           string `json:"app"`
					Limit         int    `json:"limit"`
					StartingAfter string `json:"starting_after"`
				}
				if err := decode(args, &in); err != nil {
					return failure("arguments", err)
				}
				if !publicAppRE.MatchString(in.App) || (in.StartingAfter != "" && !publicRunRE.MatchString(in.StartingAfter)) {
					return refuse("app must be an aapp_ id (and starting_after an asmt_ id)")
				}
				if in.Limit < 1 || in.Limit > maxRunsPerPage {
					in.Limit = 10
				}
				q := url.Values{"limit": {strconv.Itoa(in.Limit)}}
				if in.StartingAfter != "" {
					q.Set("starting_after", in.StartingAfter)
				}
				var page struct {
					Data    []map[string]any `json:"data"`
					HasMore bool             `json:"has_more"`
				}
				if err := pl.PlatformGet(ctx, "/api/v3/ascend/applications/"+in.App+"/assessments", q, &page); err != nil {
					return failure("assessments", err)
				}
				runs := make([]map[string]any, 0, len(page.Data))
				for _, a := range page.Data {
					runs = append(runs, trimRun(a, false))
				}
				return mcp.JSONResult(map[string]any{"app": in.App, "runs": runs, "has_more": page.HasMore}, false)
			},
		},
		{
			def: mcp.Tool{Name: "ascend.run", Title: "One assessment run",
				Description: "Read one assessment run: status, score, per-category and per-control results, the written summary and the recommendations.",
				InputSchema: schema(`{"type":"object","properties":{"app":{"type":"string"},"run":{"type":"string","description":"an asmt_ id"}},"required":["app","run"],"additionalProperties":false}`),
				Annotations: &mcp.Annotations{ReadOnlyHint: true}},
			run: func(ctx context.Context, args json.RawMessage) mcp.Result {
				var in struct {
					App string `json:"app"`
					Run string `json:"run"`
				}
				if err := decode(args, &in); err != nil {
					return failure("arguments", err)
				}
				if !publicAppRE.MatchString(in.App) || !publicRunRE.MatchString(in.Run) {
					return refuse("app must be an aapp_ id and run an asmt_ id")
				}
				var a map[string]any
				if err := pl.PlatformGet(ctx, "/api/v3/ascend/applications/"+in.App+"/assessments/"+in.Run, nil, &a); err != nil {
					return failure("assessment", err)
				}
				return mcp.JSONResult(trimRun(a, true), false)
			},
		},
	}
}

func hostOf(v any) string {
	s, _ := v.(string)
	if u, err := url.Parse(s); err == nil {
		return u.Host
	}
	return ""
}

// trimRun keeps what a summary needs: no finding ids, and controls only in a single run's detail.
func trimRun(a map[string]any, detail bool) map[string]any {
	out := map[string]any{}
	for _, k := range []string{"id", "name", "status", "type", "score", "total", "failed", "severity", "progress",
		"trend", "created_at", "completed_at"} {
		if v, ok := a[k]; ok {
			out[k] = v
		}
	}
	var cats []map[string]any
	if list, ok := a["category_summary"].([]any); ok {
		for _, c := range list {
			cm, _ := c.(map[string]any)
			if cm == nil {
				continue
			}
			cat := map[string]any{"id": cm["id"], "name": cm["name"], "failed": cm["failed"], "total": cm["total"],
				"score": cm["score"], "severity": cm["severity"], "status": cm["status"]}
			if detail {
				var controls []map[string]any
				if cl, ok := cm["controls"].([]any); ok {
					for _, x := range cl {
						if xm, _ := x.(map[string]any); xm != nil {
							controls = append(controls, map[string]any{"id": xm["id"], "failed": xm["failed"], "total": xm["total"],
								"severity": xm["severity"], "status": xm["status"]})
						}
					}
				}
				cat["controls"] = controls
			}
			cats = append(cats, cat)
		}
	}
	out["categories"] = cats
	if detail {
		if s, ok := a["summary"].(string); ok {
			if len(s) > summaryChars {
				s = s[:summaryChars] + "…"
			}
			out["summary"] = s
		}
		var recs []any
		if list, ok := a["recommendations"].([]any); ok {
			for _, r := range list {
				if rm, _ := r.(map[string]any); rm != nil {
					recs = append(recs, rm["title"])
				}
			}
		}
		out["recommendations"] = recs
	}
	return out
}
