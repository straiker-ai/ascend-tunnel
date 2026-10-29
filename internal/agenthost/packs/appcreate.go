package packs

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/straiker-ai/ascend-tunnel/internal/agenthost/mcp"
)

// Confirmer is the person at this terminal: it approves one action an agent wants to take on their behalf, and
// types a secret that never reaches an agent. Only an interactive chat has one, so a service never offers the
// tools that need it.
type Confirmer interface {
	Confirm(ctx context.Context, agent, question string) bool
	Secret(ctx context.Context, prompt string) (string, bool)
}

const (
	maxAppName      = 200
	maxTemplateJSON = 32 << 10
	maxHeaders      = 30
)

var (
	headerNameRE = regexp.MustCompile(`^[A-Za-z0-9!#$%&'*+.^_|~-]{1,100}$`)
	// A credential travels only as the {{API_KEY}} placeholder; the person types the value at this terminal.
	credentialHeaders = map[string]bool{"authorization": true, "proxy-authorization": true, "cookie": true,
		"x-api-key": true, "api-key": true, "apikey": true, "x-auth-token": true, "x-access-token": true}
	sizes = map[string]bool{"small": true, "medium": true, "large": true}
)

// appCreate creates an Ascend application as the signed-in person, after they say yes at this terminal. It looks
// for an application already on the same endpoint (or with the same name) first and returns those instead of
// creating a duplicate, unless allow_duplicate is set; the person still confirms.
func appCreate(pl Platform, cf Confirmer, org string) tool {
	return tool{
		def: mcp.Tool{Name: "ascend.app_create", Title: "Create an Ascend application",
			Description: "Create an Ascend application for a chat API as the signed-in person, after they confirm at their terminal. " +
				"Returns the applications already on the same endpoint or name instead, unless allow_duplicate.",
			InputSchema: schema(`{"type":"object","properties":{` +
				`"name":{"type":"string"},"endpoint":{"type":"string"},` +
				`"request_template":{"type":"object"},"response_path":{"type":"string"},` +
				`"headers":{"type":"object","additionalProperties":{"type":"string"}},` +
				`"api_key":{"type":"string","enum":["none","ask"]},` +
				`"size":{"type":"string","enum":["small","medium","large"]},"qpm":{"type":"integer","minimum":1,"maximum":600},` +
				`"system_prompt":{"type":"string"},"purpose":{"type":"string"},` +
				`"controls":{"type":"array","items":{"type":"string"},"maxItems":500},"allow_duplicate":{"type":"boolean"}},` +
				`"required":["name","endpoint","request_template","response_path"],"additionalProperties":false}`)},
		run: func(ctx context.Context, args json.RawMessage) mcp.Result {
			var in struct {
				Name            string            `json:"name"`
				Endpoint        string            `json:"endpoint"`
				RequestTemplate map[string]any    `json:"request_template"`
				ResponsePath    string            `json:"response_path"`
				Headers         map[string]string `json:"headers"`
				APIKey          string            `json:"api_key"`
				Size            string            `json:"size"`
				QPM             int               `json:"qpm"`
				SystemPrompt    string            `json:"system_prompt"`
				Purpose         string            `json:"purpose"`
				Controls        []string          `json:"controls"`
				AllowDuplicate  bool              `json:"allow_duplicate"`
			}
			if err := decode(args, &in); err != nil {
				return failure("arguments", err)
			}
			spec, endpoint, problem := appSpec(in.Name, in.Endpoint, in.RequestTemplate, in.ResponsePath, in.Headers,
				in.Size, in.QPM, in.SystemPrompt, in.Purpose)
			if problem != "" {
				return refuse(problem)
			}
			if in.APIKey == "" {
				in.APIKey = "none"
			}
			if in.APIKey != "none" && in.APIKey != "ask" {
				return refuse(`api_key is "none" or "ask" (the person types it here); never the key itself`)
			}
			if in.APIKey == "none" && strings.Contains(spec["request_template"].(string)+headerJSON(spec), "{{API_KEY}}") {
				return refuse(`the request uses {{API_KEY}}: set api_key to "ask"`)
			}

			existing, err := sameApps(ctx, pl, endpoint, in.Name)
			if err != nil {
				return failure("applications", err)
			}
			if len(existing) > 0 && !in.AllowDuplicate {
				return mcp.JSONResult(map[string]any{"created": false, "existing": existing,
					"next": "An application already uses this endpoint or name: offer the person that one; create another " +
						"only if they want it, with allow_duplicate."}, false)
			}

			controls, err := chooseControls(ctx, pl, in.Controls)
			if err != nil {
				return refuse(err.Error())
			}
			spec["control_type"], spec["control_ids"] = "custom", controls

			question := fmt.Sprintf("create the Ascend application %q for %s in org %s (%s, %d queries a minute, %d controls)",
				in.Name, endpoint, org, spec["assessment_size"], spec["max_queries_per_minute"], len(controls))
			if len(existing) > 0 {
				question += fmt.Sprintf(", although %d application(s) already use this endpoint or name", len(existing))
			}
			if !cf.Confirm(ctx, agentFrom(ctx), question) {
				return refuse("the person did not confirm: nothing was created")
			}
			spec["api_key"] = "none"
			if in.APIKey == "ask" {
				key, ok := cf.Secret(ctx, "API key for "+endpoint+" (stored with the application in Straiker; the agent never sees it)")
				if !ok || strings.TrimSpace(key) == "" {
					return refuse("the person did not enter an API key: nothing was created")
				}
				spec["api_key"] = strings.TrimSpace(key)
			}

			var made map[string]any
			if err := pl.PlatformPost(ctx, "/api/v3/ascend/applications", spec, &made); err != nil {
				return failure("create", err)
			}
			id, _ := made["id"].(string)
			if !publicAppRE.MatchString(id) || made["name"] != in.Name {
				return refuse("Straiker's answer did not name the application just created; check /apps before trying again")
			}
			return mcp.JSONResult(map[string]any{"created": true, "id": id, "name": in.Name, "url": endpoint}, false)
		},
	}
}

// appSpec is the platform's create request for a single-POST chat API, as straiker-ai/ascend-agent builds it,
// without the API key and controls; or why it cannot be made. endpoint comes back normalised.
func appSpec(name, endpoint string, body map[string]any, responsePath string, headers map[string]string,
	size string, qpm int, systemPrompt, purpose string) (map[string]any, string, string) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > maxAppName {
		return nil, "", fmt.Sprintf("name is 1-%d characters", maxAppName)
	}
	u, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || len(endpoint) > 2048 {
		return nil, "", "endpoint is the chat API's http(s) URL"
	}
	u.Fragment = ""
	tmpl, err := json.Marshal(body)
	if err != nil || len(tmpl) > maxTemplateJSON {
		return nil, "", "request_template is a JSON object under 32 KiB"
	}
	if !strings.Contains(string(tmpl), "{{PROMPT}}") {
		return nil, "", `request_template must carry "{{PROMPT}}" where the message goes`
	}
	response, problem := responseTemplate(responsePath)
	if problem != "" {
		return nil, "", problem
	}
	if len(headers) > maxHeaders {
		return nil, "", fmt.Sprintf("at most %d headers", maxHeaders)
	}
	rows := []map[string]string{}
	hasType := false
	for k, v := range headers {
		lk := strings.ToLower(k)
		switch {
		case !headerNameRE.MatchString(k) || len(v) > 4096 || strings.ContainsAny(v, "\r\n"):
			return nil, "", "header " + k + " is not a valid header"
		case credentialHeaders[lk] && !strings.Contains(v, "{{API_KEY}}"):
			return nil, "", "header " + k + ` carries a credential: write it with {{API_KEY}} (e.g. "Bearer {{API_KEY}}") and set api_key to "ask"`
		case lk == "content-type":
			hasType = true
		}
		rows = append(rows, map[string]string{"name": k, "value": v})
	}
	if !hasType {
		rows = append(rows, map[string]string{"name": "Content-Type", "value": "application/json"})
	}
	if size == "" {
		size = "small"
	}
	if !sizes[size] {
		return nil, "", "size is small, medium or large"
	}
	if qpm == 0 {
		qpm = 30
	}
	if systemPrompt == "" {
		systemPrompt = name
	}
	spec := map[string]any{"name": name, "api_type": "api", "url": u.String(), "system_prompt": systemPrompt,
		"max_queries_per_minute": qpm, "assessment_size": size, "request_template": string(tmpl),
		"response_template": response, "headers": rows}
	if purpose != "" {
		spec["business_purpose"] = purpose
	}
	return spec, u.String(), ""
}

// responseTemplate turns a path such as "choices.0.message.content" into the platform's response template, with
// {{RESPONSE}} where the reply is (only the first element of an array, as the platform reads it).
func responseTemplate(path string) (string, string) {
	if path == "" || len(path) > 512 {
		return "", "response_path is where the reply is in the response, e.g. \"reply\" or \"choices.0.message.content\""
	}
	var v any = "{{RESPONSE}}"
	parts := strings.FieldsFunc(path, func(r rune) bool { return r == '.' || r == '[' || r == ']' })
	for i := len(parts) - 1; i >= 0; i-- {
		switch p := parts[i]; {
		case p == "0":
			v = []any{v}
		case strings.Trim(p, "0123456789") == "":
			return "", "response_path reads only the first element of an array (index 0)"
		default:
			v = map[string]any{p: v}
		}
	}
	b, _ := json.Marshal(v)
	return string(b), ""
}

func headerJSON(spec map[string]any) string {
	b, _ := json.Marshal(spec["headers"])
	return string(b)
}

// sameApps is the person's applications already on this endpoint (scheme, host and path, case and a trailing
// slash aside) or with this name.
func sameApps(ctx context.Context, pl Platform, endpoint, name string) ([]map[string]any, error) {
	want := endpointKey(endpoint)
	var out []map[string]any
	after := ""
	for seen := 0; seen < maxApps; {
		q := url.Values{"limit": {"100"}}
		if after != "" {
			q.Set("starting_after", after)
		}
		var page struct {
			Data    []map[string]any `json:"data"`
			HasMore bool             `json:"has_more"`
		}
		if err := pl.PlatformGet(ctx, "/api/v3/ascend/applications", q, &page); err != nil {
			return nil, err
		}
		for _, a := range page.Data {
			u, _ := a["url"].(string)
			n, _ := a["name"].(string)
			if (u != "" && endpointKey(u) == want) || strings.EqualFold(strings.TrimSpace(n), strings.TrimSpace(name)) {
				out = append(out, map[string]any{"id": a["id"], "name": n, "url": u})
			}
		}
		seen += len(page.Data)
		if !page.HasMore || len(page.Data) == 0 {
			break
		}
		after, _ = page.Data[len(page.Data)-1]["id"].(string)
	}
	return out, nil
}

func endpointKey(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return strings.ToLower(raw)
	}
	host := strings.ToLower(u.Hostname())
	if p := u.Port(); p != "" && !(u.Scheme == "https" && p == "443") && !(u.Scheme == "http" && p == "80") {
		host += ":" + p
	}
	return strings.ToLower(u.Scheme) + "://" + host + strings.TrimRight(u.EscapedPath(), "/")
}

// chooseControls is the controls to assess with: the person's choice, checked against the catalog, or every
// control that is not deprecated.
func chooseControls(ctx context.Context, pl Platform, chosen []string) ([]string, error) {
	var catalog struct {
		Controls []map[string]any `json:"controls"`
		Data     []map[string]any `json:"data"`
	}
	if err := pl.PlatformGet(ctx, "/api/v3/ascend/controls", nil, &catalog); err != nil {
		return nil, fmt.Errorf("the controls catalog could not be read: %v", err)
	}
	rows := catalog.Controls
	if len(rows) == 0 {
		rows = catalog.Data
	}
	live := map[string]bool{}
	var all []string
	for _, c := range rows {
		id, _ := c["id"].(string)
		if dep, _ := c["deprecated"].(bool); id == "" || dep {
			continue
		}
		live[id] = true
		all = append(all, id)
	}
	if len(chosen) == 0 {
		if len(all) == 0 {
			return nil, fmt.Errorf("the controls catalog has no controls")
		}
		return all, nil
	}
	for _, c := range chosen {
		if !live[c] {
			return nil, fmt.Errorf("control %q is not in the catalog (or is deprecated)", c)
		}
	}
	return chosen, nil
}
