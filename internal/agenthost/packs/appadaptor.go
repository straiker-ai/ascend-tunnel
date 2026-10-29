package packs

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/straiker-ai/ascend-tunnel/internal/agenthost/mcp"
)

// Patcher changes a platform record as the signed-in person.
type Patcher interface {
	PlatformPatch(ctx context.Context, path string, body, out any) error
}

const (
	// adaptorKey is where an application carries its adaptor: iris lifts it into adapter_source at run start.
	adaptorKey = "_adaptor_src"
	// maxAdaptorValue keeps the stored record well under the platform's 400 KB item limit.
	maxAdaptorValue = 256 << 10
)

var aliasRE = regexp.MustCompile(`^v0:[a-z0-9_-]{1,64}$`)

// appAdaptor stores an adaptor on an existing application as the signed-in person, after they say yes at this
// terminal: the value goes into the application's request_template under _adaptor_src, the rest of the template
// unchanged, and is read back to prove it landed.
func appAdaptor(pl Platform, pt Patcher, cf Confirmer, org string) tool {
	return tool{
		def: mcp.Tool{Name: "ascend.app_adaptor", Title: "Store an adaptor on an Ascend application",
			Description: "Store an adaptor on one of the person's Ascend applications, after they confirm at their terminal. " +
				"The adaptor is the gated template value (base64) or a v0: alias.",
			InputSchema: schema(`{"type":"object","properties":{` +
				`"app":{"type":"string","description":"the application's aapp_ id"},` +
				`"name":{"type":"string","description":"the application's name, as a check"},` +
				`"adaptor":{"type":"string","description":"the gated template value (base64) or a v0: alias"},` +
				`"summary":{"type":"string","maxLength":200,"description":"what the adaptor does, for the person"}},` +
				`"required":["app","name","adaptor"],"additionalProperties":false}`)},
		run: func(ctx context.Context, args json.RawMessage) mcp.Result {
			var in struct {
				App     string `json:"app"`
				Name    string `json:"name"`
				Adaptor string `json:"adaptor"`
				Summary string `json:"summary"`
			}
			if err := decode(args, &in); err != nil {
				return failure("arguments", err)
			}
			if !publicAppRE.MatchString(in.App) {
				return refuse("app is the application's aapp_ id")
			}
			what, problem := describeAdaptor(in.Adaptor)
			if problem != "" {
				return refuse(problem)
			}
			path := "/api/v3/ascend/applications/" + in.App
			rec, tpl, err := appTemplate(ctx, pl, path)
			if err != nil {
				return failure("application", err)
			}
			name, _ := rec["name"].(string)
			if name != in.Name {
				return refuse(fmt.Sprintf("application %s is named %q, not %q: nothing was stored", in.App, name, in.Name))
			}
			replaces := "nothing (it runs on its request template alone)"
			if cur, ok := tpl[adaptorKey].(string); ok && cur != "" {
				if cur == in.Adaptor {
					return mcp.JSONResult(map[string]any{"stored": true, "unchanged": true, "app": in.App, "name": name}, false)
				}
				replaces = "its current adaptor (" + describeStored(cur) + ")"
			}
			url, _ := rec["url"].(string)
			question := fmt.Sprintf("store the adaptor %s on the Ascend application %q (%s) in org %s, replacing %s",
				what, name, url, org, replaces)
			if in.Summary != "" {
				question += ": " + in.Summary
			}
			if !cf.Confirm(ctx, agentFrom(ctx), question) {
				return refuse("the person did not confirm: nothing was stored")
			}
			tpl[adaptorKey] = in.Adaptor
			raw, err := json.MarshalIndent(tpl, "", "  ")
			if err != nil {
				return failure("template", err)
			}
			var out map[string]any
			if err := pt.PlatformPatch(ctx, path, map[string]any{"request_template": string(raw)}, &out); err != nil {
				return failure("store", err)
			}
			if _, after, err := appTemplate(ctx, pl, path); err != nil || after[adaptorKey] != in.Adaptor {
				return refuse("Straiker did not keep the adaptor on " + in.App + ": check the application in the console")
			}
			return mcp.JSONResult(map[string]any{"stored": true, "app": in.App, "name": name, "adaptor": what,
				"replaced": replaces}, false)
		},
	}
}

// appTemplate reads an application and its request_template, which must be a JSON object.
func appTemplate(ctx context.Context, pl Platform, path string) (map[string]any, map[string]any, error) {
	var rec map[string]any
	if err := pl.PlatformGet(ctx, path, nil, &rec); err != nil {
		return nil, nil, err
	}
	tpl := map[string]any{}
	if s, _ := rec["request_template"].(string); s != "" {
		if err := json.Unmarshal([]byte(s), &tpl); err != nil {
			return nil, nil, fmt.Errorf("its request_template is not a JSON object; fix it in the console first")
		}
	}
	return rec, tpl, nil
}

// describeAdaptor names an adaptor for the person (its alias, or digest and size), or says why it cannot be stored.
func describeAdaptor(v string) (string, string) {
	switch {
	case aliasRE.MatchString(v):
		return v, ""
	case v == "" || len(v) > maxAdaptorValue:
		return "", fmt.Sprintf("adaptor is a base64 template value under %d KiB, or a v0: alias", maxAdaptorValue>>10)
	}
	src, err := base64.StdEncoding.DecodeString(v)
	if err != nil || len(src) == 0 {
		return "", "adaptor is the gated template value (base64), as the gate returns it"
	}
	return describeStored(v), ""
}

func describeStored(v string) string {
	if aliasRE.MatchString(v) {
		return v
	}
	sum := sha256.Sum256([]byte(v))
	return fmt.Sprintf("sha256 %s, %.1f KB", hex.EncodeToString(sum[:])[:12], float64(len(v))/1000)
}
