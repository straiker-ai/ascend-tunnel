package packs

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/straiker-ai/ascend-tunnel/internal/agenthost/policy"
)

// fakeOrg is Straiker's API for one signed-in person, and that person at the terminal.
type fakeOrg struct {
	fakeApprover
	apps    []map[string]any
	posted  []map[string]any
	confirm bool
	asked   []string
	key     string
}

func (f *fakeOrg) PlatformGet(ctx context.Context, path string, q url.Values, out any) error {
	var body any
	switch {
	case strings.HasSuffix(path, "/applications"):
		body = map[string]any{"data": f.apps, "has_more": false}
	case strings.HasSuffix(path, "/controls"):
		body = map[string]any{"controls": []map[string]any{{"id": "pii_leak"}, {"id": "old_one", "deprecated": true}, {"id": "prompt_injection"}}}
	}
	raw, _ := json.Marshal(body)
	return json.Unmarshal(raw, out)
}

func (f *fakeOrg) PlatformPost(ctx context.Context, path string, body, out any) error {
	raw, _ := json.Marshal(body)
	var spec map[string]any
	_ = json.Unmarshal(raw, &spec)
	f.posted = append(f.posted, spec)
	answer, _ := json.Marshal(map[string]any{"id": "aapp_NewApp0000000000001", "name": spec["name"], "api_type": "api"})
	return json.Unmarshal(answer, out)
}

func (f *fakeOrg) Confirm(ctx context.Context, agent, question string) bool {
	f.asked = append(f.asked, agent+": "+question)
	return f.confirm
}

func (f *fakeOrg) Secret(ctx context.Context, prompt string) (string, bool) {
	return f.key, f.key != ""
}

func createRegistry(org *fakeOrg) *Registry {
	return New(policy.Default(), Info{Org: "1"}, http.DefaultClient, nil, org)
}

const chatArgs = `"name":"support-bot","endpoint":"https://Chat.Example.com/v1/chat/","request_template":{"messages":[{"role":"user","content":"{{PROMPT}}"}]},"response_path":"choices.0.message.content"`

func TestAnApplicationIsCreatedOnlyAfterThePersonConfirms(t *testing.T) {
	org := &fakeOrg{confirm: true}
	out, isErr := callAs(t, createRegistry(org), "ascend", "ascend.app_create", `{`+chatArgs+`}`)
	if isErr || out["created"] != true || out["id"] != "aapp_NewApp0000000000001" {
		t.Fatalf("create: %v", out)
	}
	if len(org.asked) != 1 || !strings.Contains(org.asked[0], `"support-bot"`) || !strings.Contains(org.asked[0], "in org 1") ||
		!strings.HasPrefix(org.asked[0], "ascend: ") {
		t.Fatalf("the person is asked, naming the app, endpoint and org: %q", org.asked)
	}
	spec := org.posted[0]
	if spec["url"] != "https://Chat.Example.com/v1/chat/" || spec["api_key"] != "none" || spec["api_type"] != "api" ||
		spec["response_template"] != `{"choices":[{"message":{"content":"{{RESPONSE}}"}}]}` ||
		!strings.Contains(spec["request_template"].(string), "{{PROMPT}}") {
		t.Fatalf("spec: %v", spec)
	}
	if ids, _ := json.Marshal(spec["control_ids"]); string(ids) != `["pii_leak","prompt_injection"]` {
		t.Fatalf("every control that is not deprecated, by default: %s", ids)
	}
	if h, _ := json.Marshal(spec["headers"]); !strings.Contains(string(h), "application/json") {
		t.Fatalf("headers: %s", h)
	}
}

func TestADeclinedApplicationIsNotCreated(t *testing.T) {
	org := &fakeOrg{confirm: false}
	if out, isErr := callAs(t, createRegistry(org), "ascend", "ascend.app_create", `{`+chatArgs+`}`); !isErr || len(org.posted) != 0 {
		t.Fatalf("declined: %v, posted %v", out, org.posted)
	}
}

func TestAnApplicationAlreadyOnTheEndpointIsOfferedNotDuplicated(t *testing.T) {
	for _, existing := range []map[string]any{
		{"id": "aapp_Old0000000000000001", "name": "chat", "url": "https://chat.example.com/v1/chat"},  // case and slash aside
		{"id": "aapp_Old0000000000000002", "name": "Support-Bot", "url": "https://other.example.com/"}, // the same name
	} {
		org := &fakeOrg{confirm: true, apps: []map[string]any{existing}}
		r := createRegistry(org)
		out, isErr := callAs(t, r, "ascend", "ascend.app_create", `{`+chatArgs+`}`)
		if isErr || out["created"] != false || len(org.posted) != 0 || len(org.asked) != 0 ||
			!strings.Contains(fmtJSON(out["existing"]), existing["id"].(string)) {
			t.Fatalf("%v: %v (posted %v, asked %v)", existing["name"], out, org.posted, org.asked)
		}
		out, _ = callAs(t, r, "ascend", "ascend.app_create", `{`+chatArgs+`,"allow_duplicate":true}`)
		if out["created"] != true || len(org.asked) != 1 || !strings.Contains(org.asked[0], "already use this endpoint or name") {
			t.Fatalf("a duplicate on purpose is still confirmed, and says so: %v %q", out, org.asked)
		}
	}
}

func TestACredentialIsTypedHereNeverPassedByTheAgent(t *testing.T) {
	org := &fakeOrg{confirm: true}
	r := createRegistry(org)
	for _, bad := range []string{
		`{` + chatArgs + `,"headers":{"Authorization":"Bearer sk-live-123"}}`,
		`{` + chatArgs + `,"headers":{"x-api-key":"sk-live-123"}}`,
		`{` + chatArgs + `,"headers":{"Authorization":"Bearer {{API_KEY}}"}}`, // the key is used, so it must be asked for
		`{` + chatArgs + `,"api_key":"sk-live-123"}`,
	} {
		if out, isErr := callAs(t, r, "ascend", "ascend.app_create", bad); !isErr {
			t.Errorf("%s must be refused: %v", bad, out)
		}
	}
	if len(org.posted) != 0 {
		t.Fatal("nothing is created from a refused request")
	}
	org.key = "sk-typed-here"
	out, isErr := callAs(t, r, "ascend", "ascend.app_create", `{`+chatArgs+`,"headers":{"Authorization":"Bearer {{API_KEY}}"},"api_key":"ask"}`)
	if isErr || out["created"] != true || org.posted[0]["api_key"] != "sk-typed-here" || strings.Contains(fmtJSON(out), "sk-typed-here") {
		t.Fatalf("the typed key reaches Straiker, never the agent: %v", out)
	}
	org.key = ""
	if out, isErr := callAs(t, r, "ascend", "ascend.app_create", `{`+chatArgs+`,"api_key":"ask","allow_duplicate":true}`); !isErr || len(org.posted) != 1 {
		t.Fatalf("a cancelled key creates nothing: %v", out)
	}
}

func TestABadRequestIsRefused(t *testing.T) {
	r := createRegistry(&fakeOrg{confirm: true})
	for _, bad := range []string{
		`{"name":"x","endpoint":"ftp://x/y","request_template":{"m":"{{PROMPT}}"},"response_path":"reply"}`,
		`{"name":"x","endpoint":"https://user:pw@x.example/y","request_template":{"m":"{{PROMPT}}"},"response_path":"reply"}`,
		`{"name":"x","endpoint":"https://x.example/y","request_template":{"m":"hi"},"response_path":"reply"}`,
		`{"name":"x","endpoint":"https://x.example/y","request_template":{"m":"{{PROMPT}}"},"response_path":"choices.1.text"}`,
		`{"name":"","endpoint":"https://x.example/y","request_template":{"m":"{{PROMPT}}"},"response_path":"reply"}`,
		`{"name":"x","endpoint":"https://x.example/y","request_template":{"m":"{{PROMPT}}"},"response_path":"reply","controls":["nope"]}`,
	} {
		if out, isErr := callAs(t, r, "ascend", "ascend.app_create", bad); !isErr {
			t.Errorf("%s must be refused: %v", bad, out)
		}
	}
}

func TestCreatingNeedsAPersonAndIsNotTheBuilders(t *testing.T) {
	if _, ok := New(policy.Default(), Info{}, http.DefaultClient, nil, &fakePlatform{}).tools["ascend.app_create"]; ok {
		t.Fatal("without a person to confirm (a service host), ascend.app_create is not offered")
	}
	p := policy.Default()
	if p.Allowed("adaptor-builder", []string{"ascend.app_create"}, "ascend.app_create") {
		t.Fatal("the builder reads Ascend data but never creates applications")
	}
	if !p.Allowed("ascend", []string{"ascend.app_create"}, "ascend.app_create") || !p.Allowed("adaptor-builder", []string{"ascend.runs"}, "ascend.runs") {
		t.Fatal("Ascend Agent may create; the builder still reads")
	}
}

func fmtJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
