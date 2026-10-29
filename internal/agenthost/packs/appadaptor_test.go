package packs

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/straiker-ai/ascend-tunnel/internal/agenthost/policy"
)

// fakeApp is one platform application, the person who confirms, and what Straiker keeps on a PATCH.
type fakeApp struct {
	fakeApprover
	record  map[string]any
	confirm bool
	asked   []string
	patched []map[string]any
	drop    bool // Straiker answers the PATCH but keeps nothing
}

func (f *fakeApp) PlatformGet(ctx context.Context, path string, q url.Values, out any) error {
	raw, _ := json.Marshal(f.record)
	return json.Unmarshal(raw, out)
}

func (f *fakeApp) PlatformPost(ctx context.Context, path string, body, out any) error { return nil }

func (f *fakeApp) PlatformPatch(ctx context.Context, path string, body, out any) error {
	b := body.(map[string]any)
	f.patched = append(f.patched, b)
	if !f.drop {
		f.record["request_template"] = b["request_template"]
	}
	return nil
}

func (f *fakeApp) Confirm(ctx context.Context, agent, question string) bool {
	f.asked = append(f.asked, agent+": "+question)
	return f.confirm
}

func (f *fakeApp) Secret(ctx context.Context, prompt string) (string, bool) { return "", false }

func newFakeApp(confirm bool) *fakeApp {
	return &fakeApp{confirm: confirm, record: map[string]any{"id": "aapp_37qqZZG17sgNg7e4uyUSSD", "name": "support-bot",
		"url": "https://chat.example.com/v1/chat", "request_template": `{"message":"{{PROMPT}}","channel":"web"}`}}
}

var adaptor = base64.StdEncoding.EncodeToString([]byte("async function turn(ctx){return ctx.prompt}"))

func adaptorArgs(name, value string) string {
	return `{"app":"aapp_37qqZZG17sgNg7e4uyUSSD","name":"` + name + `","adaptor":"` + value + `","summary":"keeps the session id"}`
}

func TestAnAdaptorIsStoredOnlyAfterThePersonConfirmsAndKeepsTheRestOfTheTemplate(t *testing.T) {
	f := newFakeApp(true)
	r := New(policy.Default(), Info{Org: "1"}, http.DefaultClient, nil, f)
	out, isErr := callAs(t, r, "ascend", "ascend.app_adaptor", adaptorArgs("support-bot", adaptor))
	if isErr || out["stored"] != true {
		t.Fatalf("store: %v", out)
	}
	if len(f.asked) != 1 || !strings.Contains(f.asked[0], `"support-bot"`) || !strings.Contains(f.asked[0], "in org 1") ||
		!strings.Contains(f.asked[0], "replacing nothing") || !strings.Contains(f.asked[0], "keeps the session id") {
		t.Fatalf("the person is asked, naming the app, org and what it replaces: %q", f.asked)
	}
	var tpl map[string]any
	_ = json.Unmarshal([]byte(f.record["request_template"].(string)), &tpl)
	if tpl["_adaptor_src"] != adaptor || tpl["message"] != "{{PROMPT}}" || tpl["channel"] != "web" {
		t.Fatalf("merged into the template: %v", tpl)
	}
}

func TestNothingIsStoredWhenThePersonSaysNoOrTheNameIsWrong(t *testing.T) {
	f := newFakeApp(false)
	r := New(policy.Default(), Info{Org: "1"}, http.DefaultClient, nil, f)
	if out, isErr := callAs(t, r, "ascend", "ascend.app_adaptor", adaptorArgs("support-bot", adaptor)); !isErr ||
		!strings.Contains(out["error"].(string), "did not confirm") {
		t.Fatalf("declined: %v", out)
	}
	f.confirm = true
	if out, isErr := callAs(t, r, "ascend", "ascend.app_adaptor", adaptorArgs("other-bot", adaptor)); !isErr ||
		!strings.Contains(out["error"].(string), `named "support-bot"`) {
		t.Fatalf("wrong name: %v", out)
	}
	if len(f.patched) != 0 || len(f.asked) != 1 {
		t.Fatalf("nothing written; a wrong name is refused before asking: %v %v", f.patched, f.asked)
	}
}

func TestAnAdaptorMustBeTheGatedValueOrAnAlias(t *testing.T) {
	f := newFakeApp(true)
	r := New(policy.Default(), Info{Org: "1"}, http.DefaultClient, nil, f)
	for _, v := range []string{"", "not base64!", "v0:../etc", strings.Repeat("A", maxAdaptorValue+4)} {
		if out, isErr := callAs(t, r, "ascend", "ascend.app_adaptor", adaptorArgs("support-bot", v)); !isErr {
			t.Fatalf("%.20q accepted: %v", v, out)
		}
	}
	if out, isErr := callAs(t, r, "ascend", "ascend.app_adaptor", adaptorArgs("support-bot", "v0:passthrough")); isErr || out["stored"] != true {
		t.Fatalf("alias: %v", out)
	}
}

func TestAStoreThatDoesNotLandIsReported(t *testing.T) {
	f := newFakeApp(true)
	f.drop = true
	r := New(policy.Default(), Info{Org: "1"}, http.DefaultClient, nil, f)
	if out, isErr := callAs(t, r, "ascend", "ascend.app_adaptor", adaptorArgs("support-bot", adaptor)); !isErr ||
		!strings.Contains(out["error"].(string), "did not keep") {
		t.Fatalf("dropped: %v", out)
	}
}

func TestTheBuilderCannotStoreAnAdaptor(t *testing.T) {
	p := policy.Default()
	if p.Allowed("adaptor-builder", p.Agents["adaptor-builder"], "ascend.app_adaptor") {
		t.Fatal("the builder proposes; only Ascend Agent stores, with the person's yes")
	}
}
