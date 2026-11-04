package packs

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"syscall"
	"testing"

	"github.com/straiker-ai/ascend-tunnel/internal/agenthost/policy"
)

type fakeApprover struct {
	answer bool
	asked  []string
}

func (f *fakeApprover) Approve(ctx context.Context, agent, tool string, u *url.URL) bool {
	f.asked = append(f.asked, fmt.Sprintf("%s %s %s", agent, tool, u.Hostname()))
	return f.answer
}

func callAs(t *testing.T, r *Registry, agent, name, args string) (map[string]any, bool) {
	t.Helper()
	res := r.Call(WithAgent(context.Background(), agent), name, json.RawMessage(args))
	var out map[string]any
	if err := json.Unmarshal([]byte(res.Content[0].Text), &out); err != nil {
		t.Fatalf("%s: %v (%s)", name, err, res.Content[0].Text)
	}
	return out, res.IsError
}

func page(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<title>Help</title>")
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestAPersonApprovesSitesBeyondTheTargets(t *testing.T) {
	srv := page(t)
	ap := &fakeApprover{answer: true}
	r := New(policy.Default(), Info{}, http.DefaultClient, nil, ap)
	out, isErr := callAs(t, r, "adaptor-builder", "http.probe", `{"url":"`+srv.URL+`/help"}`)
	if isErr || out["title"] != "Help" {
		t.Fatalf("approved: %v %v", out, isErr)
	}
	if len(ap.asked) != 1 || ap.asked[0] != "adaptor-builder http.probe 127.0.0.1" {
		t.Fatalf("asked: %v", ap.asked)
	}
	ap.answer = false
	out, isErr = callAs(t, r, "adaptor-builder", "net.check", `{"url":"`+srv.URL+`"}`)
	if !isErr || !strings.Contains(out["error"].(string), "did not approve") {
		t.Fatalf("declined: %v", out)
	}
	if info, _ := callAs(t, r, "", "env.info", `{}`); info["approvals"] != true {
		t.Fatalf("env.info must say approvals are possible: %v", info)
	}
}

func TestATargetsURLNeedsNoApproval(t *testing.T) {
	srv := page(t)
	ap := &fakeApprover{}
	pol := mustPolicy(t, "targets:\n  site: { url: '"+srv.URL+"/' }\npacks: [env, net, http]\ninteractive:\n  allow_hosts: ['*.example.com']\n")
	r := New(pol, Info{}, http.DefaultClient, nil, ap)
	out, isErr := callAs(t, r, "a", "http.probe", `{"url":"`+srv.URL+`/help"}`)
	if isErr || out["target"] != "site" || len(ap.asked) != 0 {
		t.Fatalf("a url under a target is that target: %v %v asked=%v", out, isErr, ap.asked)
	}
}

func TestAPolicyFileCapsApprovals(t *testing.T) {
	srv := page(t)
	ap := &fakeApprover{answer: true}
	noCap := mustPolicy(t, "packs: [env, net, http]\n")
	r := New(noCap, Info{}, http.DefaultClient, nil, ap)
	if out, isErr := callAs(t, r, "a", "http.probe", `{"url":"`+srv.URL+`"}`); !isErr || !strings.Contains(out["error"].(string), "only its policy's targets") {
		t.Fatalf("a policy file without interactive allows no approvals: %v", out)
	}
	if info, _ := callAs(t, r, "", "env.info", `{}`); info["approvals"] != false {
		t.Fatalf("env.info: %v", info)
	}
	capped := mustPolicy(t, "packs: [env, net, http]\ninteractive:\n  allow_hosts: ['*.example.com']\n")
	r = New(capped, Info{}, http.DefaultClient, nil, ap)
	if out, isErr := callAs(t, r, "a", "http.probe", `{"url":"`+srv.URL+`"}`); !isErr || !strings.Contains(out["error"].(string), "does not let a person approve 127.0.0.1") {
		t.Fatalf("outside the cap: %v", out)
	}
	if len(ap.asked) != 0 {
		t.Fatalf("nobody is asked about a site the policy forbids: %v", ap.asked)
	}
}

func TestMetadataIsNeverReachable(t *testing.T) {
	ap := &fakeApprover{answer: true}
	r := New(policy.Default(), Info{}, http.DefaultClient, nil, ap)
	for _, u := range []string{"http://169.254.169.254/latest/meta-data/", "http://metadata.google.internal/", "http://[fe80::1]/"} {
		if out, isErr := callAs(t, r, "a", "http.probe", `{"url":"`+u+`"}`); !isErr || !strings.Contains(out["error"].(string), "never reachable") {
			t.Errorf("%s: %v", u, out)
		}
	}
	if len(ap.asked) != 0 {
		t.Fatalf("blocked addresses are refused before anyone is asked: %v", ap.asked)
	}
	var raw syscall.RawConn
	if guard("tcp4", "169.254.169.254:80", raw) == nil || guard("tcp4", "10.0.0.1:443", raw) != nil {
		t.Fatal("the dialer refuses link-local addresses after DNS, and only those")
	}
}

func TestAServiceTakesNoURLs(t *testing.T) {
	r := New(policy.Default(), Info{}, http.DefaultClient, nil, nil)
	if out, isErr := callAs(t, r, "a", "http.probe", `{"url":"https://example.com"}`); !isErr || !strings.Contains(out["error"].(string), "only its policy's targets") {
		t.Fatalf("no approver: %v", out)
	}
	for _, tl := range r.List() {
		if strings.Contains(string(tl.InputSchema), `"url"`) {
			t.Errorf("%s offers url without an approver: %s", tl.Name, tl.InputSchema)
		}
	}
}

type fakeCapturer struct {
	fakeApprover
	opened []string
}

func (f *fakeCapturer) Capture(ctx context.Context, agent string, u *url.URL, appID, instructions string) (map[string]any, error) {
	f.opened = append(f.opened, agent+" "+u.String()+" "+appID+" "+instructions)
	return map[string]any{"recording": true}, nil
}

func TestABrowserCaptureNeedsAPersonAndTheirApproval(t *testing.T) {
	c := &fakeCapturer{fakeApprover: fakeApprover{answer: true}}
	r := New(policy.Default(), Info{}, http.DefaultClient, nil, c)
	out, isErr := callAs(t, r, "adaptor-builder", "browser.capture",
		`{"url":"https://www.example.com/","app_id":"00000000-0000-7000-8000-000000000001","instructions":"open the chat"}`)
	if isErr || out["recording"] != true || len(c.opened) != 1 || len(c.asked) != 1 {
		t.Fatalf("capture: %v opened=%v asked=%v", out, c.opened, c.asked)
	}
	c.answer = false
	if out, isErr := callAs(t, r, "a", "browser.capture", `{"url":"https://other.example/"}`); !isErr || !strings.Contains(out["error"].(string), "did not approve") {
		t.Fatalf("declined: %v", out)
	}
	if out, isErr := callAs(t, r, "a", "browser.capture", `{"url":"https://www.example.com/","app_id":"nope"}`); !isErr || !strings.Contains(out["error"].(string), "uuid") {
		t.Fatalf("bad app id: %v", out)
	}
	plain := New(policy.Default(), Info{}, http.DefaultClient, nil, &fakeApprover{answer: true})
	if strings.Contains(strings.Join(plain.Names(), ","), "browser.capture") {
		t.Fatal("no capturer, no browser tool")
	}
	if strings.Contains(strings.Join(New(policy.Default(), Info{}, http.DefaultClient, nil, nil).Names(), ","), "browser") {
		t.Fatal("a service has no person to drive a browser")
	}
}

type fakePlatform struct {
	fakeApprover
	paths []string
}

func (f *fakePlatform) PlatformGet(ctx context.Context, path string, q url.Values, out any) error {
	f.paths = append(f.paths, path+"?"+q.Encode())
	var body string
	switch {
	case strings.HasSuffix(path, "/applications"):
		body = `{"data":[{"id":"aapp_TestApp0000000000001","name":"support-bot","url":"https://chat.example.com/chat","headers":"secret"}],"has_more":false}`
	case strings.HasSuffix(path, "/assessments"):
		body = `{"data":[{"id":"asmt_TestRun0000000000001","status":"complete","score":40,"total":200,"failed":120,"summary":"long","category_summary":[{"id":"app_grounding","name":"Application Grounding","failed":141,"total":270,"keyfindings":["x"],"controls":[{"id":"science","failed":10,"total":12}]}]}],"has_more":true}`
	default:
		body = `{"id":"asmt_TestRun0000000000001","summary":"words","recommendations":[{"title":"Improve system prompt","description":"long"}],"category_summary":[{"id":"app_grounding","controls":[{"id":"science","failed":10,"total":12,"keyfindings":["x"]}]}]}`
	}
	return json.Unmarshal([]byte(body), out)
}

func (f *fakePlatform) PlatformPost(ctx context.Context, path string, body, out any) error {
	f.paths = append(f.paths, "POST "+path)
	return json.Unmarshal([]byte(`{}`), out)
}

func TestAscendReadsAreFixedAndTrimmed(t *testing.T) {
	pl := &fakePlatform{}
	r := New(policy.Default(), Info{}, http.DefaultClient, nil, pl)
	apps, isErr := callAs(t, r, "a", "ascend.apps", `{}`)
	if isErr || strings.Contains(fmt.Sprint(apps), "secret") || !strings.Contains(fmt.Sprint(apps), "chat.example.com") {
		t.Fatalf("apps: %v", apps)
	}
	runs, isErr := callAs(t, r, "a", "ascend.runs", `{"app":"aapp_TestApp0000000000001","limit":5}`)
	if isErr || runs["has_more"] != true || strings.Contains(fmt.Sprint(runs), "keyfindings") || strings.Contains(fmt.Sprint(runs), "controls") {
		t.Fatalf("runs: %v", runs)
	}
	one, _ := callAs(t, r, "a", "ascend.run", `{"app":"aapp_TestApp0000000000001","run":"asmt_TestRun0000000000001"}`)
	if fmt.Sprint(one["recommendations"]) != "[Improve system prompt]" || !strings.Contains(fmt.Sprint(one), "science") {
		t.Fatalf("run: %v", one)
	}
	for _, bad := range []string{`{"app":"../../admin"}`, `{"app":"aapp_TestApp0000000000001/../x"}`, `{"app":"aapp_TestApp0000000000001","starting_after":"x?y"}`} {
		if out, isErr := callAs(t, r, "a", "ascend.runs", bad); !isErr {
			t.Errorf("%s must be refused: %v", bad, out)
		}
	}
	want := []string{"/api/v3/ascend/applications?limit=100", "/api/v3/ascend/applications/aapp_TestApp0000000000001/assessments?limit=5",
		"/api/v3/ascend/applications/aapp_TestApp0000000000001/assessments/asmt_TestRun0000000000001?"}
	if strings.Join(pl.paths, " ") != strings.Join(want, " ") {
		t.Fatalf("paths: %v", pl.paths)
	}
}
