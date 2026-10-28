package packs

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/straiker-ai/ascend-tunnel/internal/agenthost/mcp"
	"github.com/straiker-ai/ascend-tunnel/internal/agenthost/policy"
)

func mustPolicy(t *testing.T, doc string) *policy.Policy {
	t.Helper()
	p, err := policy.Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func call(t *testing.T, r *Registry, name, args string) (map[string]any, bool) {
	t.Helper()
	res := r.Call(context.Background(), name, json.RawMessage(args))
	var out map[string]any
	if err := json.Unmarshal([]byte(res.Content[0].Text), &out); err != nil {
		t.Fatalf("%s: %v (%s)", name, err, res.Content[0].Text)
	}
	return out, res.IsError
}

func TestRegistryServesOnlyEnabledPacks(t *testing.T) {
	r := New(mustPolicy(t, "packs: [env]\n"), Info{Version: "t"}, http.DefaultClient, nil, nil)
	if got := strings.Join(r.Names(), ","); got != "env.info" {
		t.Fatal(got)
	}
	if res := r.Call(context.Background(), "http.probe", json.RawMessage(`{}`)); !res.IsError {
		t.Fatal("a tool of a disabled pack must not run")
	}
	all := New(mustPolicy(t, "packs: [env, net, http]\n"), Info{}, http.DefaultClient, nil, nil)
	if got := strings.Join(all.Names(), ","); got != "env.info,http.probe,net.check" {
		t.Fatal(got)
	}
	for _, tl := range all.List() {
		var s map[string]any
		if err := json.Unmarshal(tl.InputSchema, &s); err != nil || s["type"] != "object" || tl.Description == "" {
			t.Errorf("%s: schema %s", tl.Name, tl.InputSchema)
		}
	}
}

func TestEnvInfo(t *testing.T) {
	p := mustPolicy(t, "org: '7'\ntargets:\n  b: { url: https://b.corp }\n  a: { url: https://a.corp }\npacks: [env]\n")
	r := New(p, Info{Version: "1.2.3", HostID: "abcd1234", Org: "7", API: "https://api.example"}, http.DefaultClient, nil, nil)
	out, isErr := call(t, r, "env.info", `{}`)
	if isErr || out["host_version"] != "1.2.3" || out["host_id"] != "abcd1234" || out["policy_digest"] != p.Digest() {
		t.Fatal(out)
	}
	if ts := out["targets"].([]any); len(ts) != 2 || ts[0] != "a" {
		t.Fatal("targets are ids, sorted:", ts)
	}
	if strings.Contains(mustJSON(out), "a.corp") {
		t.Fatal("env.info must not reveal target URLs")
	}
	if _, isErr := call(t, r, "env.info", `{"extra":1}`); !isErr {
		t.Fatal("unknown arguments are refused")
	}
}

func TestHTTPProbe(t *testing.T) {
	var sawCookie, sawAuth bool
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("elsewhere")) }))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawCookie = sawCookie || r.Header.Get("Cookie") != ""
		sawAuth = sawAuth || r.Header.Get("Authorization") != ""
		switch r.URL.Path {
		case "/app/help":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Set-Cookie", "session=secret")
			w.Write([]byte("<html><head><title> Help \n Center </title></head><body>q=" + r.URL.RawQuery + "</body></html>"))
		case "/app/hop":
			http.Redirect(w, r, "/app/help", http.StatusFound)
		case "/app/away":
			http.Redirect(w, r, other.URL+"/x", http.StatusFound)
		case "/app/big":
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte(strings.Repeat("a", probeMaxBody+10)))
		case "/app/bin":
			w.Header().Set("Content-Type", "image/png")
			w.Write([]byte{0x89, 'P', 'N', 'G'})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	p := mustPolicy(t, "targets:\n  site: { url: '"+srv.URL+"/app/' }\npacks: [http]\n")
	r := New(p, Info{Version: "t"}, srv.Client(), nil, nil)

	out, isErr := call(t, r, "http.probe", `{"target":"site","path":"/help?lang=en"}`)
	if isErr || out["status"].(float64) != 200 || out["title"] != "Help Center" || !strings.Contains(out["body"].(string), "q=lang=en") {
		t.Fatal(out)
	}
	if strings.Contains(mustJSON(out), "secret") {
		t.Fatal("Set-Cookie must not be returned")
	}
	if out, _ := call(t, r, "http.probe", `{"target":"site","path":"/hop"}`); out["title"] != "Help Center" {
		t.Fatal("same-host redirect is followed:", out)
	}
	out, _ = call(t, r, "http.probe", `{"target":"site","path":"/away"}`)
	if out["status"].(float64) != 302 || !strings.Contains(out["redirect_not_followed"].(string), strings.TrimPrefix(other.URL, "http://")) {
		t.Fatal("cross-host redirect must stop:", out)
	}
	if out, _ := call(t, r, "http.probe", `{"target":"site","path":"/big"}`); out["truncated"] != true || out["bytes"].(float64) != probeMaxBody {
		t.Fatal("body is capped:", out["bytes"], out["truncated"])
	}
	if out, _ := call(t, r, "http.probe", `{"target":"site","path":"/bin"}`); out["body"] != nil || out["body_omitted"] == nil {
		t.Fatal("binary bodies are omitted")
	}
	for _, bad := range []string{
		`{"target":"nope"}`,
		`{"target":"site","path":"http://evil.example/"}`,
		`{"target":"site","path":"//evil.example/x"}`,
		`{"target":"site","path":"/a\\b"}`,
		`{"target":"site","url":"/"}`,
	} {
		if _, isErr := call(t, r, "http.probe", bad); !isErr {
			t.Errorf("%s: accepted", bad)
		}
	}
	if sawCookie || sawAuth {
		t.Fatal("http.probe must send no cookies or credentials")
	}
}

func TestJoinPathStaysUnderTarget(t *testing.T) {
	base, _ := url.Parse("https://h.corp:8443/app/")
	cases := map[string]string{
		"":                "https://h.corp:8443/app/",
		"/":               "https://h.corp:8443/app/",
		"/help":           "https://h.corp:8443/app/help",
		"help/":           "https://h.corp:8443/app/help/",
		"/../../etc/x":    "https://h.corp:8443/app/etc/x",
		"/a/./b/../c?q=1": "https://h.corp:8443/app/a/c?q=1",
		"/x#frag":         "https://h.corp:8443/app/x",
	}
	for in, want := range cases {
		u, err := joinPath(base, in)
		if err != nil || u.String() != want {
			t.Errorf("%q -> %v %v, want %s", in, u, err, want)
		}
	}
}

func TestNetCheck(t *testing.T) {
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	defer srv.Close()
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := ln.Addr().String()
	ln.Close()
	doc := "targets:\n  tls: { url: '" + srv.URL + "' }\n  down: { url: 'http://" + closed + "' }\npacks: [net]\n"

	r := New(mustPolicy(t, doc), Info{}, http.DefaultClient, nil, nil)
	out, isErr := call(t, r, "net.check", `{"target":"tls"}`)
	tlsOut := out["tls"].(map[string]any)
	if isErr || out["reachable"] != true || tlsOut["ok"] != true || tlsOut["verified"] != false || tlsOut["verify_error"] == nil {
		t.Fatal("a self-signed target is reachable, handshakes, and is reported unverified:", out)
	}
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	r = New(mustPolicy(t, doc), Info{}, http.DefaultClient, roots, nil)
	if out, _ := call(t, r, "net.check", `{"target":"tls"}`); out["tls"].(map[string]any)["verified"] != true {
		t.Fatal("with its CA trusted it verifies:", out)
	}
	if out, isErr := call(t, r, "net.check", `{"target":"down"}`); !isErr || out["reachable"] != false {
		t.Fatal("a closed port is unreachable:", out)
	}
	if _, isErr := call(t, r, "net.check", `{"target":"127.0.0.1:22"}`); !isErr {
		t.Fatal("a host:port that is not a policy target id is refused")
	}
}

func mustJSON(v any) string { b, _ := json.Marshal(v); return string(b) }

var _ mcp.Tools = (*Registry)(nil)
