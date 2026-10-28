package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/straiker-ai/ascend-tunnel/internal/agenthost/token"
	"github.com/straiker-ai/ascend-tunnel/internal/agenthost/wire"
	"github.com/straiker-ai/ascend-tunnel/internal/identity"
)

func writePolicy(t *testing.T, doc string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "host.yaml")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func runCmd(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(context.Background(), args, strings.NewReader(stdin), &out, &errb)
	return code, out.String(), errb.String()
}

func TestHelpVersionUnknown(t *testing.T) {
	if code, out, _ := runCmd(t, "", "help"); code != 0 || !strings.Contains(out, "ascend-agent run") {
		t.Fatal("help prints the commands")
	}
	t.Setenv("ASCEND_AGENT_HOME", t.TempDir())
	t.Setenv("STRAIKER_API_KEY", "")
	if code, out, errs := runCmd(t, ""); code != 2 || !strings.Contains(out, "Sign in to Straiker first") || !strings.Contains(errs, "no token read") {
		t.Fatalf("no arguments opens chat, which signs in first: %d %q %q", code, out, errs)
	}
	if code, out, _ := runCmd(t, "", "version"); code != 0 || !strings.Contains(out, "protocol "+wire.Version) {
		t.Fatal(out)
	}
	if code, _, _ := runCmd(t, "", "launch"); code != 2 {
		t.Fatal("unknown command exits 2")
	}
	if code, _, errs := runCmd(t, "", "run", "-policy", filepath.Join(t.TempDir(), "missing.yaml")); code != 2 || !strings.Contains(errs, "missing.yaml") {
		t.Fatal(errs)
	}
}

func TestPolicyCheckAndShow(t *testing.T) {
	path := writePolicy(t, "targets:\n  site: { url: 'https://site.corp' }\npacks: [env, http]\nagents:\n  recon: [http.probe]\n")
	code, out, _ := runCmd(t, "", "policy", "check", "-policy", path)
	if code != 0 || !strings.Contains(out, "ok: ") || !strings.Contains(out, "warning: no org") || !strings.Contains(out, "warning: no session_key") {
		t.Fatal(out)
	}
	code, out, _ = runCmd(t, "", "policy", "show", "-policy", path)
	if code != 0 || !strings.Contains(out, "site                 https://site.corp") || !strings.Contains(out, "recon                http.probe") {
		t.Fatal(out)
	}
	if code, _, _ := runCmd(t, "", "policy", "check", "-policy", writePolicy(t, "packs: [shell]\n")); code != 1 {
		t.Fatal("a bad policy fails the check")
	}
	if code, _, _ := runCmd(t, "", "policy", "check", "-policy", writePolicy(t, "session_key: nope\n")); code != 1 {
		t.Fatal("an unparsable session key fails the check")
	}
	if code, _, _ := runCmd(t, "", "policy"); code != 2 {
		t.Fatal("policy needs check or show")
	}
}

func TestRunRefusesUnsafeSettings(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	key := base64.StdEncoding.EncodeToString(pub)
	cases := map[string]string{
		"no org":         "session_key: " + key + "\npacks: [env]\n",
		"no session key": "org: '1'\npacks: [env]\n",
		"plain http":     "org: '1'\nsession_key: " + key + "\napi: http://api.example.com/agent\n",
		"unknown env":    "org: '1'\nsession_key: " + key + "\nenv: moon\n",
	}
	for name, doc := range cases {
		if code, _, errs := runCmd(t, "", "run", "-policy", writePolicy(t, doc), "-state-dir", t.TempDir()); code != 2 {
			t.Errorf("%s: exit %d %s", name, code, errs)
		}
	}
}

func TestKeyIsTheTunnelKey(t *testing.T) {
	dir := t.TempDir()
	id, err := identity.Load("", dir) // what ascend-tunnel would create
	if err != nil {
		t.Fatal(err)
	}
	code, out, errs := runCmd(t, "", "key", "-state-dir", dir)
	if code != 0 || strings.TrimSpace(out) != identity.PasteForm(id.PublicKey) || !strings.Contains(errs, id.AgentID) {
		t.Fatal(out, errs)
	}
}

func TestServeStdio(t *testing.T) {
	path := writePolicy(t, "targets:\n  site: { url: 'https://site.corp' }\npacks: [env]\n")
	in := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`not json`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"env.info","arguments":{}}}`,
	}, "\n") + "\n"
	code, out, errs := runCmd(t, in, "serve", "-stdio", "-policy", path, "-audit-log", filepath.Join(t.TempDir(), "a.jsonl"))
	if code != 0 {
		t.Fatal(errs)
	}
	byID := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		var m struct {
			ID    json.RawMessage `json:"id"`
			Error *struct{ Code int }
		}
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("stdout must be only protocol: %q", line)
		}
		byID[string(m.ID)] = line
	}
	if len(byID) != 4 || !strings.Contains(byID["1"], `"protocolVersion":"2025-06-18"`) || !strings.Contains(byID["2"], "env.info") ||
		!strings.Contains(byID["3"], `"targets":["site"]`) || !strings.Contains(byID["null"], "-32700") {
		t.Fatal(byID)
	}
	if code, _, _ := runCmd(t, "", "serve", "-policy", path); code != 2 {
		t.Fatal("serve without -stdio is refused")
	}
}

// fakeAPI is a stand-in for Straiker's agent API: it streams one call and records what comes back.
type fakeAPI struct {
	t       *testing.T
	hostPub ed25519.PublicKey
	sess    ed25519.PrivateKey
	agentID string

	mu      sync.Mutex
	results []wire.Result
	hellos  []wire.Hello
	authErr string
}

func (f *fakeAPI) checkAuth(r *http.Request) {
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	parts := strings.Split(tok, ".")
	ok := len(parts) == 3
	if ok {
		sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
		ok = ed25519.Verify(f.hostPub, []byte(parts[0]+"."+parts[1]), sig)
	}
	var c token.HostClaims
	if ok {
		raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
		ok = json.Unmarshal(raw, &c) == nil && c.Subject == f.agentID && c.Tenant == "1" && c.Audience == token.HostAudience
	}
	if !ok {
		f.mu.Lock()
		f.authErr = "host token did not verify with the machine key"
		f.mu.Unlock()
	}
}

func (f *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.checkAuth(r)
	switch r.URL.Path {
	case "/agent/stream":
		now := time.Now()
		msg := json.RawMessage(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"env.info","arguments":{}}}`)
		digest, _ := token.MessageDigest(msg)
		jwt, _ := token.MintSession(f.sess, token.Session{Issuer: "straiker", Audience: "host:" + f.agentID, Tenant: "1", SID: "s1",
			Agent: "adaptor-builder", Grants: []string{"env.info"}, CallID: "c1", MsgSHA256: digest,
			IssuedAt: now.Unix(), Expiry: now.Add(5 * time.Minute).Unix()})
		env, _ := json.Marshal(wire.Envelope{SID: "s1", CallID: "c1", SessionJWT: jwt, Message: msg})
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprintf(w, ": hello\n\nid: 1\nevent: call\ndata: %s\n\n", env)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	case "/agent/results":
		var res wire.Result
		_ = json.NewDecoder(r.Body).Decode(&res)
		f.mu.Lock()
		f.results = append(f.results, res)
		f.mu.Unlock()
		w.WriteHeader(204)
	case "/agent/hello":
		var h wire.Hello
		_ = json.NewDecoder(r.Body).Decode(&h)
		f.mu.Lock()
		f.hellos = append(f.hellos, h)
		f.mu.Unlock()
		w.WriteHeader(204)
	default:
		http.NotFound(w, r)
	}
}

func TestRunEndToEnd(t *testing.T) {
	stateDir := t.TempDir()
	id, err := identity.Load("1", stateDir)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(id.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	sessPub, sessPriv, _ := ed25519.GenerateKey(rand.Reader)
	api := &fakeAPI{t: t, hostPub: sshPub.(ssh.CryptoPublicKey).CryptoPublicKey().(ed25519.PublicKey), sess: sessPriv, agentID: id.AgentID}
	srv := httptest.NewServer(api)
	defer srv.Close()

	audit := filepath.Join(t.TempDir(), "ascend-agent-audit.jsonl")
	path := writePolicy(t, fmt.Sprintf("org: '1'\napi: %s/agent\nsession_key: %s\ntargets:\n  site: { url: 'https://site.corp' }\npacks: [env]\nagents:\n  adaptor-builder: [env.info]\n",
		srv.URL, base64.StdEncoding.EncodeToString(sessPub)))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int)
	var out, errb bytes.Buffer
	go func() {
		done <- run(ctx, []string{"run", "-policy", path, "-state-dir", stateDir, "-audit-log", audit}, nil, &out, &errb)
	}()

	deadline := time.Now().Add(10 * time.Second)
	for {
		api.mu.Lock()
		n, h := len(api.results), len(api.hellos)
		api.mu.Unlock()
		if n > 0 && h > 0 {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("no result/hello; stderr %s", errb.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	if code := <-done; code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}

	api.mu.Lock()
	defer api.mu.Unlock()
	if api.authErr != "" {
		t.Fatal(api.authErr)
	}
	r := api.results[0]
	if r.SID != "s1" || r.CallID != "c1" || !strings.Contains(string(r.Message), id.AgentID) {
		t.Fatalf("result %+v %s", r, r.Message)
	}
	if h := api.hellos[0]; h.HostID != id.AgentID || h.Org != "1" || len(h.Tools) != 1 || h.Tools[0] != "env.info" || h.Protocol != wire.Version {
		t.Fatalf("hello %+v", h)
	}
	logged, _ := os.ReadFile(audit)
	for _, want := range []string{`"event":"host.start"`, `"event":"host.connected"`, `"event":"host.call"`, `"tool":"env.info"`, `"outcome":"ok"`} {
		if !strings.Contains(string(logged), want) {
			t.Errorf("audit log lacks %s:\n%s", want, logged)
		}
	}
}
