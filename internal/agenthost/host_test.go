package agenthost

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/straiker-ai/ascend-tunnel/internal/agenthost/mcp"
	"github.com/straiker-ai/ascend-tunnel/internal/agenthost/packs"
	"github.com/straiker-ai/ascend-tunnel/internal/agenthost/policy"
	"github.com/straiker-ai/ascend-tunnel/internal/agenthost/token"
	"github.com/straiker-ai/ascend-tunnel/internal/agenthost/wire"
)

const testPolicy = `
org: "1"
targets:
  site: { url: "https://site.corp" }
packs: [env, net]
agents:
  adaptor-builder: [env.*, net.check]
limits: { concurrent_calls: 2, calls_per_minute: %d }
`

type recorder struct {
	mu      sync.Mutex
	results []wire.Result
	events  []string
}

func (r *recorder) Post(_ context.Context, path string, body any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if path == wire.PathResults {
		r.results = append(r.results, body.(wire.Result))
	}
	return nil
}

func (r *recorder) Log(event string, kv ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, strings.TrimSpace(fmt.Sprintln(append([]any{event}, kv...)...)))
}

func (r *recorder) waitResults(t *testing.T, n int) []wire.Result {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		r.mu.Lock()
		if len(r.results) >= n {
			out := append([]wire.Result(nil), r.results...)
			r.mu.Unlock()
			return out
		}
		r.mu.Unlock()
	}
	t.Fatalf("waited for %d results", n)
	return nil
}

func (r *recorder) audit() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return strings.Join(r.events, "\n")
}

// slowTools wraps real tools and adds one that blocks until cancelled, counting runs.
type slowTools struct {
	mcp.Tools
	runs    atomic.Int32
	started chan struct{}
}

func (s *slowTools) List() []mcp.Tool {
	return append(s.Tools.List(), mcp.Tool{Name: "net.wait", Description: "d", InputSchema: json.RawMessage(`{"type":"object"}`)})
}

func (s *slowTools) Call(ctx context.Context, name string, args json.RawMessage) mcp.Result {
	s.runs.Add(1)
	if name == "net.wait" {
		s.started <- struct{}{}
		<-ctx.Done()
		return mcp.TextResult("stopped", true)
	}
	return s.Tools.Call(ctx, name, args)
}

type harness struct {
	host  *Host
	rec   *recorder
	tools *slowTools
	priv  ed25519.PrivateKey
}

func newHarness(t *testing.T, perMinute int) *harness {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	p, err := policy.Parse([]byte(fmt.Sprintf(testPolicy, perMinute)))
	if err != nil {
		t.Fatal(err)
	}
	tools := &slowTools{Tools: packs.New(p, packs.Info{Version: "t", HostID: "abcd1234", Org: "1"}, http.DefaultClient, nil, nil), started: make(chan struct{}, 4)}
	rec := &recorder{}
	e := New(Config{Policy: p, Tools: tools, HostID: "abcd1234", Org: "1", SessionKeys: []ed25519.PublicKey{pub},
		Info: mcp.ServerInfo{Name: "ascend-agent", Version: "t"}, API: rec, Audit: rec})
	return &harness{host: e, rec: rec, tools: tools, priv: priv}
}

// jwt mints a session token bound to one call, as the broker does.
func (h *harness) jwt(t *testing.T, sid, callID, msg string, grants ...string) string {
	t.Helper()
	digest, err := token.MessageDigest([]byte(msg))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tok, err := token.MintSession(h.priv, token.Session{
		Issuer: token.SessionIssuer, Audience: "host:abcd1234", Tenant: "1", SID: sid,
		Agent: "adaptor-builder", Grants: grants, CallID: callID, MsgSHA256: digest,
		IssuedAt: now.Unix(), Expiry: now.Add(10 * time.Minute).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// call sends one message with a token bound to it.
func (h *harness) call(t *testing.T, sid, callID, msg string, grants ...string) {
	t.Helper()
	h.send(sid, callID, h.jwt(t, sid, callID, msg, grants...), msg)
}

func (h *harness) send(sid, callID, jwt, message string) {
	data, _ := json.Marshal(wire.Envelope{SID: sid, CallID: callID, SessionJWT: jwt, Message: json.RawMessage(message)})
	h.host.Handle(context.Background(), wire.Event{ID: callID, Event: wire.EventCall, Data: data})
}

func reply(t *testing.T, r wire.Result) mcp.Message {
	t.Helper()
	var m mcp.Message
	if err := json.Unmarshal(r.Message, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestListIsGrantIntersectPolicy(t *testing.T) {
	h := newHarness(t, 100)
	h.call(t, "s1", "c1", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, "env.info")
	m := reply(t, h.rec.waitResults(t, 1)[0])
	if !strings.Contains(string(m.Result), "env.info") || strings.Contains(string(m.Result), "net.check") {
		t.Fatal("only granted AND allowed tools are listed:", string(m.Result))
	}
	// A re-minted token with wider grants widens the same session, up to the policy.
	h.call(t, "s1", "c2", `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`, "env.info", "net.*")
	m = reply(t, h.rec.waitResults(t, 2)[1])
	if !strings.Contains(string(m.Result), "net.check") || strings.Contains(string(m.Result), "net.wait") {
		t.Fatal("net.check is granted and allowed; net.wait is granted but not in the policy:", string(m.Result))
	}
}

func TestCallIsServedAndAudited(t *testing.T) {
	h := newHarness(t, 100)
	h.call(t, "s1", "c1", `{"jsonrpc":"2.0","id":"x","method":"tools/call","params":{"name":"env.info","arguments":{}}}`, "env.info")
	r := h.rec.waitResults(t, 1)[0]
	m := reply(t, r)
	if r.SID != "s1" || r.CallID != "c1" || string(m.ID) != `"x"` || !strings.Contains(string(m.Result), "abcd1234") {
		t.Fatalf("%+v %s", r, m.Result)
	}
	a := h.rec.audit()
	if !strings.Contains(a, "host.session sid s1 agent adaptor-builder") || !strings.Contains(a, "tool env.info args_sha256") || !strings.Contains(a, "outcome ok") {
		t.Fatal(a)
	}
}

func TestForgedOrMisdirectedCallsAreRefused(t *testing.T) {
	h := newHarness(t, 100)
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	msg := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"env.info"}}`
	other := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"net.check","arguments":{"target":"site"}}}`
	forged := func(callID string) string {
		d, _ := token.MessageDigest([]byte(msg))
		tok, _ := token.MintSession(otherPriv, token.Session{Issuer: "straiker", Audience: "host:abcd1234", Tenant: "1", SID: "s1",
			Agent: "adaptor-builder", Grants: []string{"env.*"}, CallID: callID, MsgSHA256: d,
			IssuedAt: time.Now().Unix(), Expiry: time.Now().Add(time.Minute).Unix()})
		return tok
	}
	cases := []struct {
		name string
		jwt  func(callID string) string
	}{
		{"forged", forged},
		{"other session", func(c string) string { return h.jwt(t, "s2", c, msg, "env.*") }},
		{"token for another call", func(string) string { return h.jwt(t, "s1", "c-other", msg, "env.*") }},
		{"token for another message", func(c string) string { return h.jwt(t, "s1", c, other, "env.*", "net.*") }},
		{"none", func(string) string { return "" }},
	}
	for i, c := range cases {
		callID := fmt.Sprint("c", i+1)
		h.send("s1", callID, c.jwt(callID), msg)
		m := reply(t, h.rec.waitResults(t, i+1)[i])
		if m.Error == nil || m.Error.Code != ErrSessionRejected {
			t.Errorf("%s: %s", c.name, m.Result)
		}
	}
	if h.tools.runs.Load() != 0 {
		t.Fatal("no tool may run for a refused call")
	}
	if !strings.Contains(h.rec.audit(), "outcome rejected") {
		t.Fatal(h.rec.audit())
	}
}

func TestRedeliveryRunsOnce(t *testing.T) {
	h := newHarness(t, 100)
	msg := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"env.info"}}`
	jwt := h.jwt(t, "s1", "c1", msg, "env.info")
	h.send("s1", "c1", jwt, msg)
	first := h.rec.waitResults(t, 1)[0]
	h.send("s1", "c1", jwt, msg)
	second := h.rec.waitResults(t, 2)[1]
	if h.tools.runs.Load() != 1 || string(first.Message) != string(second.Message) {
		t.Fatalf("a redelivered call_id must re-post the same answer without running again (runs=%d)", h.tools.runs.Load())
	}
}

func TestRateLimit(t *testing.T) {
	h := newHarness(t, 1)
	h.call(t, "s1", "c1", `{"jsonrpc":"2.0","id":1,"method":"ping"}`, "env.info")
	h.rec.waitResults(t, 1)
	h.call(t, "s1", "c2", `{"jsonrpc":"2.0","method":"notifications/initialized"}`, "env.info")
	h.call(t, "s1", "c3", `{"jsonrpc":"2.0","id":3,"method":"ping"}`, "env.info")
	m := reply(t, h.rec.waitResults(t, 2)[1])
	if m.Error == nil || m.Error.Code != ErrRateLimited || string(m.ID) != "3" {
		t.Fatalf("over calls_per_minute is refused (notifications do not count): %+v", m)
	}
}

func TestCloseCancelsInFlight(t *testing.T) {
	h := newHarness(t, 100)
	p, _ := policy.Parse([]byte(strings.Replace(fmt.Sprintf(testPolicy, 100), "net.check", "net.*", 1)))
	h.host.cfg.Policy = p
	h.call(t, "s1", "c1", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"net.wait"}}`, "net.*")
	<-h.tools.started
	data, _ := json.Marshal(wire.Close{SID: "s1"})
	h.host.Handle(context.Background(), wire.Event{Event: wire.EventClose, Data: data})
	m := reply(t, h.rec.waitResults(t, 1)[0])
	if !strings.Contains(string(m.Result), "stopped") {
		t.Fatal("closing the session must cancel its calls:", string(m.Result))
	}
}

func TestBadEventsAreAuditedNotServed(t *testing.T) {
	h := newHarness(t, 100)
	h.host.Handle(context.Background(), wire.Event{Event: wire.EventCall, Data: json.RawMessage(`{"sid":"s1"}`)})
	h.host.Handle(context.Background(), wire.Event{Event: "surprise"})
	h.host.Handle(context.Background(), wire.Event{Event: wire.EventPing})
	a := h.rec.audit()
	if !strings.Contains(a, "host.bad_event") || !strings.Contains(a, "host.unknown_event event surprise") {
		t.Fatal(a)
	}
}

func TestSweepForgetsIdleSessions(t *testing.T) {
	h := newHarness(t, 100)
	now := time.Now()
	h.host.cfg.Now = func() time.Time { return now }
	h.call(t, "s1", "c1", `{"jsonrpc":"2.0","id":1,"method":"ping"}`, "env.info")
	h.rec.waitResults(t, 1)
	now = now.Add(sessionIdle + dedupeTTL + time.Minute)
	h.host.Sweep()
	h.host.mu.Lock()
	defer h.host.mu.Unlock()
	if len(h.host.sessions) != 0 || len(h.host.seen) != 0 {
		t.Fatalf("sessions %d seen %d", len(h.host.sessions), len(h.host.seen))
	}
}

func TestBucket(t *testing.T) {
	now := time.Unix(0, 0)
	b := newBucket(2, func() time.Time { return now })
	if !b.take() || !b.take() || b.take() {
		t.Fatal("burst up to the per-minute cap")
	}
	now = now.Add(30 * time.Second)
	if !b.take() || b.take() {
		t.Fatal("refills continuously")
	}
}
