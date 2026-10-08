package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/crypto/ssh"

	"github.com/straiker-ai/ascend-tunnel/internal/config"
	"github.com/straiker-ai/ascend-tunnel/internal/identity"
)

// testRelay is a stand-in for Straiker's relay: TLS, a WebSocket carrying SSH, publickey logins for
// listed keys only, and unix-socket remote forwards it can open connections through.
type testRelay struct {
	srv     *httptest.Server
	hostKey ssh.Signer

	mu       sync.Mutex
	listed   map[string]bool
	sockets  map[string]*ssh.ServerConn
	users    []string
	upgrades int
}

func newTestRelay(t *testing.T) *testRelay {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	r := &testRelay{hostKey: signer, listed: map[string]bool{}, sockets: map[string]*ssh.ServerConn{}}
	r.srv = httptest.NewTLSServer(http.HandlerFunc(r.handle))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *testRelay) url() string { return "wss://" + r.srv.Listener.Addr().String() + "/tunnel" }

func (r *testRelay) hostKeyLine() string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(r.hostKey.PublicKey())))
}

func (r *testRelay) list(pub ssh.PublicKey) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.listed[string(pub.Marshal())] = true
}

func (r *testRelay) handle(w http.ResponseWriter, req *http.Request) {
	ws, err := websocket.Accept(w, req, nil)
	if err != nil {
		return
	}
	ws.SetReadLimit(64 << 20)
	r.mu.Lock()
	r.upgrades++
	r.mu.Unlock()
	conn := websocket.NetConn(context.Background(), ws, websocket.MessageBinary)
	defer conn.Close()
	conf := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.listed[string(k.Marshal())] {
			return nil, nil
		}
		return nil, errors.New("no app lists this key")
	}}
	conf.AddHostKey(r.hostKey)
	sc, chans, reqs, err := ssh.NewServerConn(conn, conf)
	if err != nil {
		return
	}
	r.mu.Lock()
	r.users = append(r.users, sc.User())
	r.mu.Unlock()
	go func() {
		for ch := range chans {
			_ = ch.Reject(ssh.Prohibited, "no session channels")
		}
	}()
	for q := range reqs {
		if q.Type != "streamlocal-forward@openssh.com" {
			_ = q.Reply(false, nil)
			continue
		}
		var p struct{ SocketPath string }
		if err := ssh.Unmarshal(q.Payload, &p); err != nil {
			_ = q.Reply(false, nil)
			continue
		}
		r.mu.Lock()
		r.sockets[p.SocketPath] = sc
		r.mu.Unlock()
		_ = q.Reply(true, nil)
	}
}

// waitSocket waits for the agent to bind path, then opens a connection through it, as Envoy would.
func (r *testRelay) open(t *testing.T, path string) ssh.Channel {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		r.mu.Lock()
		sc := r.sockets[path]
		r.mu.Unlock()
		if sc != nil {
			ch, reqs, err := sc.OpenChannel("forwarded-streamlocal@openssh.com",
				ssh.Marshal(struct{ SocketPath, Reserved string }{path, ""}))
			if err != nil {
				t.Fatal(err)
			}
			go ssh.DiscardRequests(reqs)
			return ch
		}
		if time.Now().After(deadline) {
			t.Fatalf("the agent never bound %s", path)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// echoTarget is a customer app: it echoes until the client half-closes.
func echoTarget(t *testing.T) config.Forward {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return config.Forward{Host: "127.0.0.1", Port: ln.Addr().(*net.TCPAddr).Port}
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *syncBuffer) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func (s *syncBuffer) events(t *testing.T) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(s.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("audit line is not JSON: %q", line)
		}
		out = append(out, m)
	}
	return out
}

func newAgent(t *testing.T, r *testRelay, forwards []config.Forward, fanout int) (*Agent, *syncBuffer) {
	t.Helper()
	dir := t.TempDir()
	ca := filepath.Join(dir, "relay-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: r.srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	id, err := identity.Load("1234", filepath.Join(dir, "state"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Tenant: "1234", Relay: r.url(), HostKey: r.hostKeyLine(), CAFile: ca,
		Fanout: fanout, Forwards: forwards}
	buf := &syncBuffer{}
	a, err := New(cfg, id, NewAudit("", buf))
	if err != nil {
		t.Fatal(err)
	}
	return a, buf
}

func runAgent(t *testing.T, a *Agent) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		a.Run(ctx)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("the agent did not stop when told")
		}
	})
}

func roundTrip(t *testing.T, ch ssh.Channel, msg string) string {
	t.Helper()
	if _, err := ch.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	_ = ch.CloseWrite()
	got, err := io.ReadAll(ch)
	if err != nil {
		t.Fatal(err)
	}
	return string(got)
}

func TestTheTunnelCarriesConnectionsToTheTarget(t *testing.T) {
	r := newTestRelay(t)
	target := echoTarget(t)
	a, audit := newAgent(t, r, []config.Forward{target}, 2)
	r.list(a.id.Signer.PublicKey())
	runAgent(t, a)

	for link := 0; link < 2; link++ {
		path := identity.SocketPath(a.id.SocketDir, target.Host, link)
		if got := roundTrip(t, r.open(t, path), "hello over link"); got != "hello over link" {
			t.Fatalf("link %d echoed %q", link, got)
		}
	}
	r.mu.Lock()
	users := append([]string(nil), r.users...)
	r.mu.Unlock()
	for _, u := range users {
		if u != a.id.User {
			t.Fatalf("logged in as %s, want the org-and-key login %s", u, a.id.User)
		}
	}
	waitFor(t, func() bool { return countEvents(audit.events(t), "connection") == 2 })
	for _, e := range audit.events(t) {
		if e["event"] == "connection" && (e["bytes_to_target"] != float64(15) || e["bytes_from_target"] != float64(15)) {
			t.Fatalf("connection audit %v", e)
		}
	}
	if countEvents(audit.events(t), "identity") != 1 || countEvents(audit.events(t), "forward") < 2 {
		t.Fatalf("audit %s", audit.String())
	}
	for _, e := range audit.events(t) {
		if e["event"] == "identity" {
			urls, _ := e["app_urls"].([]any)
			if len(urls) != 1 || urls[0] != target.AppURL() {
				t.Fatalf("the identity line names each target's app URL: %v", e)
			}
		}
	}
}

func TestAnUnlistedAgentWaitsAndIsLetInOnceListed(t *testing.T) {
	r := newTestRelay(t)
	target := echoTarget(t)
	a, audit := newAgent(t, r, []config.Forward{target}, 1)
	var sleeps []time.Duration
	var mu sync.Mutex
	a.sleep = func(ctx context.Context, d time.Duration) error {
		mu.Lock()
		sleeps = append(sleeps, d)
		n := len(sleeps)
		mu.Unlock()
		if n == 2 {
			r.list(a.id.Signer.PublicKey()) // the customer pastes the key
		}
		return nil
	}
	runAgent(t, a)
	path := identity.SocketPath(a.id.SocketDir, target.Host, 0)
	if got := roundTrip(t, r.open(t, path), "ping"); got != "ping" {
		t.Fatalf("echoed %q", got)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, d := range sleeps[:2] {
		if d < unlistedRetry || d > unlistedRetry+time.Second {
			t.Fatalf("a refused agent retries every 5-6s, slept %v", d)
		}
	}
	if n := countEvents(audit.events(t), "waiting"); n != 1 {
		t.Fatalf("want one waiting line before the first minute, got %d", n)
	}
}

func TestAWrongHostKeyIsNeverLoggedInto(t *testing.T) {
	r := newTestRelay(t)
	a, audit := newAgent(t, r, []config.Forward{echoTarget(t)}, 1)
	r.list(a.id.Signer.PublicKey())
	a.cfg.HostKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMk8CisV24CYS6k/jtJCKqtwmUyFXsWrG1h+R7Z6P7KM"
	stop := make(chan struct{})
	a.sleep = func(ctx context.Context, d time.Duration) error { close(stop); return errors.New("stop") }
	a.linkLoop(context.Background(), 0)
	<-stop
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.users) != 0 {
		t.Fatal("the agent must not authenticate to a relay whose host key does not match the pin")
	}
	if countEvents(audit.events(t), "disconnected") != 1 || countEvents(audit.events(t), "waiting") != 0 {
		t.Fatalf("a host key mismatch is a failure, not a wait: %s", audit.String())
	}
	if !strings.Contains(audit.String(), "not trusted") {
		t.Fatalf("the mismatch says so: %s", audit.String())
	}
}

func TestTheRetryPaces(t *testing.T) {
	r := newTestRelay(t)
	clock := time.Unix(0, 0)
	newLoop := func(sessionErr error, stopAfter int) (*Agent, *syncBuffer, *[]time.Duration) {
		a, audit := newAgent(t, r, []config.Forward{{Host: "h", Port: 1}}, 1)
		var sleeps []time.Duration
		a.now = func() time.Time { return clock }
		a.audit.now = a.now
		a.jitter = func(max time.Duration) time.Duration { return max }
		a.session = func(context.Context, int) error { return sessionErr }
		a.sleep = func(_ context.Context, d time.Duration) error {
			clock = clock.Add(d)
			sleeps = append(sleeps, d)
			if len(sleeps) == stopAfter {
				return errors.New("stop")
			}
			return nil
		}
		return a, audit, &sleeps
	}

	unlisted := errors.New("ssh: handshake failed: ssh: unable to authenticate, attempted methods [none publickey], no supported methods remain")
	a, audit, sleeps := newLoop(unlisted, 60)
	a.linkLoop(context.Background(), 0)
	for _, d := range *sleeps {
		if d != unlistedRetry+time.Second {
			t.Fatalf("steady retry, never backing off: slept %v", d)
		}
	}
	var at []time.Time
	for _, e := range audit.events(t) {
		if e["event"] == "waiting" {
			ts, _ := time.Parse("2006-01-02T15:04:05.000000-07:00", e["ts"].(string))
			at = append(at, ts)
		}
	}
	if len(at) < 4 {
		t.Fatalf("one waiting line a minute over six minutes, got %d", len(at))
	}
	for i := 1; i < len(at); i++ {
		if gap := at[i].Sub(at[i-1]); gap < unlistedLogEvery || gap >= unlistedLogEvery+6*time.Second {
			t.Fatalf("waiting lines %v apart", gap)
		}
	}

	b, _, sleeps := newLoop(errors.New("relay unreachable"), 7)
	b.linkLoop(context.Background(), 0)
	want := []time.Duration{3, 6, 12, 24, 45, 45, 45}
	for i, d := range *sleeps {
		if d != want[i]*time.Second {
			t.Fatalf("backoff %v, want %v (2s doubling to 30s, plus up to half again)", *sleeps, want)
		}
	}
}

func TestTheRelayIsReachedThroughTheProxy(t *testing.T) {
	r := newTestRelay(t)
	var connects int
	var mu sync.Mutex
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodConnect {
			http.Error(w, "CONNECT only", http.StatusMethodNotAllowed)
			return
		}
		mu.Lock()
		connects++
		mu.Unlock()
		dst, err := net.Dial("tcp", req.Host)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		c, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			dst.Close()
			return
		}
		_, _ = c.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		go func() { _, _ = io.Copy(dst, c); dst.Close() }()
		_, _ = io.Copy(c, dst)
		c.Close()
	}))
	defer proxy.Close()
	old := proxyFunc
	proxyFunc = func(*http.Request) (*url.URL, error) { return url.Parse(proxy.URL) }
	defer func() { proxyFunc = old }()

	target := echoTarget(t)
	a, audit := newAgent(t, r, []config.Forward{target}, 1)
	r.list(a.id.Signer.PublicKey())
	runAgent(t, a)
	if got := roundTrip(t, r.open(t, identity.SocketPath(a.id.SocketDir, target.Host, 0)), "via proxy"); got != "via proxy" {
		t.Fatalf("echoed %q", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if connects == 0 {
		t.Fatal("the WebSocket must go through HTTPS_PROXY's CONNECT")
	}
	if countEvents(audit.events(t), "proxy") != 1 {
		t.Fatalf("the proxy in use is logged once: %s", audit.String())
	}
}

func TestCheckReportsEachStep(t *testing.T) {
	r := newTestRelay(t)
	target := echoTarget(t)
	a, _ := newAgent(t, r, []config.Forward{target, {Host: "127.0.0.1", Port: closedPort(t)}}, 1)

	var out bytes.Buffer
	if a.Check(context.Background(), &out) {
		t.Fatalf("an unreachable target fails the check:\n%s", out.String())
	}
	for _, want := range []string{
		"PASS  relay WebSocket upgraded",
		"PASS  relay host key matches",
		"WAIT  no Ascend app lists this agent's key yet",
		"PASS  target " + target.Addr() + " reachable",
		"FAIL  target 127.0.0.1:",
		identity.PasteForm(a.id.PublicKey),
		"INFO  app URL for " + target.Addr() + ": " + target.AppURL() + "/...",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in:\n%s", want, out.String())
		}
	}

	r.list(a.id.Signer.PublicKey())
	a.cfg.Forwards = a.cfg.Forwards[:1]
	out.Reset()
	if !a.Check(context.Background(), &out) || !strings.Contains(out.String(), "PASS  an Ascend app lists this agent's key") {
		t.Fatalf("a listed agent with reachable targets passes:\n%s", out.String())
	}

	a.cfg.HostKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMk8CisV24CYS6k/jtJCKqtwmUyFXsWrG1h+R7Z6P7KM"
	out.Reset()
	if a.Check(context.Background(), &out) || !strings.Contains(out.String(), "does not match the pinned key") {
		t.Fatalf("a host key mismatch fails:\n%s", out.String())
	}
}

func closedPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}

func countEvents(events []map[string]any, name string) int {
	n := 0
	for _, e := range events {
		if e["event"] == name {
			n++
		}
	}
	return n
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in time")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestRedactDropsProxyCredentials(t *testing.T) {
	if got := redact("http://user:secret@proxy.corp:8080"); strings.Contains(got, "secret") {
		t.Fatalf("a proxy password must never reach a log: %s", got)
	}
}
