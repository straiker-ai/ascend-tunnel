package agentclient

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// gateway fakes the token exchange and the agent routes. Tokens are "t1", "t2"… and only the newest is accepted.
type gateway struct {
	*httptest.Server
	exchanges atomic.Int32
	expired   atomic.Bool
	mux       *http.ServeMux
}

func newGateway(t *testing.T) *gateway {
	g := &gateway{mux: http.NewServeMux()}
	g.mux.HandleFunc("POST /auth/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("subject_token") != "pat-1" || !strings.HasSuffix(r.Form.Get("subject_token_type"), ":pat") {
			http.Error(w, `{"detail":"bad token"}`, http.StatusUnauthorized)
			return
		}
		n := g.exchanges.Add(1)
		g.expired.Store(false)
		fmt.Fprintf(w, `{"access_token":"t%d","expires_in":3600}`, n)
	})
	g.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/token" {
			want := fmt.Sprintf("Bearer t%d", g.exchanges.Load())
			if r.Header.Get("Authorization") != want || g.expired.Load() {
				http.Error(w, `{"detail":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
		}
		g.mux.ServeHTTP(w, r)
	}))
	t.Cleanup(g.Close)
	return g
}

func (g *gateway) client() *Client {
	return &Client{Base: g.URL, PAT: "pat-1", HTTP: g.Server.Client()}
}

func TestSignInOnceAndAgainAfterA401(t *testing.T) {
	g := newGateway(t)
	g.mux.HandleFunc("GET /api/v3/ascend/agent/hosts/a4d9ef2c", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"tenant":"1","hostId":"a4d9ef2c","online":true}`)
	})
	c := g.client()
	for i := 0; i < 3; i++ {
		h, err := c.Host(context.Background(), "a4d9ef2c")
		if err != nil || !h.Online || h.Tenant != "1" {
			t.Fatalf("host: %+v %v", h, err)
		}
	}
	if g.exchanges.Load() != 1 {
		t.Fatalf("exchanged %d times for 3 calls", g.exchanges.Load())
	}
	g.expired.Store(true)
	if _, err := c.Host(context.Background(), "a4d9ef2c"); err != nil {
		t.Fatalf("after expiry: %v", err)
	}
	if g.exchanges.Load() != 2 {
		t.Fatalf("a 401 must re-exchange once, got %d exchanges", g.exchanges.Load())
	}
}

func TestErrorsCarryTheDetail(t *testing.T) {
	g := newGateway(t)
	g.mux.HandleFunc("POST /api/v3/ascend/agent/sessions", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprint(w, `{"detail":"an adaptor build is already running for your organisation"}`)
	})
	g.mux.HandleFunc("GET /api/v3/ascend/agent/hosts/{id}", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"detail":"no such agent host"}`, http.StatusNotFound)
	})
	c := g.client()
	_, err := c.StartSession(context.Background(), StartRequest{Message: "hello"})
	if err == nil || !strings.Contains(err.Error(), "429: an adaptor build is already running") {
		t.Fatalf("want the 429 detail, got %v", err)
	}
	if _, err := c.Host(context.Background(), "ffffffff"); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	bad := &Client{Base: g.URL, PAT: "wrong", HTTP: g.Server.Client()}
	if _, err := bad.Host(context.Background(), "a4d9ef2c"); err == nil || !strings.Contains(err.Error(), "sign in") {
		t.Fatalf("a bad PAT is a sign-in error, got %v", err)
	}
}

func sse(w http.ResponseWriter, events ...string) {
	w.Header().Set("Content-Type", "text/event-stream")
	fmt.Fprint(w, ": connected\n\n")
	for _, e := range events {
		fmt.Fprint(w, e)
	}
	w.(http.Flusher).Flush()
}

func ev(id, typ string, fields map[string]any) string {
	fields["type"] = typ
	b, _ := json.Marshal(fields)
	return fmt.Sprintf("id: %s\nevent: %s\ndata: %s\n\n", id, typ, b)
}

func collect(t *testing.T, c *Client, sid string) []Event {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ch := make(chan Event, 100)
	if err := c.Follow(ctx, sid, "", ch); err != nil {
		t.Fatalf("follow: %v", err)
	}
	close(ch)
	var out []Event
	for e := range ch {
		out = append(out, e)
	}
	return out
}

func TestFollowResumesTheStreamUntilTheSessionEnds(t *testing.T) {
	g := newGateway(t)
	var calls atomic.Int32
	g.mux.HandleFunc("GET /api/v3/ascend/agent/sessions/s1/events", func(w http.ResponseWriter, r *http.Request) {
		switch calls.Add(1) {
		case 1:
			sse(w, ev("1-1", "tool.start", map[string]any{"name": "host_http_probe", "where": "local"}))
		case 2:
			if r.Header.Get("Last-Event-ID") != "1-1" {
				t.Errorf("reconnect must resume after 1-1, sent %q", r.Header.Get("Last-Event-ID"))
			}
			sse(w, ev("1-2", "build.result", map[string]any{"status": "proposed", "candidate": map[string]any{"source": "x", "bytes": 1}}),
				ev("1-3", "session.status", map[string]any{"status": "ended"}))
		default:
			t.Error("followed past the end of the session")
		}
	})
	got := collect(t, g.client(), "s1")
	if len(got) != 3 || got[0].Where != "local" || got[1].Cand.Source != "x" || !got[2].Terminal() || got[2].ID != "1-3" {
		t.Fatalf("events: %+v", got)
	}
}

func TestFollowPollsWhenTheStreamIsNotSSE(t *testing.T) {
	g := newGateway(t)
	var polls atomic.Int32
	g.mux.HandleFunc("GET /api/v3/ascend/agent/sessions/s2/events", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") == "text/event-stream" {
			w.Header().Set("Content-Type", "application/json") // a proxy that rewrote the response
			fmt.Fprint(w, `{"events":[],"cursor":"0"}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if polls.Add(1) == 1 {
			fmt.Fprint(w, `{"events":[{"id":"5-1","type":"assistant.text","text":"hi"}],"cursor":"5-1"}`)
			return
		}
		if r.URL.Query().Get("after") != "5-1" {
			t.Errorf("poll must continue after 5-1, got %q", r.URL.Query().Get("after"))
		}
		fmt.Fprint(w, `{"events":[{"id":"5-2","type":"session.status","status":"cancelled"}],"cursor":"5-2"}`)
	})
	got := collect(t, g.client(), "s2")
	if len(got) != 2 || got[0].Text != "hi" || got[1].Status != "cancelled" {
		t.Fatalf("events: %+v", got)
	}
}

func TestCleanStripsWhatATerminalWouldObey(t *testing.T) {
	cases := map[string]string{
		"plain\ttext\nnext":                         "plain\ttext\nnext",
		"\x1b[31mred\x1b[0m":                        "red",
		"\x1b]8;;https://evil\x07click\x1b]8;;\x07": "click",
		"\x1b]0;window title\x1b\\after":            "after",
		"bell\x07 backspace\x08 cr\r":               "bell backspace cr",
		"c1\u009b31m csi":                           "c131m csi",
		"\x1bPdevice control\x1b\\ok":               "ok",
		"keep unicode — ✔ 日本":                       "keep unicode — ✔ 日本",
	}
	for in, want := range cases {
		if got := Clean(in); got != want {
			t.Errorf("Clean(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLoginIsSavedLikeTheAWSCLIDoes(t *testing.T) {
	home := t.TempDir()
	t.Setenv("ASCEND_AGENT_HOME", home)
	t.Setenv(PATEnv, "")
	if _, err := LoadConfig(); err != ErrNotSignedIn {
		t.Fatalf("want ErrNotSignedIn, got %v", err)
	}
	c := &Config{Env: "dev", Gateway: "https://api.dev.straiker.ai", Org: "1", User: "a@b.c", Token: "pat-1",
		SessionKeys: map[string]string{"dev": "key"}}
	path, err := c.Save()
	if err != nil {
		t.Fatal(err)
	}
	// Windows has no mode bits; there the per-user profile directory's ACL keeps it private.
	if fi, _ := os.Stat(path); runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Fatalf("config must be readable only by its owner: %v", fi.Mode())
	}
	got, err := LoadConfig()
	if err != nil || got.Token != "pat-1" || got.SessionKeys["dev"] != "key" {
		t.Fatalf("loaded: %+v %v", got, err)
	}
	t.Setenv(PATEnv, "env-pat")
	if got, _ := LoadConfig(); got.Token != "env-pat" {
		t.Fatalf("%s overrides the saved token: %q", PATEnv, got.Token)
	}
	if _, err := Logout(); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(); err != ErrNotSignedIn {
		t.Fatalf("after logout: %v", err)
	}
}

func TestSitesAreRememberedPerOrg(t *testing.T) {
	t.Setenv("ASCEND_AGENT_HOME", t.TempDir())
	if err := AllowSite("1", "WWW.SharkNinja.com"); err != nil {
		t.Fatal(err)
	}
	if !SiteAllowed("1", "www.sharkninja.com") || SiteAllowed("2", "www.sharkninja.com") {
		t.Fatal("an always-allowed site belongs to its org")
	}
	if removed, _ := ForgetSite("1", "www.sharkninja.com"); !removed || SiteAllowed("1", "www.sharkninja.com") {
		t.Fatal("forget")
	}
}

func TestProdUnlessTheConfigFileNamesAnotherEnvironment(t *testing.T) {
	home := t.TempDir()
	t.Setenv("ASCEND_AGENT_HOME", home)
	t.Setenv(PATEnv, "")
	if env, gw, err := TargetEnv(); err != nil || env != "prod" || gw != "https://api.prod.straiker.ai" {
		t.Fatalf("no file: %q %q %v", env, gw, err)
	}
	if err := os.WriteFile(filepath.Join(home, "config.json"), []byte(`{"env": "dev"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if env, gw, err := TargetEnv(); err != nil || env != "dev" || gw != "https://api.dev.straiker.ai" {
		t.Fatalf("env only: %q %q %v", env, gw, err)
	}
	if _, err := LoadConfig(); err != ErrNotSignedIn {
		t.Fatalf("an env is not a login: %v", err)
	}
	c := &Config{Env: "dev", Gateway: "https://stand-in", Org: "1", Token: "pat-1"}
	if _, err := c.Save(); err != nil {
		t.Fatal(err)
	}
	if env, gw, _ := TargetEnv(); env != "dev" || gw != "https://stand-in" {
		t.Fatalf("saved login: %q %q", env, gw)
	}
	if _, err := Logout(); err != nil {
		t.Fatal(err)
	}
	if env, _, _ := TargetEnv(); env != "dev" {
		t.Fatal("logout keeps a non-prod env, so the next login goes there again")
	}
	if _, err := LoadConfig(); err != ErrNotSignedIn {
		t.Fatalf("after logout: %v", err)
	}
	if err := os.WriteFile(filepath.Join(home, "config.json"), []byte(`{"env": "qa"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := TargetEnv(); err == nil {
		t.Fatal("an unknown env is refused")
	}
	for env, gw := range DefaultGateway {
		if gw != "https://api."+env+".straiker.ai" {
			t.Errorf("%s gateway %s", env, gw)
		}
	}
}

func TestSignInFindsTheOrgAndPinsTheKey(t *testing.T) {
	g := newGateway(t)
	g.mux.HandleFunc("GET /api/v3/ascend/agent/whoami", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"tenant":"1","principal":"yg@straiker.ai","sessionKey":"K","agentApi":"https://bridge/agent/v1"}`)
	})
	c, err := SignIn(context.Background(), g.Server.Client(), "pat-1", "dev", g.URL)
	if err != nil {
		t.Fatal(err)
	}
	if c.Env != "dev" || c.Org != "1" || c.User != "yg@straiker.ai" || c.SessionKeys["dev"] != "K" || c.AgentAPI == "" {
		t.Fatalf("config: %+v", c)
	}
	if _, err := SignIn(context.Background(), g.Server.Client(), "wrong", "dev", g.URL); err == nil {
		t.Fatal("a token that does not sign in is refused")
	}
}

func TestHARsAreUploadedGzippedToTheSession(t *testing.T) {
	g := newGateway(t)
	var got []byte
	var query url.Values
	g.mux.HandleFunc("POST /api/v3/ascend/agent/sessions/{sid}/har", func(w http.ResponseWriter, r *http.Request) {
		if r.PathValue("sid") != "s1" || r.Header.Get("Content-Encoding") != "gzip" {
			t.Errorf("sid %q, Content-Encoding %q", r.PathValue("sid"), r.Header.Get("Content-Encoding"))
		}
		query = r.URL.Query()
		zr, err := gzip.NewReader(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		got, _ = io.ReadAll(zr)
		fmt.Fprint(w, `{"traceId":"t1","trace":{"keptRequests":3,"totalRequests":9}}`)
	})
	app := "01a16263-de1f-7754-bd60-490a7cf2945f"
	tr, err := g.client().UploadHAR(context.Background(), "s1", app, "here it is", []byte(`{"log":{"entries":[]}}`))
	if err != nil || tr.TraceID != "t1" || tr.Trace.KeptRequests != 3 || string(got) != `{"log":{"entries":[]}}` {
		t.Fatalf("%+v %v %q", tr, err, got)
	}
	if query.Get("appId") != app || query.Get("note") != "here it is" {
		t.Fatalf("query %v", query)
	}
	if _, err := g.client().UploadHAR(context.Background(), "s1", "", "", []byte(`{}`)); err != nil || len(query) != 0 {
		t.Fatalf("without an app or note: %v %v", err, query)
	}
}
