package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	brokeragent "github.com/straiker-ai/straiker-broker/pkg/agent"
	brokerid "github.com/straiker-ai/straiker-broker/pkg/identity"

	"github.com/straiker-ai/ascend-tunnel/internal/agentclient"
)

// fakeBrokerAPI is Straiker's gateway for Straiker Broker, one record per list page so every walk follows the cursor.
type fakeBrokerAPI struct {
	mu      sync.Mutex
	brokers []agentclient.Broker
	targets []agentclient.BrokerTarget
	labels  []string // posted with each broker and target
	calls   []string // "POST /api/v3/broker/brokers", ...
	raced   bool     // a POST answers 409, the record having been made meanwhile
	// refuse answers the route ("" for every route) with this status and error code.
	refuse, refuseCode string
	refuseStatus       int
}

func (f *fakeBrokerAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/auth/token" {
		fmt.Fprint(w, `{"access_token":"t1","expires_in":3600}`)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	route := r.Method + " " + r.URL.Path
	f.calls = append(f.calls, route)
	switch {
	case r.Header.Get("Authorization") != "Bearer t1":
		apiError(w, http.StatusUnauthorized, "unauthorized")
		return
	case r.Method == http.MethodGet && r.URL.Query().Get("limit") != "100":
		apiError(w, http.StatusBadRequest, "invalid_limit")
		return
	case f.refuseStatus != 0 && (f.refuse == "" || f.refuse == route):
		apiError(w, f.refuseStatus, f.refuseCode)
		return
	}
	var in struct {
		PublicKey string   `json:"public_key"`
		Label     string   `json:"label"`
		BrokerID  string   `json:"broker_id"`
		Name      string   `json:"name"`
		Port      int      `json:"port"`
		Products  []string `json:"products"`
	}
	_ = json.NewDecoder(r.Body).Decode(&in)
	switch route {
	case "GET /api/v3/broker/brokers":
		page(w, r, f.brokers)
	case "GET /api/v3/broker/targets":
		page(w, r, f.targets)
	case "POST /api/v3/broker/brokers":
		b := agentclient.Broker{ID: "brk_" + strconv.Itoa(len(f.brokers)+1), PublicKey: in.PublicKey, Status: "active"}
		f.brokers, f.labels = append(f.brokers, b), append(f.labels, in.Label)
		if f.raced {
			apiError(w, http.StatusConflict, "broker_exists")
			return
		}
		_ = json.NewEncoder(w).Encode(b)
	case "POST /api/v3/broker/targets":
		tg := agentclient.BrokerTarget{ID: "tgt_" + strconv.Itoa(len(f.targets)+1), BrokerID: in.BrokerID, Name: in.Name,
			Port: in.Port, Products: []string{}}
		f.targets, f.labels = append(f.targets, tg), append(f.labels, in.Label)
		if f.raced {
			apiError(w, http.StatusConflict, "target_exists")
			return
		}
		_ = json.NewEncoder(w).Encode(tg)
	default:
		id, ok := strings.CutSuffix(strings.TrimPrefix(r.URL.Path, "/api/v3/broker/targets/"), "/grants")
		i := slices.IndexFunc(f.targets, func(t agentclient.BrokerTarget) bool { return t.ID == id })
		if !ok || r.Method != http.MethodPut || i < 0 {
			apiError(w, http.StatusNotFound, "not_found")
			return
		}
		f.targets[i].Products = in.Products
		_ = json.NewEncoder(w).Encode(f.targets[i])
	}
}

func page[T any](w http.ResponseWriter, r *http.Request, list []T) {
	i, _ := strconv.Atoi(r.URL.Query().Get("cursor"))
	out := map[string]any{"data": list[i:min(i+1, len(list))], "has_more": i+1 < len(list)}
	if i+1 < len(list) {
		out["next_cursor"] = strconv.Itoa(i + 1)
	}
	_ = json.NewEncoder(w).Encode(out)
}

func apiError(w http.ResponseWriter, status int, code string) {
	w.WriteHeader(status)
	fmt.Fprintf(w, `{"error":{"type":"invalid_request_error","code":%q,"message":"refused: %s"}}`, code, code)
}

// records is what Straiker holds now, and every call it answered.
func (f *fakeBrokerAPI) records() ([]agentclient.Broker, []agentclient.BrokerTarget, []string, []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.brokers), slices.Clone(f.targets), slices.Clone(f.labels), slices.Clone(f.calls)
}

// writes are the calls that changed something.
func (f *fakeBrokerAPI) writes() []string {
	_, _, _, calls := f.records()
	return slices.DeleteFunc(calls, func(c string) bool { return strings.HasPrefix(c, "GET ") })
}

// running counts the broker agents the tunnel runs at once, through its run seam.
type running struct {
	mu      sync.Mutex
	n       int
	started chan struct{}
}

func (r *running) run(_ *brokeragent.Agent, ctx context.Context) {
	r.mu.Lock()
	r.n++
	r.mu.Unlock()
	r.started <- struct{}{}
	<-ctx.Done()
	r.mu.Lock()
	r.n--
	r.mu.Unlock()
}

func (r *running) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.n
}

func testTunnels(t *testing.T, f *fakeBrokerAPI, s *settings) (*tunnels, *running) {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	tn, err := newTunnels(ctx, s, &agentclient.Client{Base: srv.URL, PAT: "pat-1", HTTP: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	r := &running{started: make(chan struct{}, 8)}
	tn.run = r.run
	return tn, r
}

func TestTheChatsTunnelRegistersEachTargetAndEndsWithTheChat(t *testing.T) {
	dir := t.TempDir()
	f := &fakeBrokerAPI{}
	tn, r := testTunnels(t, f, &settings{org: "1", env: "dev", stateDir: dir})
	if tn.stateDir != filepath.Join(dir, "broker") {
		t.Fatalf("the broker keeps its own key: %s", tn.stateDir)
	}
	ctx := context.Background()
	target, allow, err := tn.open(ctx, "chat.corp.internal", 443)
	if err != nil || target != "tgt_1" || strings.Join(allow, ",") != "chat.corp.internal:443" {
		t.Fatalf("open: %q %v %v", target, allow, err)
	}
	<-r.started
	brokers, targets, labels, calls := f.records()
	if len(brokers) != 1 || brokers[0].PublicKey != tn.id.PublicKey || !strings.HasPrefix(labels[0], "ascend-agent ") {
		t.Fatalf("the broker is registered with its key line and this machine's name: %+v %v", brokers, labels)
	}
	if tg := targets[0]; tg.BrokerID != "brk_1" || tg.Name != "chat.corp.internal" || tg.Port != 443 ||
		strings.Join(tg.Products, ",") != "ascend" {
		t.Fatalf("the target is declared and granted to Ascend: %+v", tg)
	}
	again, _, err := tn.open(ctx, "chat.corp.internal", 443)
	if _, _, _, now := f.records(); err != nil || again != "tgt_1" || len(now) != len(calls) {
		t.Fatalf("the same target again is a no-op: %q %v", again, err)
	}
	if _, _, err := tn.open(ctx, "chat.corp.internal", 8443); err == nil || !strings.Contains(err.Error(), "one port per host") {
		t.Fatalf("a second port for a host: %v", err)
	}
	if target, allow, err = tn.open(ctx, "app2.internal", 80); err != nil || target != "tgt_2" || len(allow) != 2 {
		t.Fatalf("open another: %q %v %v", target, allow, err)
	}
	<-r.started
	if brokers, targets, _, _ = f.records(); len(brokers) != 1 || targets[1].BrokerID != "brk_1" {
		t.Fatalf("one broker for every target: %+v", brokers)
	}
	if n := r.count(); n != 1 {
		t.Fatalf("one broker runs at a time, restarted with the longer allowlist: %d", n)
	}
	allow = tn.close()
	if strings.Join(allow, ",") != "chat.corp.internal:443,app2.internal:80" {
		t.Fatalf("allow: %v", allow)
	}
	if r.count() != 0 {
		t.Fatal("close stops it")
	}
	want := "straiker-broker service install --org 1 --allow chat.corp.internal:443 --allow app2.internal:80 --env dev " +
		"--state-dir " + filepath.Join(dir, "broker")
	if got := tn.keepCommand(allow); got != want {
		t.Fatalf("service command:\n got %q\nwant %q", got, want)
	}
}

func TestTheTunnelReusesWhatStraikerHasAndKeepsTheirGrants(t *testing.T) {
	f := &fakeBrokerAPI{}
	tn, r := testTunnels(t, f, &settings{org: "1", env: "dev", stateDir: t.TempDir()})
	f.brokers = []agentclient.Broker{
		{ID: "brk_other", PublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOo1Og0g1ySNPvGcpekTrxnLXVc2+2QJ5n3aisivR4X2", Status: "active"},
		{ID: "brk_mine", PublicKey: brokerid.PasteForm(tn.id.PublicKey), Status: "active"}, // the blob alone is the same key
	}
	f.targets = []agentclient.BrokerTarget{
		{ID: "tgt_other", BrokerID: "brk_other", Name: "chat.corp.internal", Port: 443},
		{ID: "tgt_chat", BrokerID: "brk_mine", Name: "chat.corp.internal", Port: 8443, Products: []string{"defend"}},
		{ID: "tgt_app2", BrokerID: "brk_mine", Name: "app2.internal", Port: 443, Products: []string{"ascend"}},
	}
	target, _, err := tn.open(context.Background(), "chat.corp.internal", 443)
	if err != nil || target != "tgt_chat" {
		t.Fatalf("this broker's target for the host, whatever port it was declared with: %q %v", target, err)
	}
	<-r.started
	if _, targets, _, _ := f.records(); strings.Join(targets[1].Products, ",") != "defend,ascend" {
		t.Fatalf("Ascend is added to the grants already there: %v", targets[1].Products)
	}
	if target, _, err = tn.open(context.Background(), "app2.internal", 443); err != nil || target != "tgt_app2" {
		t.Fatalf("open: %q %v", target, err)
	}
	if got := f.writes(); strings.Join(got, ",") != "PUT /api/v3/broker/targets/tgt_chat/grants" {
		t.Fatalf("nothing is registered twice, and a target granted to Ascend is left alone: %v", got)
	}
}

func TestTheTunnelReusesWhatAnotherOpenRegisteredMeanwhile(t *testing.T) {
	f := &fakeBrokerAPI{raced: true}
	tn, r := testTunnels(t, f, &settings{org: "1", env: "dev", stateDir: t.TempDir()})
	target, _, err := tn.open(context.Background(), "chat.corp.internal", 443)
	if err != nil || target != "tgt_1" {
		t.Fatalf("a 409 lists again and reuses the record: %q %v", target, err)
	}
	<-r.started
	want := "POST /api/v3/broker/brokers,POST /api/v3/broker/targets,PUT /api/v3/broker/targets/tgt_1/grants"
	if got := strings.Join(f.writes(), ","); got != want {
		t.Fatalf("calls: %s", got)
	}
}

func TestTheTunnelSaysWhatToDoWhenStraikerRefuses(t *testing.T) {
	for _, c := range []struct {
		name string
		f    *fakeBrokerAPI
		want []string
	}{
		{"a login without the scope", &fakeBrokerAPI{refuseStatus: 403, refuseCode: "insufficient_scope"},
			[]string{"refused: insufficient_scope", "integration:write", "ascend:write", "ascend-agent login"}},
		{"a key revoked meanwhile", &fakeBrokerAPI{refuse: "POST /api/v3/broker/targets", refuseStatus: 422, refuseCode: "broker_revoked"},
			[]string{"refused: broker_revoked", "revoked broker", "delete "}},
		{"anything else", &fakeBrokerAPI{refuse: "POST /api/v3/broker/targets", refuseStatus: 422, refuseCode: "invalid_name"},
			[]string{"Straiker API answered 422: refused: invalid_name"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			tn, r := testTunnels(t, c.f, &settings{org: "1", env: "dev", stateDir: t.TempDir()})
			_, _, err := tn.open(context.Background(), "chat.corp.internal", 443)
			for _, w := range c.want {
				if err == nil || !strings.Contains(err.Error(), w) {
					t.Fatalf("want %q in %v", w, err)
				}
			}
			if r.count() != 0 || len(tn.list()) != 0 {
				t.Fatal("nothing opens")
			}
		})
	}
}

func TestARevokedKeyIsRefusedWithHowToGetANewOne(t *testing.T) {
	f := &fakeBrokerAPI{}
	tn, _ := testTunnels(t, f, &settings{org: "1", env: "dev", stateDir: t.TempDir()})
	f.brokers = []agentclient.Broker{{ID: "brk_old", PublicKey: tn.id.PublicKey, Status: "revoked"}}
	_, _, err := tn.open(context.Background(), "chat.corp.internal", 443)
	if err == nil || !strings.Contains(err.Error(), "revoked broker") || !strings.Contains(err.Error(), "delete "+tn.stateDir) {
		t.Fatalf("revoked: %v", err)
	}
	if got := f.writes(); len(got) != 0 {
		t.Fatalf("a revoked key is not registered again: %v", got)
	}
}

func TestTheServiceCommandQuotesTheStateDirAndLeavesProdOut(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "Application Support")
	tn, _ := testTunnels(t, &fakeBrokerAPI{}, &settings{org: "1", env: "prod", stateDir: dir})
	want := "straiker-broker service install --org 1 --allow chat.corp.internal:443 --state-dir '" + filepath.Join(dir, "broker") + "'"
	if got := tn.keepCommand([]string{"chat.corp.internal:443"}); got != want {
		t.Fatalf("service command:\n got %q\nwant %q", got, want)
	}
}

func TestTheServiceCommandTrustsTheSameCA(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	tn, _ := testTunnels(t, &fakeBrokerAPI{}, &settings{org: "1", env: "dev", stateDir: dir, caFile: "proxy ca.pem"})
	want := "straiker-broker service install --org 1 --allow chat.corp.internal:443 --env dev --ca-file '" +
		filepath.Join(dir, "proxy ca.pem") + "' --state-dir " + filepath.Join(dir, "broker")
	if got := tn.keepCommand([]string{"chat.corp.internal:443"}); got != want {
		t.Fatalf("a relative CA file is made absolute, as the service needs it:\n got %q\nwant %q", got, want)
	}
}

func TestATunnelCanBeClosedWhileTheChatRunsAndCountsItsConnections(t *testing.T) {
	tn, r := testTunnels(t, &fakeBrokerAPI{}, &settings{org: "1", env: "dev", stateDir: t.TempDir()})
	for _, h := range []string{"chat.corp.internal", "app2.internal"} {
		if _, _, err := tn.open(context.Background(), h, 443); err != nil {
			t.Fatal(err)
		}
	}
	tn.audit.Log("connection", "link", 0, "dest", "chat.corp.internal:443", "bytes_to_target", 10)
	tn.audit.Log("connection", "link", 0, "dest", "chat.corp.internal:443", "error", "refused")
	tn.audit.Log("connection", "link", 0, "dest", "elsewhere:443")
	open := tn.list()
	if len(open) != 2 || open[0].addr != "chat.corp.internal:443" || open[0].conns != 1 || open[0].failed != 1 || open[1].conns != 0 {
		t.Fatalf("list: %+v", open)
	}
	if _, err := tn.shut("nowhere.internal"); err == nil {
		t.Fatal("closing what is not open says so")
	}
	gone, err := tn.shut("chat.corp.internal") // by host, as a person types it
	if err != nil || strings.Join(gone, ",") != "chat.corp.internal:443" {
		t.Fatalf("shut one: %v %v", gone, err)
	}
	if open := tn.list(); len(open) != 1 || open[0].addr != "app2.internal:443" {
		t.Fatalf("the other stays open: %+v", open)
	}
	if gone, err := tn.shut(""); err != nil || len(gone) != 1 {
		t.Fatalf("shut all: %v %v", gone, err)
	}
	if n := r.count(); n != 0 || len(tn.list()) != 0 || len(tn.close()) != 0 {
		t.Fatalf("nothing runs once every target is closed: %d", n)
	}
}
