package main

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/straiker-ai/ascend-tunnel/internal/agent"
	"github.com/straiker-ai/ascend-tunnel/internal/identity"
)

func TestTheChatsTunnelGrowsItsAllowlistAndEndsWithTheChat(t *testing.T) {
	dir := t.TempDir()
	id, err := identity.Load("1", dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tn := newTunnels(ctx, &settings{org: "1", env: "dev", stateDir: dir}, id)
	var mu sync.Mutex
	running, started := 0, make(chan struct{}, 4)
	tn.run = func(_ *agent.Agent, ctx context.Context) {
		mu.Lock()
		running++
		mu.Unlock()
		started <- struct{}{}
		<-ctx.Done()
		mu.Lock()
		running--
		mu.Unlock()
	}
	key, err := tn.open("chat.corp.internal", 443)
	if err != nil || key != identity.PasteForm(id.PublicKey) {
		t.Fatalf("open: %q %v", key, err)
	}
	<-started
	if _, err := tn.open("chat.corp.internal", 443); err != nil {
		t.Fatalf("the same target again is a no-op: %v", err)
	}
	if _, err := tn.open("chat.corp.internal", 8443); err == nil || !strings.Contains(err.Error(), "one port per host") {
		t.Fatalf("a second port for a host: %v", err)
	}
	if _, err := tn.open("app2.internal", 80); err != nil {
		t.Fatal(err)
	}
	<-started
	mu.Lock()
	n := running
	mu.Unlock()
	if n != 1 {
		t.Fatalf("one tunnel runs at a time, restarted with the longer allowlist: %d", n)
	}
	allow := tn.close()
	if strings.Join(allow, ",") != "chat.corp.internal:443,app2.internal:80" {
		t.Fatalf("allow: %v", allow)
	}
	mu.Lock()
	n = running
	mu.Unlock()
	if n != 0 {
		t.Fatal("close stops it")
	}
	got := tn.keepCommand(allow)
	if got != "ascend-tunnel service install --org 1 --allow chat.corp.internal:443 --allow app2.internal:80 --env dev" {
		t.Fatalf("service command: %q", got)
	}
}

func TestATunnelCanBeClosedWhileTheChatRunsAndCountsItsConnections(t *testing.T) {
	dir := t.TempDir()
	id, err := identity.Load("1", dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tn := newTunnels(ctx, &settings{org: "1", env: "dev", stateDir: dir}, id)
	var mu sync.Mutex
	running := 0
	tn.run = func(_ *agent.Agent, ctx context.Context) {
		mu.Lock()
		running++
		mu.Unlock()
		<-ctx.Done()
		mu.Lock()
		running--
		mu.Unlock()
	}
	for _, h := range []string{"chat.corp.internal", "app2.internal"} {
		if _, err := tn.open(h, 443); err != nil {
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
	time.Sleep(10 * time.Millisecond)
	mu.Lock()
	n := running
	mu.Unlock()
	if n != 0 || len(tn.list()) != 0 || len(tn.close()) != 0 {
		t.Fatalf("nothing runs once every target is closed: %d", n)
	}
}
