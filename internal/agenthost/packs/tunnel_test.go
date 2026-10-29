package packs

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/straiker-ai/ascend-tunnel/internal/agenthost/policy"
)

// fakeTunnel is the chat's built-in tunnel, and the person who confirms it.
type fakeTunnel struct {
	fakeApprover
	confirm bool
	asked   []string
	opened  []string
}

func (f *fakeTunnel) Confirm(ctx context.Context, agent, question string) bool {
	f.asked = append(f.asked, agent+": "+question)
	return f.confirm
}

func (f *fakeTunnel) Secret(ctx context.Context, prompt string) (string, bool) { return "", false }

func (f *fakeTunnel) Tunnel(ctx context.Context, host string, port int) (string, error) {
	f.opened = append(f.opened, fmt.Sprintf("%s:%d", host, port))
	return "AAAAC3NzaC1lZDI1NTE5AAAAIOo1Og0g1ySNPvGcpekTrxnLXVc2+2QJ5n3aisivR4X2", nil
}

func listening(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String()
}

func tunnelRegistry(p *policy.Policy, f *fakeTunnel) *Registry {
	return New(p, Info{Org: "1", Env: "dev"}, http.DefaultClient, nil, f)
}

func TestATunnelOpensOnlyAfterThePersonConfirms(t *testing.T) {
	addr := listening(t)
	f := &fakeTunnel{confirm: true}
	out, isErr := callAs(t, tunnelRegistry(policy.Default(), f), "ascend", "tunnel.open",
		`{"endpoint":"http://`+addr+`/v1/chat?x=1"}`)
	_, port, _ := net.SplitHostPort(addr)
	if isErr || out["endpoint"] != "http://127.0.0.1.tun.straiker.ai/v1/chat?x=1" || out["target"] != addr ||
		!strings.HasPrefix(out["agentKey"].(string), "AAAAC3NzaC1lZDI1NTE5") {
		t.Fatalf("open: %v", out)
	}
	if len(f.asked) != 1 || !strings.HasPrefix(f.asked[0], "ascend: ") || !strings.Contains(f.asked[0], addr) ||
		!strings.Contains(f.asked[0], "org 1") {
		t.Fatalf("the person is asked, naming the target and org: %q", f.asked)
	}
	if len(f.opened) != 1 || f.opened[0] != "127.0.0.1:"+port {
		t.Fatalf("opened: %v", f.opened)
	}
	if keep := out["keepRunning"].(string); !strings.HasPrefix(keep, "ascend-tunnel service install --org 1 --allow "+addr+" --env dev") {
		t.Fatalf("the service command keeps the same target and environment: %q", keep)
	}
}

func TestATunnelIsNotOpenedWhenThePersonSaysNo(t *testing.T) {
	f := &fakeTunnel{}
	out, isErr := callAs(t, tunnelRegistry(policy.Default(), f), "ascend", "tunnel.open", `{"endpoint":"http://`+listening(t)+`/"}`)
	if !isErr || !strings.Contains(out["error"].(string), "did not open") || len(f.opened) != 0 {
		t.Fatalf("declined: %v %v", out, f.opened)
	}
}

func TestATunnelIsNotOfferedForWhatThisMachineCannotReach(t *testing.T) {
	addr := listening(t)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := ln.Addr().String()
	ln.Close()
	f := &fakeTunnel{confirm: true}
	r := tunnelRegistry(policy.Default(), f)
	for _, c := range []struct{ endpoint, want string }{
		{"http://" + closed + "/", "cannot reach"},
		{"http://169.254.169.254/latest", "never reachable"},
		{"ftp://" + addr, "http or https"},
		{"https://user:pw@" + addr, "no credentials"},
		{"https://chat.corp.internal.tun.straiker.ai/v1", "already a tunnel address"},
	} {
		out, isErr := callAs(t, r, "ascend", "tunnel.open", `{"endpoint":"`+c.endpoint+`"}`)
		if !isErr || !strings.Contains(out["error"].(string), c.want) {
			t.Fatalf("%s: %v", c.endpoint, out)
		}
	}
	if len(f.asked) != 0 || len(f.opened) != 0 {
		t.Fatalf("nobody is asked about a tunnel that cannot work: %v %v", f.asked, f.opened)
	}
}

func TestATunnelStaysWithinThePolicysCap(t *testing.T) {
	p := policy.Default()
	p.Interactive.AllowHosts = []string{"*.corp.example"}
	f := &fakeTunnel{confirm: true}
	out, isErr := callAs(t, tunnelRegistry(p, f), "ascend", "tunnel.open", `{"endpoint":"http://`+listening(t)+`/"}`)
	if !isErr || !strings.Contains(out["error"].(string), "does not let a person approve") || len(f.asked) != 0 {
		t.Fatalf("capped: %v", out)
	}
}

func TestTheBuilderCannotOpenATunnel(t *testing.T) {
	p := policy.Default()
	if p.Allowed("adaptor-builder", p.Agents["adaptor-builder"], "tunnel.open") {
		t.Fatal("the adaptor builder opens no tunnel")
	}
	if !p.Allowed("ascend", p.Agents["ascend"], "tunnel.open") {
		t.Fatal("Ascend Agent may, with the person's yes")
	}
}

func TestAServiceHasNoTunnel(t *testing.T) {
	r := New(policy.Default(), Info{Org: "1"}, http.DefaultClient, nil, nil)
	for _, n := range r.Names() {
		if strings.HasPrefix(n, "tunnel.") {
			t.Fatalf("no person, no tunnel: %v", r.Names())
		}
	}
}
