package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

type fakeTools struct{ started chan struct{} }

func (f fakeTools) List() []Tool {
	return []Tool{
		{Name: "env.info", Description: "d", InputSchema: json.RawMessage(`{"type":"object"}`)},
		{Name: "net.check", Description: "d", InputSchema: json.RawMessage(`{"type":"object"}`)},
		{Name: "slow.wait", Description: "d", InputSchema: json.RawMessage(`{"type":"object"}`)},
	}
}

func (f fakeTools) Call(ctx context.Context, name string, args json.RawMessage) Result {
	if name == "slow.wait" {
		close(f.started)
		<-ctx.Done()
		return TextResult("cancelled", true)
	}
	return JSONResult(map[string]any{"tool": name, "args": json.RawMessage(args)}, false)
}

func newSession() (*Session, fakeTools) {
	f := fakeTools{started: make(chan struct{})}
	visible := func(n string) bool { return n != "net.check" }
	return NewSession(f, visible, ServerInfo{Name: "ascend-agent", Version: "test"}), f
}

func msg(t *testing.T, s string) Message {
	t.Helper()
	var m Message
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestInitializeNegotiates(t *testing.T) {
	s, _ := newSession()
	r := s.Handle(context.Background(), msg(t, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`))
	if !strings.Contains(string(r.Result), `"protocolVersion":"2025-06-18"`) || !strings.Contains(string(r.Result), `"name":"ascend-agent"`) {
		t.Fatal(string(r.Result))
	}
	r = s.Handle(context.Background(), msg(t, `{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"1999-01-01"}}`))
	if !strings.Contains(string(r.Result), `"protocolVersion":"`+ProtocolVersions[0]+`"`) {
		t.Fatal(string(r.Result))
	}
}

func TestListAndCallFollowVisibility(t *testing.T) {
	s, _ := newSession()
	r := s.Handle(context.Background(), msg(t, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	if strings.Contains(string(r.Result), "net.check") || !strings.Contains(string(r.Result), "env.info") {
		t.Fatal("tools/list must hide tools the session may not use:", string(r.Result))
	}
	r = s.Handle(context.Background(), msg(t, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"net.check","arguments":{}}}`))
	if r.Error == nil || r.Error.Code != ErrInvalidParams {
		t.Fatal("a hidden tool must not be callable")
	}
	r = s.Handle(context.Background(), msg(t, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"nope.tool"}}`))
	if r.Error == nil {
		t.Fatal("an unknown tool must be refused")
	}
	r = s.Handle(context.Background(), msg(t, `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"env.info"}}`))
	if r.Error != nil || !strings.Contains(string(r.Result), `"args":{}`) || string(r.ID) != "4" {
		t.Fatal("missing arguments become {}:", string(r.Result))
	}
}

func TestProtocolCorners(t *testing.T) {
	s, _ := newSession()
	ctx := context.Background()
	if r := s.Handle(ctx, msg(t, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)); r != nil {
		t.Fatal("notifications get no reply")
	}
	if r := s.Handle(ctx, msg(t, `{"jsonrpc":"2.0","method":"something/else"}`)); r != nil {
		t.Fatal("unknown notifications are ignored")
	}
	if r := s.Handle(ctx, msg(t, `{"jsonrpc":"2.0","id":"a","method":"resources/list"}`)); r.Error == nil || r.Error.Code != ErrMethodNotFound {
		t.Fatal("unknown methods are method-not-found")
	}
	if r := s.Handle(ctx, msg(t, `{"jsonrpc":"1.0","id":5,"method":"ping"}`)); r.Error == nil || r.Error.Code != ErrInvalidRequest {
		t.Fatal("only JSON-RPC 2.0")
	}
	if r := s.Handle(ctx, msg(t, `{"jsonrpc":"2.0","id":6,"result":{}}`)); r != nil {
		t.Fatal("a stray response gets no reply")
	}
	if r := s.Handle(ctx, msg(t, `{"jsonrpc":"2.0","id":7,"method":"ping"}`)); r.Error != nil || string(r.Result) != "{}" {
		t.Fatal("ping")
	}
	if r := s.Handle(ctx, msg(t, `{"jsonrpc":"2.0","id":8,"method":"tools/call","params":"x"}`)); r.Error == nil {
		t.Fatal("bad params")
	}
}

func TestCancellation(t *testing.T) {
	s, f := newSession()
	done := make(chan *Message)
	go func() {
		done <- s.Handle(context.Background(), msg(t, `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"slow.wait"}}`))
	}()
	<-f.started
	s.Handle(context.Background(), msg(t, `{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":9}}`))
	select {
	case r := <-done:
		if !strings.Contains(string(r.Result), "cancelled") {
			t.Fatal(string(r.Result))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("notifications/cancelled did not stop the call")
	}
}

func TestToolName(t *testing.T) {
	if ToolName(msg(t, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"env.info"}}`)) != "env.info" {
		t.Fatal("tools/call")
	}
	if ToolName(msg(t, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)) != "" {
		t.Fatal("other methods")
	}
}
