package stream

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/straiker-ai/ascend-tunnel/internal/agenthost/wire"
)

func newClient(base string) *Client {
	return &Client{
		Base:        base,
		HTTP:        &http.Client{},
		Token:       func() (string, error) { return "tok", nil },
		FirstByte:   300 * time.Millisecond,
		Idle:        2 * time.Second,
		PollWait:    time.Second,
		StreamRetry: time.Hour,
	}
}

type collector struct {
	mu     sync.Mutex
	events []wire.Event
}

func (c *collector) add(ev wire.Event) { c.mu.Lock(); c.events = append(c.events, ev); c.mu.Unlock() }
func (c *collector) waitFor(t *testing.T, n int) []wire.Event {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		if len(c.events) >= n {
			out := append([]wire.Event(nil), c.events...)
			c.mu.Unlock()
			return out
		}
		c.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("waited for %d events", n)
	return nil
}

func TestStreamReceivesAndResumes(t *testing.T) {
	var conns atomic.Int32
	var resumedFrom atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/base/stream" || r.Header.Get("Authorization") != "Bearer tok" || r.Header.Get(wire.HeaderProtocol) != wire.Version {
			http.Error(w, "bad request", 400)
			return
		}
		n := conns.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		if n == 1 {
			fmt.Fprint(w, ": hello\n\nid: 1\nevent: call\ndata: {\"sid\":\"s\",\ndata: \"call_id\":\"c1\"}\n\n")
			return // the server closes after an event: a deploy
		}
		resumedFrom.Store(r.Header.Get(wire.HeaderLastEventID))
		fmt.Fprint(w, "id: 2\nevent: ping\ndata: {}\n\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer srv.Close()

	c := newClient(srv.URL + "/base/")
	var connects atomic.Int32
	c.OnConnect = func() { connects.Add(1) }
	var got collector
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.Run(ctx, got.add); close(done) }()
	evs := got.waitFor(t, 2)
	cancel()
	<-done

	var env wire.Envelope
	if evs[0].Event != wire.EventCall || evs[0].ID != "1" || json.Unmarshal(evs[0].Data, &env) != nil || env.CallID != "c1" {
		t.Fatalf("first event %+v", evs[0])
	}
	if evs[1].Event != wire.EventPing || resumedFrom.Load() != "1" {
		t.Fatalf("the reconnect must resume from Last-Event-ID 1, got %v", resumedFrom.Load())
	}
	if connects.Load() < 1 {
		t.Fatal("OnConnect must run")
	}
}

func TestBufferingProxyFallsBackToPoll(t *testing.T) {
	var polls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/stream":
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(200)
			w.(http.Flusher).Flush()
			<-r.Context().Done() // headers, then nothing: what a buffering proxy looks like
		case "/poll":
			if r.URL.Query().Get(wire.ParamWait) != "1" {
				http.Error(w, "wait", 400)
				return
			}
			if polls.Add(1) == 1 {
				json.NewEncoder(w).Encode(wire.PollResponse{Events: []wire.Event{{ID: "7", Event: wire.EventCall, Data: json.RawMessage(`{"sid":"s"}`)}}})
				return
			}
			if r.URL.Query().Get(wire.ParamAfter) != "7" {
				http.Error(w, "after", 400)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer srv.Close()

	c := newClient(srv.URL)
	var modes []string
	var mu sync.Mutex
	c.OnState = func(event string, kv ...any) {
		if event == "host.mode" || event == "host.connected" {
			mu.Lock()
			modes = append(modes, fmt.Sprint(event, kv[1]))
			mu.Unlock()
		}
	}
	var got collector
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.Run(ctx, got.add); close(done) }()
	evs := got.waitFor(t, 1)
	for polls.Load() < 2 {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	if evs[0].ID != "7" || c.LastID() != "7" {
		t.Fatalf("%+v", evs)
	}
	mu.Lock()
	defer mu.Unlock()
	if strings.Join(modes, ",") != "host.modepoll,host.connectedpoll" {
		t.Fatalf("states %v", modes)
	}
}

func TestPostRetriesOnlyTransientFailures(t *testing.T) {
	var calls atomic.Int32
	var status atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var res wire.Result
		if r.Header.Get("Content-Type") != "application/json" || json.NewDecoder(r.Body).Decode(&res) != nil || res.CallID != "c1" {
			http.Error(w, "bad", 400)
			return
		}
		if s := status.Load(); s != 0 && calls.Load() == 1 {
			w.WriteHeader(int(s))
			return
		}
		w.WriteHeader(204)
	}))
	defer srv.Close()
	c := newClient(srv.URL)
	body := wire.Result{SID: "s", CallID: "c1", Message: json.RawMessage(`{}`)}

	status.Store(503)
	if err := c.Post(context.Background(), wire.PathResults, body); err != nil || calls.Load() != 2 {
		t.Fatalf("a 503 is retried: %v after %d calls", err, calls.Load())
	}
	calls.Store(0)
	status.Store(403)
	err := c.Post(context.Background(), wire.PathResults, body)
	var se *StatusError
	if !errors.As(err, &se) || se.Code != 403 || calls.Load() != 1 || !strings.Contains(err.Error(), "enrolled") {
		t.Fatalf("a 403 is final and explained: %v after %d calls", err, calls.Load())
	}
}

func TestStreamRefusesNonSSE(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html>login</html>"))
	}))
	defer srv.Close()
	connected := false
	if _, err := newClient(srv.URL).streamOnce(context.Background(), func(wire.Event) {}, &connected); err == nil || connected {
		t.Fatal("a captive portal page is not a stream")
	}
}

func TestBackoff(t *testing.T) {
	var b backoff
	if d := b.next(&StatusError{Code: 401}); d != 30*time.Second {
		t.Fatal(d)
	}
	if d := b.next(&StatusError{Code: 404}); d != time.Minute {
		t.Fatal(d)
	}
	if d := b.next(&StatusError{Code: 429, Wait: 7 * time.Second}); d != 7*time.Second {
		t.Fatal(d)
	}
	for range 10 {
		if d := b.next(errors.New("net")); d > 30*time.Second || d <= 0 {
			t.Fatal(d)
		}
	}
	b.reset()
	if d := b.next(errors.New("net")); d > time.Second {
		t.Fatal("after a reset the first wait is short:", d)
	}
}

func TestSSEParser(t *testing.T) {
	var p sseParser
	var got []wire.Event
	for _, l := range strings.Split("retry: 5\n: comment\nid: 3\ndata: a\ndata:b\n\ndata: c\n\nevent: x\nid: 4\x005\n\n\n", "\n") {
		if ev, ok := p.line(l); ok {
			got = append(got, ev)
		}
	}
	if len(got) != 3 {
		t.Fatalf("%+v", got)
	}
	if got[0].Event != "message" || string(got[0].Data) != "a\nb" || got[0].ID != "3" {
		t.Fatalf("multi-line data, default event: %+v", got[0])
	}
	if got[1].ID != "3" {
		t.Fatal("the id persists across events")
	}
	if got[2].Event != "x" || got[2].ID != "3" {
		t.Fatal("an id with NUL is ignored:", got[2])
	}
}
