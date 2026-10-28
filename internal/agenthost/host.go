// Package agenthost runs the host role: it holds the stream to Straiker's agent API, checks every call's
// session token, applies the customer's policy and limits, serves the call from the tool packs, and
// posts the result. Everything is logged to the local audit log, where Straiker cannot erase it.
package agenthost

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync"
	"time"

	"github.com/straiker-ai/ascend-tunnel/internal/agenthost/mcp"
	"github.com/straiker-ai/ascend-tunnel/internal/agenthost/packs"
	"github.com/straiker-ai/ascend-tunnel/internal/agenthost/policy"
	"github.com/straiker-ai/ascend-tunnel/internal/agenthost/stream"
	"github.com/straiker-ai/ascend-tunnel/internal/agenthost/token"
	"github.com/straiker-ai/ascend-tunnel/internal/agenthost/wire"
)

// JSON-RPC errors the host returns before a call reaches a tool (pinned by testdata/agent-contract.json).
const (
	ErrSessionRejected = -32001
	ErrRateLimited     = -32002
	ErrBusy            = -32003
)

const (
	sessionIdle = 30 * time.Minute
	dedupeTTL   = 15 * time.Minute
	dedupeMax   = 10_000
)

// Auditor is the audit log (the tunnel agent's, so both write the same format).
type Auditor interface {
	Log(event string, kv ...any)
}

// Poster sends a body to the agent API.
type Poster interface {
	Post(ctx context.Context, path string, body any) error
}

// Config is what a Host needs.
type Config struct {
	Policy      *policy.Policy
	Tools       mcp.Tools
	HostID      string
	Org         string
	SessionKeys []ed25519.PublicKey
	Info        mcp.ServerInfo
	API         Poster
	Audit       Auditor
	Now         func() time.Time
}

// Host handles events from the stream.
type Host struct {
	cfg  Config
	sem  chan struct{}
	rate *bucket

	mu       sync.Mutex
	sessions map[string]*session
	seen     map[string]*seenCall
}

type session struct {
	mcp      *mcp.Session
	mu       sync.Mutex
	claims   *token.Session
	lastUsed time.Time
}

type seenCall struct {
	at   time.Time
	done bool
	resp *mcp.Message
}

// New returns a Host.
func New(cfg Config) *Host {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Host{
		cfg:      cfg,
		sem:      make(chan struct{}, cfg.Policy.Limits.ConcurrentCalls),
		rate:     newBucket(cfg.Policy.Limits.CallsPerMinute, cfg.Now),
		sessions: map[string]*session{},
		seen:     map[string]*seenCall{},
	}
}

// Run serves events from c until ctx ends: hello on every connect, a sweep every minute.
func (e *Host) Run(ctx context.Context, c *stream.Client, hello wire.Hello) {
	c.OnConnect = func() {
		go func() {
			if err := c.Post(ctx, wire.PathHello, hello); err != nil {
				e.cfg.Audit.Log("host.hello_failed", "error", err)
			}
		}()
	}
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				e.Sweep()
			}
		}
	}()
	c.Run(ctx, func(ev wire.Event) { e.Handle(ctx, ev) })
}

// Hello is what the host tells Straiker on each connect.
func (e *Host) Hello(version string, tools []string) wire.Hello {
	return wire.Hello{
		Protocol: wire.Version, HostID: e.cfg.HostID, Org: e.cfg.Org, Version: version,
		PolicyDigest: e.cfg.Policy.Digest(), Tools: tools, Targets: e.cfg.Policy.TargetIDs(),
	}
}

// Handle dispatches one event. Calls run on their own goroutines, so the stream is never held up.
func (e *Host) Handle(ctx context.Context, ev wire.Event) {
	switch ev.Event {
	case wire.EventCall:
		var env wire.Envelope
		if err := json.Unmarshal(ev.Data, &env); err != nil || env.SID == "" || env.CallID == "" {
			e.cfg.Audit.Log("host.bad_event", "event_id", ev.ID, "error", "call without sid/call_id or not JSON")
			return
		}
		go e.call(ctx, env)
	case wire.EventClose:
		var c wire.Close
		if json.Unmarshal(ev.Data, &c) == nil && c.SID != "" {
			e.closeSession(c.SID)
		}
	case wire.EventPing, "message":
	default:
		e.cfg.Audit.Log("host.unknown_event", "event", ev.Event, "event_id", ev.ID)
	}
}

func (e *Host) call(ctx context.Context, env wire.Envelope) {
	key := env.SID + "/" + env.CallID
	if prior, first := e.begin(key); !first {
		if prior != nil {
			e.post(ctx, env, prior) // a redelivery after a lost POST: the same answer, not a second run
		}
		return
	}
	resp := e.serve(ctx, env)
	e.finish(key, resp)
	if resp != nil {
		e.post(ctx, env, resp)
	}
}

func (e *Host) serve(ctx context.Context, env wire.Envelope) *mcp.Message {
	start := e.cfg.Now()
	var m mcp.Message
	if err := json.Unmarshal(env.Message, &m); err != nil {
		e.audit(env, nil, "", "bad_message", start, err.Error())
		return mcp.ErrorReply(nil, mcp.ErrParse, "message is not JSON-RPC")
	}
	digest, _ := token.MessageDigest(env.Message) // valid JSON: it just unmarshalled
	claims, err := token.VerifySession(env.SessionJWT, e.cfg.SessionKeys, token.Expect{
		HostID: e.cfg.HostID, Tenant: e.cfg.Org, SID: env.SID, CallID: env.CallID, MsgSHA256: digest,
	}, e.cfg.Now())
	if err != nil {
		e.audit(env, &m, "", "rejected", start, err.Error())
		return refuse(m, ErrSessionRejected, "session token rejected by the host")
	}
	s := e.session(env.SID, claims)
	if m.IsNotification() { // cancellations must not queue behind the limits
		s.mcp.Handle(ctx, m)
		return nil
	}
	if !e.rate.take() {
		e.audit(env, &m, claims.Agent, "rate_limited", start, "")
		return refuse(m, ErrRateLimited, "host policy calls_per_minute reached")
	}
	timeout := wire.DefaultCallTime
	if env.TimeoutMS > 0 {
		timeout = min(time.Duration(env.TimeoutMS)*time.Millisecond, wire.MaxCallTime)
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	select {
	case e.sem <- struct{}{}:
		defer func() { <-e.sem }()
	case <-ctx.Done():
		e.audit(env, &m, claims.Agent, "busy", start, "")
		return refuse(m, ErrBusy, "host policy concurrent_calls reached for the whole call time")
	}
	resp := s.mcp.Handle(packs.WithAgent(ctx, claims.Agent), m)
	outcome := "ok"
	if resp != nil && resp.Error != nil {
		outcome = "error"
	} else if resp != nil && isToolError(resp) {
		outcome = "tool_error"
	}
	e.audit(env, &m, claims.Agent, outcome, start, "")
	return resp
}

// session returns the MCP session for sid, refreshing its claims: Straiker re-mints session tokens,
// and grants may narrow between calls, so visibility always follows the latest verified token.
func (e *Host) session(sid string, claims *token.Session) *session {
	e.mu.Lock()
	defer e.mu.Unlock()
	s := e.sessions[sid]
	if s == nil {
		s = &session{}
		s.mcp = mcp.NewSession(e.cfg.Tools, func(tool string) bool {
			s.mu.Lock()
			c := s.claims
			s.mu.Unlock()
			return e.cfg.Policy.Allowed(c.Agent, c.Grants, tool)
		}, e.cfg.Info)
		e.sessions[sid] = s
		e.cfg.Audit.Log("host.session", "sid", sid, "agent", claims.Agent, "agent_version", claims.AgentVersion, "app_id", claims.AppID)
	}
	s.mu.Lock()
	s.claims, s.lastUsed = claims, e.cfg.Now()
	s.mu.Unlock()
	return s
}

func (e *Host) closeSession(sid string) {
	e.mu.Lock()
	s := e.sessions[sid]
	delete(e.sessions, sid)
	e.mu.Unlock()
	if s != nil {
		s.mcp.CancelAll()
		e.cfg.Audit.Log("host.session_closed", "sid", sid)
	}
}

// Sweep forgets idle sessions and old call ids; Run calls it every minute.
func (e *Host) Sweep() {
	now := e.cfg.Now()
	e.mu.Lock()
	defer e.mu.Unlock()
	for sid, s := range e.sessions {
		s.mu.Lock()
		idle := now.Sub(s.lastUsed) > sessionIdle
		s.mu.Unlock()
		if idle {
			s.mcp.CancelAll()
			delete(e.sessions, sid)
		}
	}
	for k, c := range e.seen {
		if c.done && now.Sub(c.at) > dedupeTTL {
			delete(e.seen, k)
		}
	}
}

// begin records a call id. first is false for a call already seen; prior is its response once done.
func (e *Host) begin(key string) (prior *mcp.Message, first bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if c, ok := e.seen[key]; ok {
		return c.resp, false
	}
	if len(e.seen) >= dedupeMax { // bounded: drop the oldest finished entry
		var oldest string
		for k, c := range e.seen {
			if c.done && (oldest == "" || c.at.Before(e.seen[oldest].at)) {
				oldest = k
			}
		}
		delete(e.seen, oldest)
	}
	e.seen[key] = &seenCall{at: e.cfg.Now()}
	return nil, true
}

func (e *Host) finish(key string, resp *mcp.Message) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if c, ok := e.seen[key]; ok {
		c.done, c.resp, c.at = true, resp, e.cfg.Now()
	}
}

func (e *Host) post(ctx context.Context, env wire.Envelope, resp *mcp.Message) {
	msg, err := json.Marshal(resp)
	if err == nil {
		err = e.cfg.API.Post(ctx, wire.PathResults, wire.Result{SID: env.SID, CallID: env.CallID, Message: msg})
	}
	if err != nil {
		e.cfg.Audit.Log("host.result_failed", "sid", env.SID, "call_id", env.CallID, "error", err)
	}
}

func (e *Host) audit(env wire.Envelope, m *mcp.Message, agent, outcome string, start time.Time, reason string) {
	kv := []any{"sid", env.SID, "call_id", env.CallID, "agent", agent}
	if m != nil {
		kv = append(kv, "method", m.Method)
		if tool := mcp.ToolName(*m); tool != "" {
			kv = append(kv, "tool", tool, "args_sha256", argsDigest(m.Params))
		}
	}
	kv = append(kv, "outcome", outcome, "ms", e.cfg.Now().Sub(start).Milliseconds())
	if reason != "" {
		kv = append(kv, "reason", reason)
	}
	e.cfg.Audit.Log("host.call", kv...)
}

// argsDigest identifies a call's arguments in the audit log without writing them there.
func argsDigest(params json.RawMessage) string {
	var p struct {
		Arguments json.RawMessage `json:"arguments"`
	}
	_ = json.Unmarshal(params, &p)
	sum := sha256.Sum256(p.Arguments)
	return hex.EncodeToString(sum[:])[:12]
}

func refuse(m mcp.Message, code int, msg string) *mcp.Message {
	if m.IsNotification() {
		return nil
	}
	return mcp.ErrorReply(m.ID, code, msg)
}

func isToolError(resp *mcp.Message) bool {
	var r struct {
		IsError bool `json:"isError"`
	}
	return json.Unmarshal(resp.Result, &r) == nil && r.IsError
}

// bucket is a token bucket: calls_per_minute, refilled continuously.
type bucket struct {
	mu     sync.Mutex
	cap    float64
	tokens float64
	last   time.Time
	now    func() time.Time
}

func newBucket(perMinute int, now func() time.Time) *bucket {
	return &bucket{cap: float64(perMinute), tokens: float64(perMinute), last: now(), now: now}
}

func (b *bucket) take() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	b.tokens = min(b.cap, b.tokens+now.Sub(b.last).Minutes()*b.cap)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
