// Package wire is the host's protocol with Straiker's agent API: the host dials out, receives calls as
// Server-Sent Events (or by long-poll when a proxy buffers SSE), and POSTs results back. The calls
// and results are MCP JSON-RPC messages in an envelope. Every name here is pinned by
// testdata/agent-contract.json, which Straiker's side checks too.
package wire

import (
	"encoding/json"
	"time"
)

// Version names this protocol revision; testdata/agent-contract.json pins it.
const Version = "agent/v0"

// Paths under the agent API base.
const (
	PathStream  = "/stream"
	PathPoll    = "/poll"
	PathResults = "/results"
	PathHello   = "/hello"
)

// SSE event names (also the "event" of a polled event).
const (
	EventCall  = "call"
	EventClose = "close"
	EventPing  = "ping"
)

// Query parameters and headers.
const (
	ParamAfter        = "after"
	ParamWait         = "wait"
	HeaderLastEventID = "Last-Event-ID"
	HeaderProtocol    = "X-Ascend-Agent-Protocol"
)

// Timing. Straiker sends a heartbeat at least every HeartbeatInterval; a host that sees nothing for
// FirstByteTimeout after connecting assumes a buffering proxy and long-polls instead.
const (
	HeartbeatInterval = 15 * time.Second
	FirstByteTimeout  = 20 * time.Second
	IdleTimeout       = 45 * time.Second
	PollWait          = 25 * time.Second
	StreamRetryAfter  = 10 * time.Minute
	DefaultCallTime   = 120 * time.Second
	MaxCallTime       = 300 * time.Second
)

// DefaultBase is the agent API base per Straiker environment.
var DefaultBase = map[string]string{
	"prod":  "https://ascendai-bridge.prod.straiker.ai/agent/v1",
	"stage": "https://ascendai-bridge.stage.straiker.ai/agent/v1",
	"dev":   "https://ascendai-bridge.dev.straiker.ai/agent/v1",
}

// Envelope is one call from Straiker: an MCP message for one agent session, with the session token
// that proves Straiker sent it and says what the session may use.
type Envelope struct {
	SID        string          `json:"sid"`
	CallID     string          `json:"call_id"`
	SessionJWT string          `json:"session_jwt"`
	TimeoutMS  int             `json:"timeout_ms,omitempty"`
	Message    json.RawMessage `json:"message"`
}

// Close ends an agent session on the host: its in-flight calls are cancelled.
type Close struct {
	SID string `json:"sid"`
}

// Result is the host's answer to a call: the MCP response, for the session and call it answers.
type Result struct {
	SID     string          `json:"sid"`
	CallID  string          `json:"call_id"`
	Message json.RawMessage `json:"message"`
}

// Hello tells Straiker what this host serves, on every connect.
type Hello struct {
	Protocol     string   `json:"protocol"`
	HostID       string   `json:"host_id"`
	Org          string   `json:"org"`
	Version      string   `json:"version"`
	PolicyDigest string   `json:"policy_digest"`
	Tools        []string `json:"tools"`
	Targets      []string `json:"targets"`
}

// Event is one received event, from the stream or a poll.
type Event struct {
	ID    string          `json:"id"`
	Event string          `json:"event"`
	Data  json.RawMessage `json:"data"`
}

// PollResponse is the body of a poll.
type PollResponse struct {
	Events []Event `json:"events"`
}
