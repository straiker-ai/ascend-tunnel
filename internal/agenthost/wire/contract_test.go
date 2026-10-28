package wire_test

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/straiker-ai/ascend-tunnel/internal/agenthost"
	"github.com/straiker-ai/ascend-tunnel/internal/agenthost/token"
	"github.com/straiker-ai/ascend-tunnel/internal/agenthost/wire"
)

// contract is testdata/agent-contract.json, which Straiker's agent API checks too.
type contract struct {
	Protocol       string            `json:"protocol"`
	Paths          map[string]string `json:"paths"`
	DefaultBase    map[string]string `json:"default_base"`
	Events         map[string]string `json:"events"`
	Params         map[string]string `json:"params"`
	Headers        map[string]string `json:"headers"`
	TimingS        map[string]int    `json:"timing_s"`
	EnvelopeFields []string          `json:"envelope_fields"`
	CloseFields    []string          `json:"close_fields"`
	ResultFields   []string          `json:"result_fields"`
	HelloFields    []string          `json:"hello_fields"`
	HostToken      struct {
		Alg       string   `json:"alg"`
		Aud       string   `json:"aud"`
		IssPrefix string   `json:"iss_prefix"`
		TTLS      int      `json:"ttl_s"`
		Claims    []string `json:"claims"`
	} `json:"host_token"`
	SessionToken struct {
		Alg          string   `json:"alg"`
		Iss          string   `json:"iss"`
		AudPrefix    string   `json:"aud_prefix"`
		MaxLifetimeS int      `json:"max_lifetime_s"`
		Claims       []string `json:"claims"`
	} `json:"session_token"`
	Errors    map[string]int `json:"jsonrpc_errors"`
	MsgDigest struct {
		Vectors []struct {
			Message string `json:"message"`
			SHA256  string `json:"sha256"`
		} `json:"vectors"`
	} `json:"msg_digest"`
}

func load(t *testing.T) contract {
	t.Helper()
	data, err := os.ReadFile("../../../testdata/agent-contract.json")
	if err != nil {
		t.Fatal(err)
	}
	var c contract
	dec := json.NewDecoder(strings.NewReader(string(data)))
	if err := dec.Decode(&c); err != nil {
		t.Fatal(err)
	}
	return c
}

// jsonFields lists a struct's JSON field names, in order.
func jsonFields(v any) []string {
	var out []string
	t := reflect.TypeOf(v)
	for i := range t.NumField() {
		name, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ",")
		out = append(out, name)
	}
	return out
}

func eq(t *testing.T, what string, got, want any) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%s: code has %v, contract has %v", what, got, want)
	}
}

func TestContract(t *testing.T) {
	c := load(t)
	eq(t, "protocol", wire.Version, c.Protocol)
	eq(t, "paths", map[string]string{"stream": wire.PathStream, "poll": wire.PathPoll, "results": wire.PathResults, "hello": wire.PathHello}, c.Paths)
	eq(t, "default_base", wire.DefaultBase, c.DefaultBase)
	eq(t, "events", map[string]string{"call": wire.EventCall, "close": wire.EventClose, "ping": wire.EventPing}, c.Events)
	eq(t, "params", map[string]string{"after": wire.ParamAfter, "wait": wire.ParamWait}, c.Params)
	eq(t, "headers", map[string]string{"last_event_id": wire.HeaderLastEventID, "protocol": wire.HeaderProtocol,
		"instance": wire.HeaderInstance}, c.Headers)
	secs := func(d time.Duration) int { return int(d / time.Second) }
	eq(t, "timing_s", map[string]int{
		"heartbeat_interval": secs(wire.HeartbeatInterval), "first_byte_timeout": secs(wire.FirstByteTimeout),
		"idle_timeout": secs(wire.IdleTimeout), "poll_wait": secs(wire.PollWait),
		"default_call": secs(wire.DefaultCallTime), "max_call": secs(wire.MaxCallTime),
	}, c.TimingS)
	eq(t, "envelope_fields", jsonFields(wire.Envelope{}), c.EnvelopeFields)
	eq(t, "close_fields", jsonFields(wire.Close{}), c.CloseFields)
	eq(t, "result_fields", jsonFields(wire.Result{}), c.ResultFields)
	eq(t, "hello_fields", jsonFields(wire.Hello{}), c.HelloFields)

	eq(t, "host_token.alg", token.Alg, c.HostToken.Alg)
	eq(t, "host_token.aud", token.HostAudience, c.HostToken.Aud)
	eq(t, "host_token.iss_prefix", token.SessionAudiencePrefix, c.HostToken.IssPrefix)
	eq(t, "host_token.ttl_s", secs(token.HostTokenTTL), c.HostToken.TTLS)
	eq(t, "host_token.claims", jsonFields(token.HostClaims{}), c.HostToken.Claims)
	eq(t, "session_token.alg", token.Alg, c.SessionToken.Alg)
	eq(t, "session_token.iss", token.SessionIssuer, c.SessionToken.Iss)
	eq(t, "session_token.aud_prefix", token.SessionAudiencePrefix, c.SessionToken.AudPrefix)
	eq(t, "session_token.max_lifetime_s", secs(token.MaxSessionLifetime), c.SessionToken.MaxLifetimeS)
	eq(t, "session_token.claims", jsonFields(token.Session{}), c.SessionToken.Claims)

	if len(c.MsgDigest.Vectors) == 0 {
		t.Error("msg_digest: no vectors")
	}
	for _, v := range c.MsgDigest.Vectors {
		got, err := token.MessageDigest([]byte(v.Message))
		eq(t, "msg_digest vector", got, v.SHA256)
		if err != nil {
			t.Error(err)
		}
	}
	eq(t, "jsonrpc_errors", map[string]int{"session_rejected": agenthost.ErrSessionRejected, "rate_limited": agenthost.ErrRateLimited, "host_busy": agenthost.ErrBusy}, c.Errors)
}
