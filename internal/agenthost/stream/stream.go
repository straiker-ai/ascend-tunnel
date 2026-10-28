// Package stream is the host's connection to Straiker's agent API: one long-lived Server-Sent Events
// stream for calls, a long-poll fallback for proxies that buffer SSE, and POSTs for everything the
// host sends. The host only ever dials out; there is nothing to connect in to.
package stream

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/straiker-ai/ascend-tunnel/internal/agenthost/wire"
)

const (
	maxEventBytes = 1 << 20 // one SSE line or polled body; a call is small
	maxReplyBytes = 64 << 10
	postAttempts  = 3
)

var (
	errBuffered = errors.New("no heartbeat after connecting: a proxy is buffering the stream")
	errIdle     = errors.New("stream went quiet")
)

// StatusError is a refusal from the agent API, with what to do about it.
type StatusError struct {
	Code int
	Body string
	Wait time.Duration // Retry-After, when the API gave one
}

func (e *StatusError) Error() string {
	hint := ""
	switch e.Code {
	case http.StatusUnauthorized, http.StatusForbidden:
		hint = " (is this host's key enrolled for this org?)"
	case http.StatusNotFound:
		hint = " (is the agent API available at this address?)"
	}
	return fmt.Sprintf("agent API answered %d%s: %s", e.Code, hint, e.Body)
}

// Client talks to one agent API base.
type Client struct {
	Base    string
	HTTP    *http.Client                  // no overall timeout: the stream is long-lived; requests carry their own
	Token   func() (string, error)        // a fresh host token per request
	OnState func(event string, kv ...any) // connection changes, for the audit log
	// OnConnect runs after each successful connect (stream opened, or a poll answered after an outage).
	OnConnect func()

	// Timings, overridable in tests.
	FirstByte   time.Duration
	Idle        time.Duration
	PollWait    time.Duration
	StreamRetry time.Duration

	mu     sync.Mutex
	lastID string
}

func (c *Client) timings() (firstByte, idle, pollWait, streamRetry time.Duration) {
	pick := func(v, d time.Duration) time.Duration {
		if v > 0 {
			return v
		}
		return d
	}
	return pick(c.FirstByte, wire.FirstByteTimeout), pick(c.Idle, wire.IdleTimeout),
		pick(c.PollWait, wire.PollWait), pick(c.StreamRetry, wire.StreamRetryAfter)
}

func (c *Client) state(event string, kv ...any) {
	if c.OnState != nil {
		c.OnState(event, kv...)
	}
}

// LastID is the id of the last event received, resumed from on reconnect.
func (c *Client) LastID() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastID
}

func (c *Client) setLastID(id string) {
	if id == "" {
		return
	}
	c.mu.Lock()
	c.lastID = id
	c.mu.Unlock()
}

// Run receives events until ctx ends, reconnecting with backoff. handle is called for each event in
// order; it must not block for long.
func (c *Client) Run(ctx context.Context, handle func(wire.Event)) {
	_, _, _, streamRetry := c.timings()
	var b backoff
	polling := false
	var pollUntil time.Time
	connected := false
	for ctx.Err() == nil {
		var got bool
		var err error
		if polling && time.Now().Before(pollUntil) {
			got, err = c.pollOnce(ctx, handle)
			if err == nil && !connected {
				connected = true
				c.connected("poll")
			}
		} else {
			if polling {
				polling = false
				c.state("host.mode", "mode", "stream", "reason", "retrying the stream")
			}
			got, err = c.streamOnce(ctx, handle, &connected)
			if errors.Is(err, errBuffered) {
				polling, pollUntil = true, time.Now().Add(streamRetry)
				c.state("host.mode", "mode", "poll", "reason", err.Error())
				continue
			}
		}
		if ctx.Err() != nil {
			return
		}
		// Healthy: a poll answered, a stream went quiet (reconnect at once), or a stream that carried
		// events was closed by the server (a deploy, a load balancer's limit).
		if err == nil || errors.Is(err, errIdle) || (got && errors.Is(err, io.EOF)) {
			b.reset()
			continue
		}
		if got {
			b.reset()
		}
		if connected {
			connected = false
			c.state("host.disconnected", "error", err.Error())
		}
		wait := b.next(err)
		c.state("host.retry", "error", err.Error(), "wait_s", int(wait.Seconds()))
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

func (c *Client) connected(mode string) {
	c.state("host.connected", "mode", mode, "base", c.Base)
	if c.OnConnect != nil {
		c.OnConnect()
	}
}

// streamOnce holds one SSE connection. got reports whether anything arrived on it.
func (c *Client) streamOnce(ctx context.Context, handle func(wire.Event), connected *bool) (got bool, err error) {
	firstByte, idle, _, _ := c.timings()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	req, err := c.request(ctx, http.MethodGet, wire.PathStream, nil, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Cache-Control", "no-cache")
	if id := c.LastID(); id != "" {
		req.Header.Set(wire.HeaderLastEventID, id)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if err := checkStatus(resp); err != nil {
		return false, err
	}
	if mt, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type")); mt != "text/event-stream" {
		return false, fmt.Errorf("agent API stream answered %q, not text/event-stream", resp.Header.Get("Content-Type"))
	}

	lines := make(chan string)
	readErr := make(chan error, 1)
	go func() {
		sc := bufio.NewScanner(resp.Body)
		sc.Buffer(make([]byte, 0, 64<<10), maxEventBytes)
		for sc.Scan() {
			select {
			case lines <- sc.Text():
			case <-ctx.Done():
				return
			}
		}
		if err := sc.Err(); err != nil {
			readErr <- err
		} else {
			readErr <- io.EOF
		}
	}()

	var p sseParser
	timer := time.NewTimer(firstByte)
	defer timer.Stop()
	for {
		select {
		case line := <-lines:
			if !got {
				got = true
				if !*connected {
					*connected = true
					c.connected("stream")
				}
			}
			timer.Reset(idle)
			if ev, ok := p.line(line); ok {
				c.setLastID(ev.ID)
				handle(ev)
			}
		case err := <-readErr:
			return got, err
		case <-timer.C:
			if !got {
				return false, errBuffered
			}
			return true, errIdle
		case <-ctx.Done():
			return got, ctx.Err()
		}
	}
}

// pollOnce is one long-poll: it waits up to PollWait for events after the last one seen.
func (c *Client) pollOnce(ctx context.Context, handle func(wire.Event)) (bool, error) {
	_, _, pollWait, _ := c.timings()
	ctx, cancel := context.WithTimeout(ctx, pollWait+15*time.Second)
	defer cancel()
	q := url.Values{wire.ParamWait: {strconv.Itoa(int(pollWait / time.Second))}}
	if id := c.LastID(); id != "" {
		q.Set(wire.ParamAfter, id)
	}
	req, err := c.request(ctx, http.MethodGet, wire.PathPoll, q, nil)
	if err != nil {
		return false, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return false, nil
	}
	if err := checkStatus(resp); err != nil {
		return false, err
	}
	var pr wire.PollResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxEventBytes)).Decode(&pr); err != nil {
		return false, fmt.Errorf("agent API poll: %w", err)
	}
	for _, ev := range pr.Events {
		c.setLastID(ev.ID)
		handle(ev)
	}
	return len(pr.Events) > 0, nil
}

// Post sends one JSON body (a result, a hello), retrying a network error or a 5xx; a 4xx is final.
func (c *Client) Post(ctx context.Context, path string, body any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	var last error
	for attempt := range postAttempts {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(500<<attempt) * time.Millisecond):
			}
		}
		rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		req, err := c.request(rctx, http.MethodPost, path, nil, data)
		if err != nil {
			cancel()
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.HTTP.Do(req)
		if err == nil {
			err = checkStatus(resp)
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxReplyBytes))
			resp.Body.Close()
		}
		cancel()
		if err == nil {
			return nil
		}
		last = err
		var se *StatusError
		if errors.As(err, &se) && se.Code < 500 && se.Code != http.StatusTooManyRequests {
			return err
		}
	}
	return last
}

func (c *Client) request(ctx context.Context, method, path string, q url.Values, body []byte) (*http.Request, error) {
	u := strings.TrimSuffix(c.Base, "/") + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, r)
	if err != nil {
		return nil, err
	}
	tok, err := c.Token()
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set(wire.HeaderProtocol, wire.Version)
	return req, nil
}

func checkStatus(resp *http.Response) error {
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	se := &StatusError{Code: resp.StatusCode, Body: strings.TrimSpace(string(body))}
	if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s > 0 {
		se.Wait = time.Duration(s) * time.Second
	}
	return se
}

// sseParser assembles Server-Sent Events from lines (the WHATWG event-stream format).
type sseParser struct {
	event, id string
	data      []string
}

func (p *sseParser) line(line string) (wire.Event, bool) {
	if line == "" {
		if p.event == "" && p.data == nil {
			return wire.Event{}, false
		}
		ev := wire.Event{ID: p.id, Event: p.event, Data: json.RawMessage(strings.Join(p.data, "\n"))}
		if ev.Event == "" {
			ev.Event = "message"
		}
		p.event, p.data = "", nil // the id persists, as the format specifies
		return ev, true
	}
	if strings.HasPrefix(line, ":") {
		return wire.Event{}, false // a comment: a heartbeat
	}
	field, value, _ := strings.Cut(line, ":")
	value = strings.TrimPrefix(value, " ")
	switch field {
	case "event":
		p.event = value
	case "data":
		p.data = append(p.data, value)
	case "id":
		if !strings.Contains(value, "\x00") {
			p.id = value
		}
	}
	return wire.Event{}, false
}

// backoff is the reconnect delay: exponential with jitter for transient failures, longer for a
// refusal that a person has to fix (enrolment, a wrong address).
type backoff struct{ n int }

func (b *backoff) reset() { b.n = 0 }

func (b *backoff) next(err error) time.Duration {
	var se *StatusError
	if errors.As(err, &se) {
		switch {
		case se.Wait > 0:
			return min(se.Wait, 5*time.Minute)
		case se.Code == http.StatusUnauthorized || se.Code == http.StatusForbidden:
			return 30 * time.Second
		case se.Code == http.StatusNotFound:
			return time.Minute
		}
	}
	d := time.Second << min(b.n, 5) // 1s .. 32s
	b.n++
	d = min(d, 30*time.Second)
	return d/2 + rand.N(d/2+1)
}
