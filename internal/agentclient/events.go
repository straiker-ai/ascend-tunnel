package agentclient

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Event is one entry of a session's timeline. Which fields are set depends on Type.
type Event struct {
	ID       string     `json:"id"`
	Type     string     `json:"type"`
	At       string     `json:"at"`
	Text     string     `json:"text"`
	By       string     `json:"by"`
	ToolID   string     `json:"toolId"`
	Name     string     `json:"name"`
	Where    string     `json:"where"`
	Detail   string     `json:"detail"`
	OK       *bool      `json:"ok"`
	Tool     string     `json:"tool"`
	Summary  string     `json:"summary"`
	Question string     `json:"question"`
	Status   string     `json:"status"`
	Reason   string     `json:"reason"`
	Notes    string     `json:"notes"`
	Message  string     `json:"message"`
	CostUSD  float64    `json:"costUsd"`
	TodayUSD float64    `json:"todayUsd"`
	DailyUSD float64    `json:"dailyUsd"`
	Model    string     `json:"model"`
	Revising bool       `json:"revising"`
	Path     string     `json:"path"`
	Pattern  string     `json:"pattern"`
	Diff     string     `json:"diff"`
	AppID    string     `json:"appId"`
	Cand     *Candidate `json:"candidate"`
	Checks   *Checks    `json:"checks"`
}

type Candidate struct {
	Source       string   `json:"source"`
	Bytes        int      `json:"bytes"`
	Digest       string   `json:"digest"`
	Capabilities []string `json:"capabilities"`
}

type Checks struct {
	Passed   *bool             `json:"passed"`
	Warnings []json.RawMessage `json:"warnings"`
	Blocking []json.RawMessage `json:"blocking"`
}

// Terminal reports whether this event ends the session.
func (e Event) Terminal() bool {
	return e.Type == "session.status" && (e.Status == "ended" || e.Status == "failed" || e.Status == "cancelled")
}

const (
	firstByteWait = 10 * time.Second // an SSE response that sends nothing this long is being buffered: poll
	idleWait      = 45 * time.Second // the server sends a comment at least every 5 s
)

// Follow delivers the session's events from after `after` ("" for all) until the session ends or ctx is
// done. It prefers SSE and falls back to long polling when a proxy buffers the stream.
func (c *Client) Follow(ctx context.Context, sid, after string, out chan<- Event) error {
	cursor, polling, failures := after, false, 0
	for ctx.Err() == nil {
		var done bool
		var err error
		if polling {
			cursor, done, err = c.pollOnce(ctx, sid, cursor, out)
		} else {
			var buffered bool
			cursor, done, buffered, err = c.streamOnce(ctx, sid, cursor, out)
			polling = buffered
		}
		if done {
			return nil
		}
		if err != nil {
			failures++
			wait := time.Duration(min(failures, 5)) * 2 * time.Second
			select {
			case <-ctx.Done():
			case <-time.After(wait):
			}
			continue
		}
		failures = 0
	}
	return ctx.Err()
}

func (c *Client) pollOnce(ctx context.Context, sid, cursor string, out chan<- Event) (string, bool, error) {
	q := url.Values{"wait": {"25"}}
	if cursor != "" {
		q.Set("after", cursor)
	}
	var body struct {
		Events []Event `json:"events"`
		Status string  `json:"status"`
		Cursor string  `json:"cursor"`
	}
	if err := c.call(ctx, http.MethodGet, "/sessions/"+url.PathEscape(sid)+"/events?"+q.Encode(), nil, &body); err != nil {
		return cursor, false, err
	}
	for _, e := range body.Events {
		if !deliver(ctx, out, e) {
			return cursor, true, nil
		}
		cursor = e.ID
		if e.Terminal() {
			return cursor, true, nil
		}
	}
	return cursor, false, nil
}

// streamOnce holds one SSE response. buffered reports a response that never started, so the caller polls.
func (c *Client) streamOnce(ctx context.Context, sid, cursor string, out chan<- Event) (string, bool, bool, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	h := http.Header{"Accept": {"text/event-stream"}, "Cache-Control": {"no-cache"}}
	if cursor != "" {
		h.Set("Last-Event-ID", cursor)
	}
	resp, err := c.request(ctx, http.MethodGet, "/sessions/"+url.PathEscape(sid)+"/events", nil, h)
	if err != nil {
		return cursor, false, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return cursor, false, false, apiError(resp)
	}
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		return cursor, false, true, nil
	}
	lines := make(chan string)
	readErr := make(chan error, 1)
	go func() {
		sc := bufio.NewScanner(resp.Body)
		sc.Buffer(make([]byte, 64<<10), 4<<20)
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
	var id, data string
	got := false
	timer := time.NewTimer(firstByteWait)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return cursor, true, false, nil
		case <-timer.C:
			if !got {
				return cursor, false, true, nil
			}
			return cursor, false, false, io.ErrUnexpectedEOF
		case err := <-readErr:
			if err == io.EOF {
				return cursor, false, false, nil
			}
			return cursor, false, false, err
		case line := <-lines:
			got = true
			timer.Reset(idleWait)
			switch {
			case line == "":
				if data == "" {
					continue
				}
				var e Event
				if json.Unmarshal([]byte(data), &e) == nil {
					e.ID = id
					if !deliver(ctx, out, e) {
						return cursor, true, false, nil
					}
					cursor = id
					if e.Terminal() {
						return cursor, true, false, nil
					}
				}
				id, data = "", ""
			case strings.HasPrefix(line, "id: "):
				id = line[4:]
			case strings.HasPrefix(line, "data: "):
				data += line[6:]
			}
		}
	}
}

func deliver(ctx context.Context, out chan<- Event, e Event) bool {
	select {
	case out <- e:
		return true
	case <-ctx.Done():
		return false
	}
}
