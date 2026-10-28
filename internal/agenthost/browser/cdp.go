// Package browser opens a visible browser on the person's machine and records the network traffic of what they do
// in it, over the Chrome DevTools Protocol, into a HAR that is redacted here before anything leaves the machine.
// The person drives the browser; nothing in this package clicks or types.
package browser

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/coder/websocket"
)

// cdp is one DevTools connection to the browser, with flattened sessions for its pages, frames and workers.
type cdp struct {
	conn    *websocket.Conn
	nextID  atomic.Int64
	mu      sync.Mutex
	pending map[int64]chan reply
	events  chan event
	closed  chan struct{}
	once    sync.Once
}

type reply struct {
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Message string `json:"message"`
	} `json:"error"`
}

type event struct {
	Method    string          `json:"method"`
	Params    json.RawMessage `json:"params"`
	SessionID string          `json:"sessionId"`
}

func dial(ctx context.Context, wsURL string) (*cdp, error) {
	conn, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		return nil, fmt.Errorf("connect to the browser: %w", err)
	}
	conn.SetReadLimit(64 << 20) // response bodies come back whole
	c := &cdp{conn: conn, pending: map[int64]chan reply{}, events: make(chan event, 4096), closed: make(chan struct{})}
	go c.read()
	return c, nil
}

func (c *cdp) read() {
	defer c.close()
	for {
		_, data, err := c.conn.Read(context.Background())
		if err != nil {
			return
		}
		var msg struct {
			ID int64 `json:"id"`
			reply
			event
		}
		if json.Unmarshal(data, &msg) != nil {
			continue
		}
		if msg.ID != 0 {
			c.mu.Lock()
			ch := c.pending[msg.ID]
			delete(c.pending, msg.ID)
			c.mu.Unlock()
			if ch != nil {
				ch <- msg.reply
			}
			continue
		}
		select {
		case c.events <- msg.event:
		default: // a recording that cannot keep up drops events rather than stalling the browser
		}
	}
}

func (c *cdp) close() {
	c.once.Do(func() {
		close(c.closed)
		_ = c.conn.Close(websocket.StatusNormalClosure, "")
	})
}

var errClosed = errors.New("the browser connection closed")

// call sends one command (to a session, when sessionID is set) and waits for its result.
func (c *cdp) call(ctx context.Context, sessionID, method string, params any) (json.RawMessage, error) {
	id := c.nextID.Add(1)
	msg := map[string]any{"id": id, "method": method}
	if params != nil {
		msg["params"] = params
	}
	if sessionID != "" {
		msg["sessionId"] = sessionID
	}
	raw, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}
	ch := make(chan reply, 1)
	c.mu.Lock()
	c.pending[id] = ch
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
	}()
	if err := c.conn.Write(ctx, websocket.MessageText, raw); err != nil {
		return nil, err
	}
	select {
	case r := <-ch:
		if r.Error != nil {
			return nil, fmt.Errorf("%s: %s", method, r.Error.Message)
		}
		return r.Result, nil
	case <-c.closed:
		return nil, errClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
