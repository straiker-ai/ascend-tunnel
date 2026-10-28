// Package agentclient is the person's side of ascend-agent: it talks to Straiker's API gateway with the
// user's login (a personal access token), to enrol this machine and to drive cloud agent sessions. It never
// touches the machine key's private half or the session tokens the host verifies.
package agentclient

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// DefaultGateway is the API gateway for each environment.
var DefaultGateway = map[string]string{
	"prod":  "https://api.prod.straiker.ai",
	"stage": "https://api.stage.straiker.ai",
	"dev":   "https://api.dev.straiker.ai",
}

const (
	agentPath    = "/api/v3/ascend/agent"
	exchangeSkew = 30 * time.Second
)

// ErrNotFound is a 404 from the gateway.
var ErrNotFound = errors.New("not found")

// APIError is any other non-2xx answer.
type APIError struct {
	Status int
	Detail string
}

func (e *APIError) Error() string {
	if e.Detail == "" {
		return fmt.Sprintf("Straiker API answered %d", e.Status)
	}
	return fmt.Sprintf("Straiker API answered %d: %s", e.Status, e.Detail)
}

// Client calls the gateway as one user. Safe for concurrent use.
type Client struct {
	Base string // the gateway, e.g. https://api.prod.straiker.ai
	PAT  string
	HTTP *http.Client

	mu      sync.Mutex
	token   string
	expires time.Time
}

func (c *Client) accessToken(ctx context.Context, fresh bool) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !fresh && c.token != "" && time.Now().Before(c.expires) {
		return c.token, nil
	}
	form := url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token_type": {"urn:straiker:params:oauth:token-type:pat"},
		"subject_token":      {c.PAT},
	}
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	var err error
	for attempt := 0; attempt < 3; attempt++ { // the exchange sometimes drops a connection unanswered
		if err = c.exchange(ctx, form, &out); err == nil {
			break
		}
		var apiErr *APIError
		if errors.As(err, &apiErr) || ctx.Err() != nil {
			break
		}
	}
	if err != nil {
		return "", fmt.Errorf("sign in: %w", err)
	}
	if out.AccessToken == "" {
		return "", errors.New("sign in: no access token in the answer")
	}
	life := time.Duration(out.ExpiresIn) * time.Second
	if life <= exchangeSkew {
		life = 5 * time.Minute
	}
	c.token, c.expires = out.AccessToken, time.Now().Add(life-exchangeSkew)
	return c.token, nil
}

func (c *Client) exchange(ctx context.Context, form url.Values, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Base+"/auth/token", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return apiError(resp)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
}

// request sends one authenticated JSON call under the agent routes.
func (c *Client) request(ctx context.Context, method, path string, body any, header http.Header) (*http.Response, error) {
	var raw []byte
	if body != nil {
		var err error
		if raw, err = json.Marshal(body); err != nil {
			return nil, err
		}
		if header == nil {
			header = http.Header{}
		}
		header.Set("Content-Type", "application/json")
	}
	return c.send(ctx, method, agentPath+path, raw, header)
}

// send sends one authenticated call to a gateway path, re-exchanging the PAT once on a 401.
func (c *Client) send(ctx context.Context, method, path string, raw []byte, header http.Header) (*http.Response, error) {
	for attempt := 0; ; attempt++ {
		tok, err := c.accessToken(ctx, attempt > 0)
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, method, c.Base+path, bytes.NewReader(raw))
		if err != nil {
			return nil, err
		}
		for k, v := range header {
			req.Header[k] = v
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := c.HTTP.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode == http.StatusUnauthorized && attempt == 0 {
			resp.Body.Close()
			continue
		}
		return resp, nil
	}
}

func (c *Client) call(ctx context.Context, method, path string, body, out any) error {
	resp, err := c.request(ctx, method, path, body, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("%w: %s", ErrNotFound, apiError(resp).Detail)
	}
	if resp.StatusCode/100 != 2 {
		return apiError(resp)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(out)
}

func apiError(resp *http.Response) *APIError {
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var body struct {
		Detail any `json:"detail"`
	}
	detail := strings.TrimSpace(string(raw))
	if json.Unmarshal(raw, &body) == nil && body.Detail != nil {
		if s, ok := body.Detail.(string); ok {
			detail = s
		} else {
			b, _ := json.Marshal(body.Detail)
			detail = string(b)
		}
	}
	if len(detail) > 300 {
		detail = detail[:300]
	}
	return &APIError{Status: resp.StatusCode, Detail: detail}
}

// GetJSON reads any gateway path as this user, e.g. /api/v3/ascend/applications.
func (c *Client) GetJSON(ctx context.Context, path string, query url.Values, out any) error {
	if len(query) > 0 {
		path += "?" + query.Encode()
	}
	resp, err := c.send(ctx, http.MethodGet, path, nil, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("%w: %s", ErrNotFound, apiError(resp).Detail)
	}
	if resp.StatusCode/100 != 2 {
		return apiError(resp)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(out)
}

// Host is an enrolled machine as the cloud sees it.
type Host struct {
	Tenant      string `json:"tenant"`
	HostID      string `json:"hostId"`
	Name        string `json:"name"`
	Fingerprint string `json:"fingerprint"`
	Online      bool   `json:"online"`
}

// Enrolment is the answer to enrolling a key.
type Enrolment struct {
	Tenant       string `json:"tenant"`
	HostID       string `json:"hostId"`
	Fingerprint  string `json:"fingerprint"`
	AgentAPI     string `json:"agentApi"`
	SessionKey   string `json:"sessionKey"`
	SessionKeyID string `json:"sessionKeyId"`
}

func (c *Client) Host(ctx context.Context, hostID string) (*Host, error) {
	var h Host
	if err := c.call(ctx, http.MethodGet, "/hosts/"+url.PathEscape(hostID), nil, &h); err != nil {
		return nil, err
	}
	return &h, nil
}

func (c *Client) Enroll(ctx context.Context, publicKey, name string) (*Enrolment, error) {
	var e Enrolment
	if err := c.call(ctx, http.MethodPost, "/hosts", map[string]string{"publicKey": publicKey, "name": name}, &e); err != nil {
		return nil, err
	}
	return &e, nil
}

// SessionKey is the public key the host pins to verify session tokens.
func (c *Client) SessionKey(ctx context.Context) (string, error) {
	var k struct {
		Key string `json:"key"`
	}
	if err := c.call(ctx, http.MethodGet, "/session-key", nil, &k); err != nil {
		return "", err
	}
	return k.Key, nil
}

// StartRequest starts a session with Ascend Agent.
type StartRequest struct {
	Message string `json:"message,omitempty"`
	AppID   string `json:"appId,omitempty"` // optional: an application the session is about
	HostID  string `json:"hostId,omitempty"`
}

// Session is a session record.
type Session struct {
	SID         string   `json:"sid"`
	Status      string   `json:"status"`
	Reason      string   `json:"reason"`
	AppID       string   `json:"appId"`
	HostID      string   `json:"hostId"`
	HostTools   []string `json:"hostTools"`
	HostTargets []string `json:"hostTargets"`
	CostUSD     float64  `json:"costUsd"`
}

func (c *Client) StartSession(ctx context.Context, r StartRequest) (*Session, error) {
	var s Session
	if err := c.call(ctx, http.MethodPost, "/sessions", r, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func (c *Client) GetSession(ctx context.Context, sid string) (*Session, error) {
	var s Session
	if err := c.call(ctx, http.MethodGet, "/sessions/"+url.PathEscape(sid), nil, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// Send gives the agent a message: an answer to its question, or the next thing to do.
func (c *Client) Send(ctx context.Context, sid, text string) error {
	return c.call(ctx, http.MethodPost, "/sessions/"+url.PathEscape(sid)+"/events",
		map[string]string{"type": "user.message", "text": text}, nil)
}

// Trace is a HAR distilled by Straiker into a redacted trace; the HAR itself is not kept.
type Trace struct {
	TraceID  string `json:"traceId"`
	HarBytes int    `json:"harBytes"`
	Trace    struct {
		KeptRequests  int `json:"keptRequests"`
		TotalRequests int `json:"totalRequests"`
	} `json:"trace"`
}

// UploadHAR sends the session a HAR, gzipped, with the person's note; the agent gets it as a message. appID may be
// empty for the session's application. Only the redacted trace is stored.
func (c *Client) UploadHAR(ctx context.Context, sid, appID, note string, har []byte) (*Trace, error) {
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	if _, err := zw.Write(har); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	q := url.Values{}
	if appID != "" {
		q.Set("appId", appID)
	}
	if note != "" {
		q.Set("note", note)
	}
	path := agentPath + "/sessions/" + url.PathEscape(sid) + "/har"
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	resp, err := c.send(ctx, http.MethodPost, path, gz.Bytes(),
		http.Header{"Content-Type": {"application/json"}, "Content-Encoding": {"gzip"}})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, apiError(resp)
	}
	var t Trace
	return &t, json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&t)
}

// Interrupt stops what the agent is doing (a reply, or a build); the session waits for the next message.
func (c *Client) Interrupt(ctx context.Context, sid string) error {
	return c.call(ctx, http.MethodPost, "/sessions/"+url.PathEscape(sid)+"/events", map[string]string{"type": "interrupt"}, nil)
}

// Cancel ends the session.
func (c *Client) Cancel(ctx context.Context, sid string) error {
	return c.call(ctx, http.MethodDelete, "/sessions/"+url.PathEscape(sid), nil, nil)
}
