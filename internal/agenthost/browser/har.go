package browser

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	maxEntries   = 3000
	maxBodyBytes = 512 << 10
	maxWSFrames  = 500
)

// recorder turns Network events from every attached session into HAR entries.
type recorder struct {
	mu      sync.Mutex
	entries map[string]*entry // by sessionId/requestId
	order   []*entry
	dropped int
	// Chrome may send a request's or response's ExtraInfo (the headers as sent, cookies included) before the
	// event it belongs to; those headers wait here, by sessionId/requestId.
	earlyReq, earlyRes map[string]map[string]string
}

type entry struct {
	key      string
	started  time.Time
	resType  string
	method   string
	url      string
	reqHdrs  map[string]string
	postData string
	postMime string
	status   int
	statusTx string
	resHdrs  map[string]string
	resMime  string
	body     string
	base64   bool
	sse      strings.Builder
	ws       []wsFrame
	failed   string
}

type wsFrame struct {
	Type   string  `json:"type"`
	Time   float64 `json:"time"`
	Opcode int     `json:"opcode"`
	Data   string  `json:"data"`
}

func newRecorder() *recorder {
	return &recorder{entries: map[string]*entry{}, earlyReq: map[string]map[string]string{},
		earlyRes: map[string]map[string]string{}}
}

// early keeps ExtraInfo headers that arrived before their event, bounded like the entries.
func (r *recorder) early(into map[string]map[string]string, session, id string, h map[string]string) {
	key := session + "/" + id
	if into[key] == nil {
		if len(into) >= maxEntries {
			return
		}
		into[key] = map[string]string{}
	}
	for k, v := range h {
		into[key][k] = v
	}
}

// takeEarly merges and forgets the early headers for key into hdrs.
func takeEarly(from map[string]map[string]string, key string, hdrs map[string]string) {
	for k, v := range from[key] {
		hdrs[k] = v
	}
	delete(from, key)
}

func (r *recorder) get(session, id string) *entry {
	return r.entries[session+"/"+id]
}

func (r *recorder) start(session, id string, e *entry) {
	if len(r.order) >= maxEntries {
		r.dropped++
		return
	}
	e.key = session + "/" + id
	r.entries[e.key] = e
	r.order = append(r.order, e)
	takeEarly(r.earlyReq, e.key, e.reqHdrs)
}

type cdpHeaders map[string]any

func (h cdpHeaders) flat() map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		if s, ok := v.(string); ok {
			out[k] = s
		}
	}
	return out
}

func wall(sec float64) time.Time {
	if sec <= 0 {
		return time.Now().UTC()
	}
	return time.Unix(0, int64(sec*float64(time.Second))).UTC()
}

// handle records one Network event; it reports a requestId whose body is ready to fetch.
func (r *recorder) handle(ev event) (bodyFor string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	switch ev.Method {
	case "Network.requestWillBeSent":
		var p struct {
			RequestID string  `json:"requestId"`
			WallTime  float64 `json:"wallTime"`
			Type      string  `json:"type"`
			Request   struct {
				URL      string     `json:"url"`
				Method   string     `json:"method"`
				Headers  cdpHeaders `json:"headers"`
				PostData string     `json:"postData"`
			} `json:"request"`
			RedirectResponse *cdpResponse `json:"redirectResponse"`
		}
		if json.Unmarshal(ev.Params, &p) != nil {
			return ""
		}
		if prev := r.get(ev.SessionID, p.RequestID); prev != nil && p.RedirectResponse != nil {
			prev.response(*p.RedirectResponse)
			delete(r.entries, prev.key) // the redirect's next hop reuses the requestId
		}
		hdrs := p.Request.Headers.flat()
		r.start(ev.SessionID, p.RequestID, &entry{started: wall(p.WallTime), resType: strings.ToLower(p.Type),
			method: p.Request.Method, url: p.Request.URL, reqHdrs: hdrs, postData: p.Request.PostData,
			postMime: header(hdrs, "content-type")})
	case "Network.requestWillBeSentExtraInfo": // the headers as sent, cookies included
		var p struct {
			RequestID string     `json:"requestId"`
			Headers   cdpHeaders `json:"headers"`
		}
		if json.Unmarshal(ev.Params, &p) == nil {
			if e := r.get(ev.SessionID, p.RequestID); e != nil {
				for k, v := range p.Headers.flat() {
					e.reqHdrs[k] = v
				}
			} else {
				r.early(r.earlyReq, ev.SessionID, p.RequestID, p.Headers.flat())
			}
		}
	case "Network.responseReceived":
		var p struct {
			RequestID string      `json:"requestId"`
			Type      string      `json:"type"`
			Response  cdpResponse `json:"response"`
		}
		if json.Unmarshal(ev.Params, &p) == nil {
			if e := r.get(ev.SessionID, p.RequestID); e != nil {
				e.response(p.Response)
				takeEarly(r.earlyRes, e.key, e.resHdrs)
				if p.Type != "" {
					e.resType = strings.ToLower(p.Type)
				}
			}
		}
	case "Network.responseReceivedExtraInfo":
		var p struct {
			RequestID string     `json:"requestId"`
			Headers   cdpHeaders `json:"headers"`
		}
		if json.Unmarshal(ev.Params, &p) == nil {
			if e := r.get(ev.SessionID, p.RequestID); e != nil && e.resHdrs != nil {
				for k, v := range p.Headers.flat() {
					e.resHdrs[k] = v
				}
			} else {
				r.early(r.earlyRes, ev.SessionID, p.RequestID, p.Headers.flat())
			}
		}
	case "Network.loadingFinished":
		var p struct {
			RequestID string `json:"requestId"`
		}
		if json.Unmarshal(ev.Params, &p) == nil {
			if e := r.get(ev.SessionID, p.RequestID); e != nil && wantsBody(e) {
				return p.RequestID
			}
		}
	case "Network.loadingFailed":
		var p struct {
			RequestID string `json:"requestId"`
			ErrorText string `json:"errorText"`
		}
		if json.Unmarshal(ev.Params, &p) == nil {
			if e := r.get(ev.SessionID, p.RequestID); e != nil {
				e.failed = p.ErrorText
			}
		}
	case "Network.webSocketCreated":
		var p struct {
			RequestID string `json:"requestId"`
			URL       string `json:"url"`
		}
		if json.Unmarshal(ev.Params, &p) == nil {
			r.start(ev.SessionID, p.RequestID, &entry{started: time.Now().UTC(), resType: "websocket", method: "GET",
				url: p.URL, reqHdrs: map[string]string{}})
		}
	case "Network.webSocketWillSendHandshakeRequest":
		var p struct {
			RequestID string `json:"requestId"`
			Request   struct {
				Headers cdpHeaders `json:"headers"`
			} `json:"request"`
		}
		if json.Unmarshal(ev.Params, &p) == nil {
			if e := r.get(ev.SessionID, p.RequestID); e != nil {
				e.reqHdrs = p.Request.Headers.flat()
			}
		}
	case "Network.webSocketHandshakeResponseReceived":
		var p struct {
			RequestID string      `json:"requestId"`
			Response  cdpResponse `json:"response"`
		}
		if json.Unmarshal(ev.Params, &p) == nil {
			if e := r.get(ev.SessionID, p.RequestID); e != nil {
				e.response(p.Response)
			}
		}
	case "Network.webSocketFrameSent", "Network.webSocketFrameReceived":
		var p struct {
			RequestID string  `json:"requestId"`
			Timestamp float64 `json:"timestamp"`
			Response  struct {
				Opcode      int    `json:"opcode"`
				PayloadData string `json:"payloadData"`
			} `json:"response"`
		}
		if json.Unmarshal(ev.Params, &p) == nil {
			if e := r.get(ev.SessionID, p.RequestID); e != nil && len(e.ws) < maxWSFrames {
				kind := "receive"
				if ev.Method == "Network.webSocketFrameSent" {
					kind = "send"
				}
				e.ws = append(e.ws, wsFrame{Type: kind, Time: p.Timestamp, Opcode: p.Response.Opcode, Data: clip(p.Response.PayloadData)})
			}
		}
	case "Network.eventSourceMessageReceived":
		var p struct {
			RequestID string `json:"requestId"`
			EventName string `json:"eventName"`
			EventID   string `json:"eventId"`
			Data      string `json:"data"`
		}
		if json.Unmarshal(ev.Params, &p) == nil {
			if e := r.get(ev.SessionID, p.RequestID); e != nil && e.sse.Len() < maxBodyBytes {
				if p.EventName != "" && p.EventName != "message" {
					e.sse.WriteString("event: " + p.EventName + "\n")
				}
				e.sse.WriteString("data: " + p.Data + "\n\n")
			}
		}
	}
	return ""
}

type cdpResponse struct {
	Status     int        `json:"status"`
	StatusText string     `json:"statusText"`
	Headers    cdpHeaders `json:"headers"`
	MimeType   string     `json:"mimeType"`
}

func (e *entry) response(r cdpResponse) {
	e.status, e.statusTx, e.resHdrs, e.resMime = r.Status, r.StatusText, r.Headers.flat(), r.MimeType
}

// wantsBody: API calls and the page itself, not scripts, images, fonts, media or styles. A site's JS bundles are
// most of a capture's weight (39 of 51 MB on a retail site) and the adaptor builder reads none of them.
func wantsBody(e *entry) bool {
	switch e.resType {
	case "xhr", "fetch", "eventsource", "document", "other":
		return true
	case "script", "stylesheet", "image", "font", "media":
		return false
	}
	m := strings.ToLower(e.resMime)
	return strings.Contains(m, "json") || strings.Contains(m, "event-stream") || strings.Contains(m, "text/plain")
}

func (r *recorder) setBody(session, id, body string, b64 bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e := r.get(session, id); e != nil {
		if b64 && textual(e.resMime) {
			body, b64 = decodeBody(body, true), false
		}
		if len(body) > maxBodyBytes {
			body, b64 = body[:maxBodyBytes], false
		}
		e.body, e.base64 = body, b64
	}
}

func textual(mime string) bool {
	m := strings.ToLower(mime)
	return strings.HasPrefix(m, "text/") || strings.Contains(m, "json") || strings.Contains(m, "javascript") || strings.Contains(m, "xml")
}

func clip(s string) string {
	if len(s) > maxBodyBytes {
		return s[:maxBodyBytes]
	}
	return s
}

func header(h map[string]string, name string) string {
	for k, v := range h {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

// Stats summarise a capture for the person.
type Stats struct {
	Requests int `json:"requests"`
	API      int `json:"api"` // xhr, fetch, websocket and event streams
	Dropped  int `json:"dropped"`
}

// har is the recording as a HAR 1.2 document, redacted.
func (r *recorder) har(version string) ([]byte, Stats) {
	r.mu.Lock()
	defer r.mu.Unlock()
	entries := make([]map[string]any, 0, len(r.order))
	st := Stats{Requests: len(r.order), Dropped: r.dropped}
	order := append([]*entry(nil), r.order...)
	sort.SliceStable(order, func(i, j int) bool { return order[i].started.Before(order[j].started) })
	for _, e := range order {
		switch e.resType {
		case "xhr", "fetch", "websocket", "eventsource":
			st.API++
		}
		req := map[string]any{"method": e.method, "url": e.url, "httpVersion": "", "headers": harHeaders(e.reqHdrs),
			"queryString": []any{}, "cookies": []any{}, "headersSize": -1, "bodySize": len(e.postData)}
		if e.postData != "" {
			req["postData"] = map[string]any{"mimeType": e.postMime, "text": redactBody(e.postData, e.postMime)}
		}
		text, mime := e.body, e.resMime
		if e.sse.Len() > 0 {
			text, mime = e.sse.String(), "text/event-stream"
		}
		content := map[string]any{"size": len(text), "mimeType": mime}
		if text != "" {
			if e.base64 {
				content["text"], content["encoding"] = text, "base64"
			} else {
				content["text"] = redactBody(text, mime)
			}
		}
		res := map[string]any{"status": e.status, "statusText": e.statusTx, "httpVersion": "",
			"headers": harHeaders(e.resHdrs), "cookies": []any{}, "content": content, "redirectURL": "",
			"headersSize": -1, "bodySize": -1}
		if e.failed != "" {
			res["_error"] = e.failed
		}
		item := map[string]any{"startedDateTime": e.started.Format(time.RFC3339Nano), "time": 0,
			"request": req, "response": res, "cache": map[string]any{}, "timings": map[string]any{"send": 0, "wait": 0, "receive": 0},
			"_resourceType": e.resType}
		if len(e.ws) > 0 {
			frames := make([]wsFrame, len(e.ws))
			for i, f := range e.ws {
				f.Data = redactBody(f.Data, "application/json")
				frames[i] = f
			}
			item["_webSocketMessages"] = frames
		}
		entries = append(entries, item)
	}
	doc := map[string]any{"log": map[string]any{"version": "1.2",
		"creator": map[string]any{"name": "ascend-agent", "version": version}, "entries": entries}}
	return encode(doc), st
}

// ---- redaction: secret values never leave the machine; names stay, for the adaptor builder ------------------

var (
	secretKey   = regexp.MustCompile(`(?i)(pass(word|wd)?|pwd|secret|otp|mfa|totp|token|api[-_]?key|private[-_]?key|client[-_]?secret|session[-_]?id|credential)`)
	tokenHeader = regexp.MustCompile(`(?i)^(x-api-key|api-key|x-auth-token|x-access-token|x-csrf-token|x-xsrf-token|x-amz-security-token)$`)
)

const redacted = "<redacted>"

func harHeaders(h map[string]string) []map[string]string {
	names := make([]string, 0, len(h))
	for k := range h {
		names = append(names, k)
	}
	sort.Strings(names)
	out := make([]map[string]string, 0, len(names))
	for _, k := range names {
		out = append(out, map[string]string{"name": k, "value": redactHeader(k, h[k])})
	}
	return out
}

func redactHeader(name, value string) string {
	switch low := strings.ToLower(name); {
	case low == "cookie":
		parts := strings.Split(value, ";")
		for i, p := range parts {
			if n, _, ok := strings.Cut(p, "="); ok {
				parts[i] = strings.TrimSpace(n) + "=" + redacted
			}
		}
		return strings.Join(parts, "; ")
	case low == "set-cookie":
		lines := strings.Split(value, "\n")
		for i, l := range lines {
			if n, _, ok := strings.Cut(l, "="); ok {
				lines[i] = strings.TrimSpace(n) + "=" + redacted
			}
		}
		return strings.Join(lines, "\n")
	case low == "authorization" || low == "proxy-authorization":
		if scheme, _, ok := strings.Cut(value, " "); ok && len(scheme) <= 16 {
			return scheme + " " + redacted
		}
		return redacted
	case tokenHeader.MatchString(low):
		return redacted
	}
	return value
}

// redactBody replaces the values of secret-looking keys in form and JSON bodies: a login typed into the capture
// browser must not leave the machine.
func redactBody(text, mime string) string {
	m := strings.ToLower(mime)
	switch {
	case strings.Contains(m, "x-www-form-urlencoded"):
		vals, err := url.ParseQuery(text)
		if err != nil {
			return text
		}
		changed := false
		for k := range vals {
			if secretKey.MatchString(k) {
				vals[k] = []string{redacted}
				changed = true
			}
		}
		if changed {
			return vals.Encode()
		}
		return text
	case strings.Contains(m, "json") || strings.HasPrefix(strings.TrimSpace(text), "{") || strings.HasPrefix(strings.TrimSpace(text), "["):
		var v any
		if json.Unmarshal([]byte(text), &v) != nil {
			return text
		}
		if redactJSON(v) {
			out, err := json.Marshal(v)
			if err == nil {
				return string(out)
			}
		}
	}
	return text
}

func redactJSON(v any) bool {
	changed := false
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			if secretKey.MatchString(k) {
				if _, isObj := x.(map[string]any); !isObj {
					t[k] = redacted
					changed = true
					continue
				}
			}
			if redactJSON(x) {
				changed = true
			}
		}
	case []any:
		for _, x := range t {
			if redactJSON(x) {
				changed = true
			}
		}
	}
	return changed
}

func decodeBody(body string, b64 bool) string {
	if !b64 {
		return body
	}
	raw, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		return body
	}
	return string(raw)
}

func encode(doc any) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false) // "<redacted>", not "\u003credacted\u003e"
	_ = enc.Encode(doc)
	return bytes.TrimSpace(buf.Bytes())
}

// MaxUploadBytes keeps a HAR under what Straiker accepts (32 MiB decoded), with room to spare.
const MaxUploadBytes = 24 << 20

var apiTypes = map[string]bool{"xhr": true, "fetch": true, "websocket": true, "eventsource": true}

// Shrink makes any HAR (a capture, or a DevTools export) fit for upload: response bodies of scripts, styles, images,
// fonts and media are dropped, and if it is still over max, the largest other non-API bodies go next. Requests,
// headers and API bodies are kept. dropped counts the bodies removed.
func Shrink(raw []byte, max int) (out []byte, dropped int, err error) {
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, 0, fmt.Errorf("not a HAR: %w", err)
	}
	log, _ := doc["log"].(map[string]any)
	list, _ := log["entries"].([]any)
	if log == nil || list == nil {
		return nil, 0, errors.New("not a HAR: no log.entries")
	}
	type body struct {
		content map[string]any
		size    int
	}
	var droppable []body
	for _, e := range list {
		em, _ := e.(map[string]any)
		res, _ := em["response"].(map[string]any)
		content, _ := res["content"].(map[string]any)
		text, _ := content["text"].(string)
		if text == "" {
			continue
		}
		kind, _ := em["_resourceType"].(string)
		kind = strings.ToLower(kind)
		mime, _ := content["mimeType"].(string)
		switch {
		case kind == "script" || kind == "stylesheet" || kind == "image" || kind == "font" || kind == "media" ||
			(kind == "" && staticMime(mime)):
			delete(content, "text")
			delete(content, "encoding")
			dropped++
		case !apiTypes[kind]:
			droppable = append(droppable, body{content, len(text)})
		}
	}
	out = encode(doc)
	sort.Slice(droppable, func(i, j int) bool { return droppable[i].size > droppable[j].size })
	for _, b := range droppable {
		if len(out) <= max {
			break
		}
		delete(b.content, "text")
		delete(b.content, "encoding")
		dropped++
		out = encode(doc)
	}
	if len(out) > max {
		return nil, dropped, fmt.Errorf("the HAR is %d MB even without page assets; record a shorter session", len(out)>>20)
	}
	return out, dropped, nil
}

func staticMime(mime string) bool {
	m := strings.ToLower(mime)
	return strings.Contains(m, "javascript") || strings.HasPrefix(m, "text/css") || strings.HasPrefix(m, "image/") ||
		strings.HasPrefix(m, "font/") || strings.HasPrefix(m, "audio/") || strings.HasPrefix(m, "video/")
}
