package browser

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func ev(session, method, params string) event {
	return event{Method: method, Params: json.RawMessage(params), SessionID: session}
}

func harOf(t *testing.T, r *recorder) map[string]any {
	t.Helper()
	raw, _ := r.har("test")
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func entries(doc map[string]any) []map[string]any {
	var out []map[string]any
	for _, e := range doc["log"].(map[string]any)["entries"].([]any) {
		out = append(out, e.(map[string]any))
	}
	return out
}

func TestAChatCallIsRecordedAndItsSecretsStayHere(t *testing.T) {
	r := newRecorder()
	r.handle(ev("s1", "Network.requestWillBeSent", `{"requestId":"1","wallTime":1761500000.5,"type":"Fetch",
		"request":{"url":"https://chat.example.com/api/messages","method":"POST",
		"headers":{"Content-Type":"application/json","Authorization":"Bearer eyJhbGciOi.secret.sig"},
		"postData":"{\"message\":\"hello\",\"session_token\":\"abc123\",\"user\":{\"password\":\"hunter2\"}}"}}`))
	r.handle(ev("s1", "Network.requestWillBeSentExtraInfo", `{"requestId":"1","headers":{"Cookie":"sid=s3cr3t; theme=dark","X-Api-Key":"k-123"}}`))
	r.handle(ev("s1", "Network.responseReceived", `{"requestId":"1","type":"Fetch","response":{"status":200,"statusText":"OK",
		"headers":{"Content-Type":"application/json"},"mimeType":"application/json"}}`))
	r.handle(ev("s1", "Network.responseReceivedExtraInfo", `{"requestId":"1","headers":{"Set-Cookie":"sid=new-s3cr3t; Path=/"}}`))
	if id := r.handle(ev("s1", "Network.loadingFinished", `{"requestId":"1"}`)); id != "1" {
		t.Fatal("an API response's body is fetched")
	}
	body := base64.StdEncoding.EncodeToString([]byte(`{"reply":"Hi! How can I help?","access_token":"tok-9"}`))
	r.setBody("s1", "1", body, true)

	doc := harOf(t, r)
	raw, _ := r.har("test")
	for _, secret := range []string{"hunter2", "abc123", "s3cr3t", "eyJhbGciOi", "k-123", "tok-9"} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("%q left the machine", secret)
		}
	}
	for _, kept := range []string{"hello", "Hi! How can I help?", "sid=<redacted>", "theme=<redacted>", "Bearer <redacted>", `"_resourceType":"fetch"`} {
		if !strings.Contains(string(raw), kept) {
			t.Errorf("%q is what the builder needs; it is missing", kept)
		}
	}
	e := entries(doc)[0]
	if e["startedDateTime"].(string)[:4] != "2025" || e["response"].(map[string]any)["status"].(float64) != 200 {
		t.Fatalf("entry: %v", e)
	}
}

// Chrome may send ExtraInfo before the event it belongs to; the cookies still reach the HAR, redacted.
func TestHeadersThatArriveEarlyAreKept(t *testing.T) {
	r := newRecorder()
	r.handle(ev("s1", "Network.requestWillBeSentExtraInfo", `{"requestId":"1","headers":{"Cookie":"sid=s3cr3t"}}`))
	r.handle(ev("s1", "Network.requestWillBeSent", `{"requestId":"1","type":"Fetch",
		"request":{"url":"https://chat.example.com/api/chat","method":"POST","headers":{}}}`))
	r.handle(ev("s1", "Network.responseReceivedExtraInfo", `{"requestId":"1","headers":{"Set-Cookie":"session=n3w; Path=/"}}`))
	r.handle(ev("s1", "Network.responseReceived", `{"requestId":"1","type":"Fetch","response":{"status":200,
		"headers":{"Content-Type":"application/json"},"mimeType":"application/json"}}`))
	raw, _ := r.har("test")
	for _, kept := range []string{"sid=<redacted>", "session=<redacted>"} {
		if !strings.Contains(string(raw), kept) {
			t.Errorf("%q is missing", kept)
		}
	}
	if strings.Contains(string(raw), "s3cr3t") || strings.Contains(string(raw), "n3w") {
		t.Error("a cookie value left the machine")
	}
	if len(r.earlyReq) != 0 || len(r.earlyRes) != 0 {
		t.Error("early headers are forgotten once used")
	}
}

func TestStreamsAreRecorded(t *testing.T) {
	r := newRecorder()
	r.handle(ev("s2", "Network.webSocketCreated", `{"requestId":"w","url":"wss://chat.example.com/ws"}`))
	r.handle(ev("s2", "Network.webSocketHandshakeResponseReceived", `{"requestId":"w","response":{"status":101,"statusText":"Switching Protocols","headers":{}}}`))
	r.handle(ev("s2", "Network.webSocketFrameSent", `{"requestId":"w","timestamp":1,"response":{"opcode":1,"payloadData":"{\"text\":\"hi\",\"token\":\"t-1\"}"}}`))
	r.handle(ev("s2", "Network.webSocketFrameReceived", `{"requestId":"w","timestamp":2,"response":{"opcode":1,"payloadData":"{\"answer\":\"hello\"}"}}`))
	r.handle(ev("s2", "Network.requestWillBeSent", `{"requestId":"e","type":"EventSource","request":{"url":"https://chat.example.com/sse","method":"GET","headers":{}}}`))
	r.handle(ev("s2", "Network.eventSourceMessageReceived", `{"requestId":"e","eventName":"delta","data":"{\"t\":\"Hel\"}"}`))
	r.handle(ev("s2", "Network.eventSourceMessageReceived", `{"requestId":"e","eventName":"message","data":"done"}`))
	es := entries(harOf(t, r))
	ws := es[0]["_webSocketMessages"].([]any)
	if len(ws) != 2 || ws[0].(map[string]any)["type"] != "send" || strings.Contains(ws[0].(map[string]any)["data"].(string), "t-1") {
		t.Fatalf("frames: %v", ws)
	}
	content := es[1]["response"].(map[string]any)["content"].(map[string]any)
	if content["mimeType"] != "text/event-stream" || content["text"] != "event: delta\ndata: {\"t\":\"Hel\"}\n\ndata: done\n\n" {
		t.Fatalf("sse: %v", content)
	}
}

func TestARedirectKeepsBothHops(t *testing.T) {
	r := newRecorder()
	r.handle(ev("s", "Network.requestWillBeSent", `{"requestId":"r","type":"Document","request":{"url":"https://a.example/","method":"GET","headers":{}}}`))
	r.handle(ev("s", "Network.requestWillBeSent", `{"requestId":"r","type":"Document","request":{"url":"https://a.example/home","method":"GET","headers":{}},
		"redirectResponse":{"status":302,"statusText":"Found","headers":{"Location":"/home"}}}`))
	r.handle(ev("s", "Network.responseReceived", `{"requestId":"r","type":"Document","response":{"status":200,"headers":{},"mimeType":"text/html"}}`))
	es := entries(harOf(t, r))
	if len(es) != 2 || es[0]["response"].(map[string]any)["status"].(float64) != 302 || es[1]["response"].(map[string]any)["status"].(float64) != 200 {
		t.Fatalf("hops: %v", es)
	}
}

func TestFormLoginsAreRedacted(t *testing.T) {
	got := redactBody("username=yg&password=hunter2&otp=123456", "application/x-www-form-urlencoded")
	if strings.Contains(got, "hunter2") || strings.Contains(got, "123456") || !strings.Contains(got, "username=yg") {
		t.Fatal(got)
	}
}

func harDoc(entries ...map[string]any) []byte {
	list := make([]any, len(entries))
	for i, e := range entries {
		list[i] = e
	}
	raw, _ := json.Marshal(map[string]any{"log": map[string]any{"entries": list}})
	return raw
}

func withBody(kind, mime string, size int) map[string]any {
	e := map[string]any{"request": map[string]any{"url": "https://x/" + kind},
		"response": map[string]any{"content": map[string]any{"mimeType": mime, "text": strings.Repeat("a", size)}}}
	if kind != "" {
		e["_resourceType"] = kind
	}
	return e
}

func TestShrinkKeepsWhatTheBuilderReads(t *testing.T) {
	raw := harDoc(withBody("script", "application/javascript", 300_000), withBody("fetch", "application/json", 1000),
		withBody("", "text/css", 5000), withBody("document", "text/html", 2000))
	out, dropped, err := Shrink(raw, 1<<20)
	if err != nil || dropped != 2 {
		t.Fatalf("dropped %d, %v", dropped, err)
	}
	if strings.Count(string(out), "a") < 3000 || strings.Count(string(out), "a") > 3100 || len(out) > 10_000 {
		t.Fatalf("the API and page bodies stay, the assets go: %d bytes", len(out))
	}
	big := harDoc(withBody("fetch", "application/json", 1000), withBody("document", "text/html", 50_000),
		withBody("document", "text/html", 40_000))
	out, dropped, err = Shrink(big, 50_000)
	if err != nil || dropped != 1 || !strings.Contains(string(out), strings.Repeat("a", 40_000)) {
		t.Fatalf("over the cap, the largest non-API body goes first: dropped %d %v", dropped, err)
	}
	if _, _, err := Shrink(harDoc(withBody("fetch", "application/json", 60_000)), 10_000); err == nil {
		t.Fatal("API bodies are never dropped; too big is an error")
	}
	if _, _, err := Shrink([]byte(`{"nope":1}`), 1000); err == nil {
		t.Fatal("not a HAR")
	}
}
