package browser

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// A real browser, headless here, loading a page that calls a JSON API and a WebSocket: the HAR has both.
func TestARealBrowserIsRecorded(t *testing.T) {
	exe, err := Find()
	if err != nil {
		t.Skip("no browser installed:", err)
	}
	extraArgs = []string{"--headless=new"}
	defer func() { extraArgs = nil }()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<title>Chat</title><script>
fetch("/api/chat",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({message:"hello",password:"hun"+"ter2"})})
  .then(r=>r.json()).then(()=>{const ws=new WebSocket("ws://"+location.host+"/ws");ws.onopen=()=>ws.send('{"text":"hi"}')});
</script>`)
	})
	mux.HandleFunc("/api/chat", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "s3cr3t"})
		fmt.Fprint(w, `{"reply":"Hi there"}`)
	})
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer c.CloseNow()
		if _, msg, err := c.Read(r.Context()); err == nil {
			_ = c.Write(r.Context(), websocket.MessageText, []byte(`{"answer":"got `+string(msg)[:4]+`"}`))
		}
		time.Sleep(time.Second)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cp, err := Start(ctx, exe, t.TempDir(), srv.URL+"/", "test")
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		raw, _ := cp.rec.har("test")
		if strings.Contains(string(raw), `answer`) {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	raw, st := cp.Stop()
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for _, want := range []string{`/api/chat`, `Hi there`, `"_webSocketMessages"`, `answer`, `sid=<redacted>`, `message\":\"hello\"`} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %s (stats %+v)", want, st)
		}
	}
	if strings.Contains(s, "hunter2") || strings.Contains(s, "s3cr3t") {
		t.Error("a secret left the machine")
	}
	if st.API < 2 {
		t.Errorf("stats: %+v", st)
	}
}
