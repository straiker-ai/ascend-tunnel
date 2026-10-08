package agent

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Audit writes one JSON line per event to the audit log and to out (stdout): identity, links,
// forwards, and one line per connection - when, where, how many bytes.
type Audit struct {
	mu   sync.Mutex
	path string
	out  io.Writer
	now  func() time.Time
}

// NewAudit returns an audit writer to path (may be "") and out.
func NewAudit(path string, out io.Writer) *Audit {
	return &Audit{path: path, out: out, now: time.Now}
}

// Log writes {"ts", "event", k1: v1, ...} with keys in the order given.
func (a *Audit) Log(event string, kv ...any) {
	var b strings.Builder
	b.WriteString(`{"ts":`)
	writeJSON(&b, a.now().UTC().Format("2006-01-02T15:04:05.000000-07:00"))
	b.WriteString(`,"event":`)
	writeJSON(&b, event)
	for i := 0; i+1 < len(kv); i += 2 {
		b.WriteByte(',')
		k, _ := kv[i].(string)
		writeJSON(&b, k)
		b.WriteByte(':')
		writeJSON(&b, kv[i+1])
	}
	b.WriteString("}\n")
	line := b.String()

	a.mu.Lock()
	defer a.mu.Unlock()
	if a.path != "" {
		// Best-effort, like any log: an unwritable file must not stop the tunnel.
		if err := os.MkdirAll(filepath.Dir(a.path), 0o700); err == nil {
			if f, err := os.OpenFile(a.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600); err == nil {
				_, _ = f.WriteString(line)
				_ = f.Close()
			}
		}
	}
	if a.out != nil {
		_, _ = io.WriteString(a.out, line)
	}
}

func writeJSON(b *strings.Builder, v any) {
	if err, ok := v.(error); ok {
		v = err.Error()
	}
	data, err := json.Marshal(v)
	if err != nil {
		data, _ = json.Marshal(err.Error())
	}
	b.Write(data)
}
