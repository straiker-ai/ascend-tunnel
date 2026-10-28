package stream

import (
	"strings"
	"testing"
)

// FuzzSSEParser feeds arbitrary event-stream text, a line at a time as streamOnce does. Every event it
// emits has a type, and no event id carries a NUL (the format says such an id is ignored).
func FuzzSSEParser(f *testing.F) {
	for _, seed := range []string{
		"event: call\ndata: {\"a\":1}\nid: 7\n\n",
		"data: one\ndata: two\n\n",
		": heartbeat\n\n",
		"id: a\x00b\ndata: x\n\n",
		"event\ndata\n\n\n",
		"data:{}\n\nevent: x\n",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, stream string) {
		var p sseParser
		for _, line := range strings.Split(stream, "\n") {
			ev, ok := p.line(strings.TrimSuffix(line, "\r"))
			if !ok {
				continue
			}
			if ev.Event == "" {
				t.Fatalf("event without a type: %+v", ev)
			}
			if strings.Contains(ev.ID, "\x00") {
				t.Fatalf("event id with a NUL: %q", ev.ID)
			}
		}
	})
}
