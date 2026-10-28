package netx

import (
	"strings"
	"testing"
)

func TestRedactDropsProxyCredentials(t *testing.T) {
	// The passwords with #, ? or / are the ones url.Parse fails on or splits in the wrong place.
	cases := map[string]string{
		"http://user:secret@proxy.corp:8080":  "http://redacted@proxy.corp:8080",
		"http://user:se#cret@proxy.corp:8080": "http://redacted@proxy.corp:8080",
		"http://user:se?cret@proxy.corp:8080": "http://redacted@proxy.corp:8080",
		"http://user:se/cret@proxy.corp:8080": "http://redacted@proxy.corp:8080",
		"http://user:se@cret@proxy.corp:8080": "http://redacted@proxy.corp:8080",
		"user:secret@proxy.corp:8080":         "redacted@proxy.corp:8080", // HTTPS_PROXY without a scheme
		"http://proxy.corp:8080":              "http://proxy.corp:8080",
	}
	for in, want := range cases {
		if got := Redact(in); got != want || strings.Contains(got, "cret") {
			t.Errorf("Redact(%q) = %q, want %q: a proxy password must never reach a log", in, got, want)
		}
	}
}
