package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const good = `
org: "1234"
session_key: AAAA
targets:
  support-bot: { url: https://support.corp.local/chat/ }
  intranet:    { url: "http://10.0.0.5:8080" }
packs: [env, net, http]
agents:
  adaptor-builder: [env.info, net.*, http.probe]
  recon: [http.probe]
limits: { concurrent_calls: 2 }
`

func TestParseGood(t *testing.T) {
	p, err := Parse([]byte(good))
	if err != nil {
		t.Fatal(err)
	}
	if p.Org != "1234" || p.Limits.ConcurrentCalls != 2 || p.Limits.CallsPerMinute != defaultCallsPerMinute {
		t.Fatalf("%+v", p)
	}
	if got := strings.Join(p.TargetIDs(), ","); got != "intranet,support-bot" {
		t.Fatal(got)
	}
	tg, ok := p.Target("support-bot")
	if !ok || tg.Parsed().Host != "support.corp.local" || tg.Parsed().Path != "/chat/" {
		t.Fatal(tg)
	}
	if len(p.Digest()) != 12 {
		t.Fatal(p.Digest())
	}
}

func TestAllowedIsGrantIntersectPolicy(t *testing.T) {
	p, err := Parse([]byte(good))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		agent  string
		grants []string
		tool   string
		want   bool
	}{
		{"adaptor-builder", []string{"env.info"}, "env.info", true},
		{"adaptor-builder", []string{"net.*"}, "net.check", true},
		{"adaptor-builder", []string{"env.info"}, "net.check", false},    // not granted by the cloud
		{"recon", []string{"env.info", "http.probe"}, "env.info", false}, // not listed for this agent
		{"recon", []string{"http.*"}, "http.probe", true},                // both sides cover it
		{"unknown-agent", []string{"env.info"}, "env.info", false},       // agent not in policy
		{"adaptor-builder", []string{"env.*"}, "env", false},             // not a tool name
		{"adaptor-builder", []string{"net.*"}, "network.check", false},   // prefix must end at the dot
		{"adaptor-builder", []string{"capture.*"}, "capture.har", false}, // pack not enabled
		{"adaptor-builder", nil, "env.info", false},                      // no grants
	}
	for _, c := range cases {
		if got := p.Allowed(c.agent, c.grants, c.tool); got != c.want {
			t.Errorf("Allowed(%s, %v, %s) = %v", c.agent, c.grants, c.tool, got)
		}
	}
	if !p.AllowLocal("http.probe") || p.AllowLocal("capture.har") {
		t.Error("AllowLocal must follow the enabled packs")
	}
}

func TestParseRefuses(t *testing.T) {
	bad := map[string]string{
		"unknown key":      "org: '1'\npackz: [env]\n",
		"bad org":          "org: 'a b'\n",
		"bad target id":    "targets:\n  Bad_ID: { url: https://x }\n",
		"ftp target":       "targets:\n  t: { url: ftp://x }\n",
		"no host":          "targets:\n  t: { url: 'https://' }\n",
		"credentials":      "targets:\n  t: { url: 'https://u:p@x' }\n",
		"query":            "targets:\n  t: { url: 'https://x/?a=1' }\n",
		"unknown pack":     "packs: [shell]\n",
		"bad pattern":      "packs: [env]\nagents:\n  a: ['*']\n",
		"pattern bad pack": "packs: [env]\nagents:\n  a: [http.probe]\n",
		"bad agent":        "packs: [env]\nagents:\n  A!: [env.info]\n",
		"too many calls":   "limits: { concurrent_calls: 65 }\n",
		"too high rate":    "limits: { calls_per_minute: 6001 }\n",
		"negative":         "limits: { concurrent_calls: -1 }\n",
		"not yaml":         "org: [\n",
	}
	for name, doc := range bad {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "host.yaml")
	if err := os.WriteFile(path, []byte(good), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path + ".missing"); err == nil {
		t.Fatal("missing file accepted")
	}
}

func TestTheDefaultNeedsNoFile(t *testing.T) {
	p := Default()
	if p.Managed() || len(p.Targets) != 0 || !p.MayApprove("anything.example") {
		t.Fatalf("default: %+v", p)
	}
	if !p.Allowed("adaptor-builder", []string{"http.probe"}, "http.probe") {
		t.Fatal("Straiker's builder may use the default packs")
	}
}

func TestApprovalPatterns(t *testing.T) {
	p, err := Parse([]byte("interactive:\n  allow_hosts: ['*.Example.com', 'chat.vendor.example']\n"))
	if err != nil {
		t.Fatal(err)
	}
	for host, want := range map[string]bool{
		"example.com": true, "www.example.com": true, "WWW.EXAMPLE.COM.": true, "badexample.com": false,
		"chat.vendor.example": true, "api.chat.vendor.example": false, "vendor.example": false,
	} {
		if got := p.MayApprove(host); got != want {
			t.Errorf("%s: %v", host, got)
		}
	}
	if q, _ := Parse([]byte("packs: [env]\n")); q.MayApprove("example.com") || !q.Managed() {
		t.Error("a policy file allows no approvals unless it says so")
	}
	for _, bad := range []string{"'https://a.example'", "'*a.example'", "'x.*'", "'a b'", "''"} {
		if _, err := Parse([]byte("interactive:\n  allow_hosts: [" + bad + "]\n")); err == nil {
			t.Errorf("%s must be refused", bad)
		}
	}
}
