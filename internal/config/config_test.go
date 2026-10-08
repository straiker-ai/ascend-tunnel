package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func noEnv(string) string { return "" }

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "agent.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestAFileConfig(t *testing.T) {
	p := writeConfig(t, `
tenant: 1234
relay: wss://relay.example/tunnel
host_key: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMk8CisV24CYS6k/jtJCKqtwmUyFXsWrG1h+R7Z6P7KM
state_dir: /tmp/state
fanout: 2
allow:
  - { host: Chat.Corp.Internal., port: 443 }
  - api.corp:8080
`)
	c, err := Load(p, Overrides{}, noEnv)
	if err != nil {
		t.Fatal(err)
	}
	if c.Tenant != "1234" {
		t.Errorf("an unquoted numeric org id is still the string %q, got %q", "1234", c.Tenant)
	}
	if c.Relay != "wss://relay.example/tunnel" || c.Fanout != 2 || c.StateDir != "/tmp/state" {
		t.Errorf("unexpected %+v", c)
	}
	if c.AuditLog != filepath.Join("/tmp/state", "connections.jsonl") {
		t.Errorf("audit log defaults beside the state, got %s", c.AuditLog)
	}
	want := []Forward{{"chat.corp.internal", 443}, {"api.corp", 8080}}
	if len(c.Forwards) != 2 || c.Forwards[0] != want[0] || c.Forwards[1] != want[1] {
		t.Errorf("forwards %v, want %v", c.Forwards, want)
	}
}

func TestFlagsOverrideEnvOverridesFile(t *testing.T) {
	p := writeConfig(t, "tenant: '1'\nrelay: wss://file/t\nfanout: 2\nallow: [ 'a.corp:1' ]\n")
	env := map[string]string{"TUNNEL_TENANT": "2", "TUNNEL_RELAY": "wss://env/t", "TUNNEL_FANOUT": "3"}
	c, err := Load(p, Overrides{Tenant: "3", Allow: []string{"b.corp:2"}}, func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	if c.Tenant != "3" || c.Relay != "wss://env/t" || c.Fanout != 3 || c.Forwards[0].Host != "b.corp" {
		t.Errorf("precedence flag > env > file broken: %+v", c)
	}
}

func TestNoFileAndNoRelayUsesTheBuiltInEnvironment(t *testing.T) {
	c, err := Load("", Overrides{Tenant: "1234", Allow: []string{"chat.corp:443"}}, noEnv)
	if err != nil {
		t.Fatal(err)
	}
	if c.Relay != Environments[DefaultEnv].Relay {
		t.Errorf("relay %s, want the %s relay", c.Relay, DefaultEnv)
	}
	if c.StateDir == "" || c.AuditLog == "" {
		t.Error("state dir and audit log need defaults")
	}
	if _, err := Load("", Overrides{Tenant: "1", Env: "nowhere", Allow: []string{"h:1"}}, noEnv); err == nil {
		t.Error("an unknown environment is refused")
	}
}

func TestABadConfigIsRefused(t *testing.T) {
	long := strings.Repeat("a", 90) + ".corp:443"
	cases := []struct {
		name string
		o    Overrides
		want string
	}{
		{"no org id", Overrides{Relay: "wss://x/t", Allow: []string{"h:1"}}, "tenant"},
		{"bad org id", Overrides{Tenant: "a b", Relay: "wss://x/t", Allow: []string{"h:1"}}, "tenant"},
		{"plain https relay", Overrides{Tenant: "1", Relay: "https://x/", Allow: []string{"h:1"}}, "wss://"},
		{"no allowlist", Overrides{Tenant: "1", Relay: "wss://x/t"}, "at least one"},
		{"no port", Overrides{Tenant: "1", Relay: "wss://x/t", Allow: []string{"h"}}, "allow[0]"},
		{"path in host", Overrides{Tenant: "1", Relay: "wss://x/t", Allow: []string{"../../etc:443"}}, "invalid forward"},
		{"tilde in host", Overrides{Tenant: "1", Relay: "wss://x/t", Allow: []string{"a~b:443"}}, "invalid forward"},
		{"port out of range", Overrides{Tenant: "1", Relay: "wss://x/t", Allow: []string{"h:70000"}}, "invalid forward"},
		{"same host twice", Overrides{Tenant: "1", Relay: "wss://x/t", Allow: []string{"h:443", "H:80"}}, "one allow entry"},
		{"fanout too high", Overrides{Tenant: "1", Relay: "wss://x/t", Fanout: 99, Allow: []string{"h:1"}}, "fanout must be"},
		{"host too long for a socket", Overrides{Tenant: "1", Relay: "wss://x/t", Allow: []string{long}}, "too long"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load("", tc.o, noEnv)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want an error containing %q", err, tc.want)
			}
		})
	}
}

func TestAMissingNamedFileIsAnError(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.yaml"), Overrides{Tenant: "1", Allow: []string{"h:1"}}, noEnv); err == nil {
		t.Fatal("a config file that was named but is missing must not be ignored")
	}
}

func TestAllowFromTheEnvironment(t *testing.T) {
	c, err := Load("", Overrides{Tenant: "1"}, func(k string) string {
		return map[string]string{"TUNNEL_ALLOW": "a.corp:443, b.corp:80"}[k]
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Forwards) != 2 || c.Forwards[1] != (Forward{"b.corp", 80}) {
		t.Fatalf("got %v", c.Forwards)
	}
}
