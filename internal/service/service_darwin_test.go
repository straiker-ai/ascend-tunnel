//go:build darwin

package service

import (
	"strings"
	"testing"
)

func TestTheLaunchAgentRunsTheCommandAsGivenAndKeepsItAlive(t *testing.T) {
	p := string(plist(Spec{Exe: "/opt/homebrew/bin/ascend-tunnel", Args: []string{"run", "--org", "1", "--host-key", "ssh-ed25519 AAAA<&>"},
		Env: []string{"HTTPS_PROXY=http://proxy:8080"}}, "/tmp/s/service.log"))
	for _, want := range []string{"<string>ai.straiker.ascend-tunnel</string>", "<string>/opt/homebrew/bin/ascend-tunnel</string><string>run</string>",
		"<string>ssh-ed25519 AAAA&lt;&amp;&gt;</string>", "<key>HTTPS_PROXY</key><string>http://proxy:8080</string>",
		"<key>KeepAlive</key><true/>", "<key>RunAtLoad</key><true/>", "<string>/tmp/s/service.log</string>"} {
		if !strings.Contains(p, want) {
			t.Fatalf("missing %s in\n%s", want, p)
		}
	}
}
