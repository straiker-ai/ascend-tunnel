package service

import (
	"strings"
	"testing"
)

func TestTheServiceGetsTheInstallersProxyButNeverAPassword(t *testing.T) {
	env := map[string]string{"HTTPS_PROXY": "http://proxy.corp:8080", "NO_PROXY": "localhost,.corp"}
	got, err := ProxyEnv(func(k string) string { return env[k] })
	if err != nil || strings.Join(got, ";") != "HTTPS_PROXY=http://proxy.corp:8080;NO_PROXY=localhost,.corp" {
		t.Fatalf("%v %v", got, err)
	}
	env["HTTPS_PROXY"] = "http://me:secret@proxy.corp:8080"
	if _, err := ProxyEnv(func(k string) string { return env[k] }); err == nil || !strings.Contains(err.Error(), "password") {
		t.Fatalf("a proxy password is refused: %v", err)
	}
}
