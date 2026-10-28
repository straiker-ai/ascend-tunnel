package config

import (
	"strings"
	"testing"
)

// FuzzParseForwards feeds arbitrary --allow entries (comma-separated here). Whatever it accepts is a
// valid, lower-case host with a port in 1-65535, one entry per host.
func FuzzParseForwards(f *testing.F) {
	for _, seed := range []string{
		"app.internal", "app.internal:8443", "[::1]:443", "a,b:80", "A.EXAMPLE.:443",
		"app.internal\x00", "app.internal\x008080", "host:0", "host:65536", ":443", "a,a:80",
	} {
		f.Add(seed, uint8(1))
	}

	f.Fuzz(func(t *testing.T, allow string, fanout uint8) {
		fwd, err := parseForwards(strings.Split(allow, ","), int(fanout%8)+1)
		if err != nil {
			return
		}
		seen := map[string]bool{}
		for _, fw := range fwd {
			if !hostRE.MatchString(fw.Host) || fw.Host != strings.ToLower(fw.Host) {
				t.Fatalf("accepted host %q", fw.Host)
			}
			if fw.Port < 1 || fw.Port > 65535 {
				t.Fatalf("accepted port %d", fw.Port)
			}
			if seen[fw.Host] {
				t.Fatalf("accepted %q twice", fw.Host)
			}
			seen[fw.Host] = true
		}
	})
}
