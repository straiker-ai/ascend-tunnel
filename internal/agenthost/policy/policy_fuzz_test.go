package policy

import "testing"

// FuzzParse feeds arbitrary bytes to the policy parser: it returns a policy or an error, never panics.
func FuzzParse(f *testing.F) {
	for _, seed := range []string{
		"",
		"org: acme\nenv: prod\n",
		"targets: [{host: app.internal, port: 443}]\n",
		"packs: {env: true}\nunknown_key: 1\n",
		"- not\n- a\n- map\n",
		"&a [*a, *a]\n",
		"org: !!binary aGVsbG8=\n",
	} {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := Parse(data)
		if err == nil && p == nil {
			t.Fatal("no policy and no error")
		}
	})
}
