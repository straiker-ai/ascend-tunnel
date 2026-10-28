package token

import (
	"crypto/ed25519"
	"strings"
	"testing"
)

// FuzzVerifySession feeds arbitrary strings to the session-token check. Beyond not panicking, a token
// may only verify if its signed part - header and claims, byte for byte - is the one Straiker minted:
// no re-encoding, padding, extra field or alg trick gets a different signed part accepted.
func FuzzVerifySession(f *testing.F) {
	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)) // fixed, so the corpus stays valid
	keys := []ed25519.PublicKey{priv.Public().(ed25519.PublicKey)}
	want := Expect{HostID: "abcd1234", Tenant: "1", SID: "s_1", CallID: "c1", MsgSHA256: "d1"}

	good, err := MintSession(priv, goodSession())
	if err != nil {
		f.Fatal(err)
	}
	if _, err := VerifySession(good, keys, want, now); err != nil {
		f.Fatalf("the seed token must verify, or the property below is never exercised: %v", err)
	}
	signed := good[:strings.LastIndex(good, ".")]

	alg, _ := signingInput(header{Alg: "none", Typ: "JWT"}, goodSession())
	for _, seed := range []string{good, tamper(good), alg + ".", signed + "." + signed, "", "..", "a.b.c", good + "="} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, tok string) {
		s, err := VerifySession(tok, keys, want, now)
		if err != nil {
			return
		}
		if got := tok[:strings.LastIndex(tok, ".")]; got != signed {
			t.Fatalf("verified a token whose signed part Straiker never minted: %q", got)
		}
		if s.Agent == "" || s.CallID != want.CallID {
			t.Fatalf("verified session %+v does not match %+v", s, want)
		}
	})
}
