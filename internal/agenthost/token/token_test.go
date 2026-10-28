package token

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

var now = time.Unix(1_800_000_000, 0)

// signSession mints a session token the way Straiker will, for tests.
func signSession(t *testing.T, priv ed25519.PrivateKey, alg string, s Session) string {
	t.Helper()
	input, err := signingInput(header{Alg: alg, Typ: "JWT"}, s)
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + b64(ed25519.Sign(priv, []byte(input)))
}

func goodSession() Session {
	return Session{
		Issuer: SessionIssuer, Audience: "host:abcd1234", Tenant: "1", SID: "s_1",
		Agent: "adaptor-builder", Grants: []string{"env.info"}, CallID: "c1", MsgSHA256: "d1",
		IssuedAt: now.Unix(), Expiry: now.Add(15 * time.Minute).Unix(),
	}
}

func TestVerifySession(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	want := Expect{HostID: "abcd1234", Tenant: "1", SID: "s_1", CallID: "c1", MsgSHA256: "d1"}
	keys := []ed25519.PublicKey{pub}

	if s, err := VerifySession(signSession(t, priv, Alg, goodSession()), keys, want, now); err != nil || s.Agent != "adaptor-builder" {
		t.Fatalf("good token: %v %+v", err, s)
	}

	mutate := func(f func(*Session)) string {
		s := goodSession()
		f(&s)
		return signSession(t, priv, Alg, s)
	}
	cases := map[string]string{
		"other key":       signSession(t, otherPriv, Alg, goodSession()),
		"alg none":        signSession(t, priv, "none", goodSession()),
		"alg HS256":       signSession(t, priv, "HS256", goodSession()),
		"issuer":          mutate(func(s *Session) { s.Issuer = "someone" }),
		"audience":        mutate(func(s *Session) { s.Audience = "host:ffffffff" }),
		"tenant":          mutate(func(s *Session) { s.Tenant = "2" }),
		"sid":             mutate(func(s *Session) { s.SID = "s_2" }),
		"other call":      mutate(func(s *Session) { s.CallID = "c2" }),
		"other message":   mutate(func(s *Session) { s.MsgSHA256 = "d2" }),
		"unbound":         mutate(func(s *Session) { s.CallID, s.MsgSHA256 = "", "" }),
		"no agent":        mutate(func(s *Session) { s.Agent = "" }),
		"expired":         mutate(func(s *Session) { s.Expiry = now.Add(-2 * time.Minute).Unix() }),
		"future":          mutate(func(s *Session) { s.IssuedAt = now.Add(5 * time.Minute).Unix() }),
		"too long":        mutate(func(s *Session) { s.Expiry = now.Add(2 * time.Hour).Unix() }),
		"two parts":       "a.b",
		"garbage":         "!!.!!.!!",
		"tampered claims": tamper(signSession(t, priv, Alg, goodSession())),
	}
	for name, tok := range cases {
		if _, err := VerifySession(tok, keys, want, now); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := VerifySession(signSession(t, priv, Alg, goodSession()), nil, want, now); err == nil {
		t.Error("no key: accepted")
	}
	noOrg := want
	noOrg.Tenant = ""
	if _, err := VerifySession(signSession(t, priv, Alg, goodSession()), keys, noOrg, now); err == nil {
		t.Error("host with no org: accepted")
	}
	unbound := want
	unbound.CallID, unbound.MsgSHA256 = "", ""
	if _, err := VerifySession(signSession(t, priv, Alg, goodSession()), keys, unbound, now); err == nil {
		t.Error("an envelope with no call id or digest: accepted")
	}
}

func TestVerifySessionDuringRotation(t *testing.T) {
	oldPub, oldPriv, _ := ed25519.GenerateKey(rand.Reader)
	newPub, newPriv, _ := ed25519.GenerateKey(rand.Reader)
	want := Expect{HostID: "abcd1234", Tenant: "1", SID: "s_1", CallID: "c1", MsgSHA256: "d1"}
	both := []ed25519.PublicKey{oldPub, newPub}
	for name, priv := range map[string]ed25519.PrivateKey{"old": oldPriv, "new": newPriv} {
		if _, err := VerifySession(signSession(t, priv, Alg, goodSession()), both, want, now); err != nil {
			t.Errorf("%s key during rotation: %v", name, err)
		}
	}
	if _, err := VerifySession(signSession(t, oldPriv, Alg, goodSession()), []ed25519.PublicKey{newPub}, want, now); err == nil {
		t.Error("a retired key must stop verifying once it is unpinned")
	}
}

func TestMessageDigest(t *testing.T) {
	// The broker hashes json.dumps(msg, separators=(",", ":")); whitespace around it must not matter.
	compact := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"env.info","arguments":{"q":"a b\u00e9"}}}`
	spaced := "{ \"jsonrpc\": \"2.0\", \"id\": 1,\n \"method\": \"tools/call\", \"params\": {\"name\": \"env.info\", \"arguments\": {\"q\": \"a b\\u00e9\"}}}"
	a, err := MessageDigest([]byte(compact))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := MessageDigest([]byte(spaced))
	sum := sha256.Sum256([]byte(compact))
	if a != b || a != hex.EncodeToString(sum[:]) {
		t.Fatalf("digest must be SHA-256 of the compact form: %s %s", a, b)
	}
	if c, _ := MessageDigest([]byte(`{"jsonrpc":"2.0","id":2}`)); c == a {
		t.Fatal("different messages, same digest")
	}
	if _, err := MessageDigest([]byte(`{not json`)); err == nil {
		t.Fatal("invalid JSON must not digest")
	}
}

// tamper swaps the claims for others while keeping the original signature.
func tamper(tok string) string {
	parts := strings.Split(tok, ".")
	s := goodSession()
	s.Grants = []string{"everything.*"}
	cj, _ := json.Marshal(s)
	return parts[0] + "." + b64(cj) + "." + parts[2]
}

func TestMintHostVerifiesAsEdDSA(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := MintHost(signer, "abcd1234", "1", now)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(tok, ".")
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	if !ed25519.Verify(pub, []byte(parts[0]+"."+parts[1]), sig) {
		t.Fatal("an host token must verify as a plain EdDSA JWS with the agent's public key")
	}
	var h header
	var c HostClaims
	if decodeJSON(parts[0], &h) != nil || decodeJSON(parts[1], &c) != nil {
		t.Fatal("undecodable")
	}
	if h.Alg != Alg || h.Kid != "abcd1234" || c.Subject != "abcd1234" || c.Audience != HostAudience ||
		c.Tenant != "1" || c.Expiry-c.IssuedAt != int64(HostTokenTTL/time.Second) || len(c.ID) != 24 {
		t.Fatalf("header %+v claims %+v", h, c)
	}
	if tok2, _ := MintHost(signer, "abcd1234", "1", now); tok2 == tok {
		t.Error("two tokens share a jti")
	}
}

func TestMintHostRefusesNonEd25519(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := MintHost(signer, "x", "1", now); err == nil {
		t.Fatal("a non-Ed25519 agent key must be refused")
	}
}

func TestParsePublicKey(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	sshPub, _ := ssh.NewPublicKey(pub)
	der, _ := x509.MarshalPKIXPublicKey(pub)
	forms := map[string]string{
		"base64":     base64.StdEncoding.EncodeToString(pub),
		"base64url":  base64.RawURLEncoding.EncodeToString(pub),
		"ssh line":   strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))) + " comment",
		"pem":        string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})),
		"whitespace": "  " + base64.StdEncoding.EncodeToString(pub) + "\n",
	}
	for name, s := range forms {
		got, err := ParsePublicKey(s)
		if err != nil || !got.Equal(pub) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for _, bad := range []string{"", "AAAA", base64.StdEncoding.EncodeToString(make([]byte, 31)), "-----BEGIN PUBLIC KEY-----\nxx\n-----END PUBLIC KEY-----"} {
		if _, err := ParsePublicKey(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
