// Package token is how the host and Straiker prove themselves to each other: the host mints its own
// token with the agent key (the same key ascend-tunnel uses), and verifies the session token Straiker
// puts on every call. Both are compact JWS signed with Ed25519 ("EdDSA"); nothing else is accepted.
package token

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	// Alg is the only JWS algorithm minted or accepted.
	Alg = "EdDSA"
	// HostAudience is the audience of the host's own token: Straiker's agent API.
	HostAudience = "ascend-agent-api"
	// HostTokenTTL is how long an host token lives; one is minted per request.
	HostTokenTTL = 5 * time.Minute
	// SessionIssuer is the issuer every session token must carry.
	SessionIssuer = "straiker"
	// SessionAudiencePrefix + the agent id is the audience a session token must name.
	SessionAudiencePrefix = "host:"
	// MaxSessionLifetime bounds exp-iat: Straiker re-mints session tokens, so a long one is refused.
	MaxSessionLifetime = time.Hour
	// Skew is the clock difference tolerated on iat and exp.
	Skew = time.Minute
)

type header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ,omitempty"`
	Kid string `json:"kid,omitempty"`
}

// HostClaims are the claims of the host's own token.
type HostClaims struct {
	Issuer   string `json:"iss"`
	Subject  string `json:"sub"` // the agent id
	Audience string `json:"aud"`
	Tenant   string `json:"tenant"`
	IssuedAt int64  `json:"iat"`
	Expiry   int64  `json:"exp"`
	ID       string `json:"jti"`
}

// MintHost signs an host token with the agent's key. The key must be Ed25519: the SSH signature blob
// of an ssh-ed25519 key is the raw Ed25519 signature, so the result is a standard EdDSA JWS.
func MintHost(signer ssh.Signer, agentID, tenant string, now time.Time) (string, error) {
	if t := signer.PublicKey().Type(); t != ssh.KeyAlgoED25519 {
		return "", fmt.Errorf("host token: the agent key is %s, need %s", t, ssh.KeyAlgoED25519)
	}
	jti := make([]byte, 12)
	if _, err := rand.Read(jti); err != nil {
		return "", err
	}
	claims := HostClaims{
		Issuer:   SessionAudiencePrefix + agentID,
		Subject:  agentID,
		Audience: HostAudience,
		Tenant:   tenant,
		IssuedAt: now.Unix(),
		Expiry:   now.Add(HostTokenTTL).Unix(),
		ID:       hex.EncodeToString(jti),
	}
	input, err := signingInput(header{Alg: Alg, Typ: "JWT", Kid: agentID}, claims)
	if err != nil {
		return "", err
	}
	sig, err := signer.Sign(rand.Reader, []byte(input))
	if err != nil {
		return "", fmt.Errorf("host token: %w", err)
	}
	if sig.Format != ssh.KeyAlgoED25519 || len(sig.Blob) != ed25519.SignatureSize {
		return "", fmt.Errorf("host token: unexpected signature format %q", sig.Format)
	}
	return input + "." + b64(sig.Blob), nil
}

// Session is a verified session token: which agent session a call belongs to, and what it may use.
type Session struct {
	Issuer       string   `json:"iss"`
	Audience     string   `json:"aud"`
	Tenant       string   `json:"tenant"`
	SID          string   `json:"sid"`
	Agent        string   `json:"agent"`
	AgentVersion string   `json:"agent_version,omitempty"`
	Grants       []string `json:"grants"`
	AppID        string   `json:"app_id,omitempty"`
	CallID       string   `json:"call_id"`    // the one call this token authorizes
	MsgSHA256    string   `json:"msg_sha256"` // MessageDigest of that call's message
	IssuedAt     int64    `json:"iat"`
	Expiry       int64    `json:"exp"`
}

// Expect is what a session token must match besides its signature.
type Expect struct {
	HostID    string // the audience is SessionAudiencePrefix + AgentID
	Tenant    string // the host's org; required
	SID       string // the envelope's session id; required
	CallID    string // the envelope's call id; required
	MsgSHA256 string // MessageDigest of the envelope's message; required
}

// MessageDigest is the lowercase hex SHA-256 of a message's compact JSON (no insignificant
// whitespace), which a call-bound session token carries as msg_sha256.
func MessageDigest(msg []byte) (string, error) {
	var b bytes.Buffer
	if err := json.Compact(&b, msg); err != nil {
		return "", err
	}
	sum := sha256.Sum256(b.Bytes())
	return hex.EncodeToString(sum[:]), nil
}

// VerifySession checks a session token's signature against Straiker's pinned keys (more than one
// during a rotation), then its claims. A token authorizes exactly one call: its call_id and
// msg_sha256 must match the envelope it arrived in.
func VerifySession(tok string, keys []ed25519.PublicKey, want Expect, now time.Time) (*Session, error) {
	if len(keys) == 0 {
		return nil, errors.New("session token: no session key configured")
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return nil, errors.New("session token: not a compact JWS")
	}
	var h header
	if err := decodeJSON(parts[0], &h); err != nil {
		return nil, fmt.Errorf("session token header: %w", err)
	}
	if h.Alg != Alg {
		return nil, fmt.Errorf("session token: alg %q refused, only %s", h.Alg, Alg)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !slices.ContainsFunc(keys, func(k ed25519.PublicKey) bool {
		return len(k) == ed25519.PublicKeySize && ed25519.Verify(k, []byte(parts[0]+"."+parts[1]), sig)
	}) {
		return nil, errors.New("session token: bad signature")
	}
	var s Session
	if err := decodeJSON(parts[1], &s); err != nil {
		return nil, fmt.Errorf("session token claims: %w", err)
	}
	switch {
	case s.Issuer != SessionIssuer:
		return nil, fmt.Errorf("session token: issuer %q", s.Issuer)
	case s.Audience != SessionAudiencePrefix+want.HostID:
		return nil, fmt.Errorf("session token: audience %q is not this host", s.Audience)
	case want.Tenant == "" || s.Tenant != want.Tenant:
		return nil, fmt.Errorf("session token: tenant %q is not this host's org", s.Tenant)
	case want.SID == "" || s.SID != want.SID:
		return nil, errors.New("session token: session id does not match the call")
	case want.CallID == "" || s.CallID != want.CallID:
		return nil, errors.New("session token: call id does not match the call")
	case want.MsgSHA256 == "" || s.MsgSHA256 != want.MsgSHA256:
		return nil, errors.New("session token: message digest does not match the call")
	case s.Agent == "":
		return nil, errors.New("session token: no agent")
	case now.Add(-Skew).Unix() >= s.Expiry:
		return nil, errors.New("session token: expired")
	case s.IssuedAt > now.Add(Skew).Unix():
		return nil, errors.New("session token: issued in the future")
	case time.Duration(s.Expiry-s.IssuedAt)*time.Second > MaxSessionLifetime:
		return nil, fmt.Errorf("session token: lifetime over %s", MaxSessionLifetime)
	}
	return &s, nil
}

// MintSession signs a session token in the format Straiker issues, for tests and a local stand-in API.
func MintSession(priv ed25519.PrivateKey, s Session) (string, error) {
	input, err := signingInput(header{Alg: Alg, Typ: "JWT"}, s)
	if err != nil {
		return "", err
	}
	return input + "." + b64(ed25519.Sign(priv, []byte(input))), nil
}

// ParsePublicKey reads Straiker's session key in any of the forms it is published in: the raw 32-byte
// key in base64, an "ssh-ed25519 AAAA..." line, or a PEM PUBLIC KEY block.
func ParsePublicKey(s string) (ed25519.PublicKey, error) {
	s = strings.TrimSpace(s)
	switch {
	case s == "":
		return nil, errors.New("session key is empty")
	case strings.HasPrefix(s, "-----BEGIN"):
		block, _ := pem.Decode([]byte(s))
		if block == nil {
			return nil, errors.New("session key: bad PEM")
		}
		k, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("session key: %w", err)
		}
		if ek, ok := k.(ed25519.PublicKey); ok {
			return ek, nil
		}
		return nil, errors.New("session key: not Ed25519")
	case strings.HasPrefix(s, ssh.KeyAlgoED25519+" "):
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(s))
		if err != nil {
			return nil, fmt.Errorf("session key: %w", err)
		}
		if ck, ok := pub.(ssh.CryptoPublicKey); ok {
			if ek, ok := ck.CryptoPublicKey().(ed25519.PublicKey); ok {
				return ek, nil
			}
		}
		return nil, errors.New("session key: not Ed25519")
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if raw, err := enc.DecodeString(s); err == nil && len(raw) == ed25519.PublicKeySize {
			return ed25519.PublicKey(raw), nil
		}
	}
	return nil, errors.New("session key: expected base64 Ed25519 key, an ssh-ed25519 line, or PEM")
}

func signingInput(h header, claims any) (string, error) {
	hj, err := json.Marshal(h)
	if err != nil {
		return "", err
	}
	cj, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	return b64(hj) + "." + b64(cj), nil
}

func decodeJSON(part string, v any) error {
	raw, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, v)
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
