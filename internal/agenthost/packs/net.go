package packs

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"time"

	"github.com/straiker-ai/ascend-tunnel/internal/agenthost/mcp"
	"github.com/straiker-ai/ascend-tunnel/internal/agenthost/policy"
)

const netCheckTimeout = 5 * time.Second

// dialer is the net.check dialer (a seam for tests).
var dialer = &net.Dialer{Timeout: netCheckTimeout, Control: guard}

func netCheck(p *policy.Policy, roots *x509.CertPool, ap Approver) tool {
	props := `"target":` + targetSchema
	if ap != nil {
		props += `,"url":` + urlSchema
	}
	return tool{
		def: mcp.Tool{
			Name:        "net.check",
			Title:       "Reachability check",
			Description: "From inside the customer's network, check that a target's host:port accepts a TCP connection and, for https, completes a TLS handshake. Sends no request.",
			InputSchema: schema(`{"type":"object","properties":{` + props + `},"additionalProperties":false}`),
			Annotations: &mcp.Annotations{ReadOnlyHint: true, OpenWorldHint: true},
		},
		run: func(ctx context.Context, args json.RawMessage) mcp.Result {
			var in struct {
				Target string `json:"target"`
				URL    string `json:"url"`
			}
			if err := decode(args, &in); err != nil {
				return failure("arguments", err)
			}
			if ap == nil && in.URL != "" {
				return refuse("this host reaches only its policy's targets")
			}
			u, label, refusal, ok := site(ctx, p, ap, "net.check", in.Target, in.URL)
			if !ok {
				return refusal
			}
			port := u.Port()
			if port == "" {
				port = map[string]string{"http": "80", "https": "443"}[u.Scheme]
			}
			addr := net.JoinHostPort(u.Hostname(), port)
			out := map[string]any{"target": label, "address": addr}

			ctx, cancel := context.WithTimeout(ctx, 2*netCheckTimeout)
			defer cancel()
			start := time.Now()
			conn, err := dialer.DialContext(ctx, "tcp", addr)
			if err != nil {
				out["reachable"], out["error"] = false, err.Error()
				return mcp.JSONResult(out, true)
			}
			defer conn.Close()
			out["reachable"] = true
			out["connect_ms"] = time.Since(start).Milliseconds()
			if u.Scheme == "https" {
				out["tls"] = handshake(ctx, conn, u.Hostname(), roots)
			}
			return mcp.JSONResult(out, false)
		},
	}
}

// handshake reports a TLS handshake and whether the certificate verifies against roots, without
// failing the check on an untrusted one: a private CA is common inside a customer network, and the
// cloud side needs to know about it (an app's _tunnel_ca), not to be stopped by it. The handshake
// verifies as usual; a verification failure still carries the server's certificates, which are reported.
func handshake(ctx context.Context, conn net.Conn, host string, roots *x509.CertPool) map[string]any {
	tc := tls.Client(conn, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12, RootCAs: roots})
	err := tc.HandshakeContext(ctx)
	out := map[string]any{"ok": true, "version": tls.VersionName(tc.ConnectionState().Version), "verified": err == nil}
	certs := tc.ConnectionState().PeerCertificates
	if err != nil {
		var unverified *tls.CertificateVerificationError
		if !errors.As(err, &unverified) {
			return map[string]any{"ok": false, "error": err.Error()}
		}
		certs = unverified.UnverifiedCertificates
		out["verify_error"] = unverified.Err.Error()
	}
	if len(certs) == 0 {
		return out
	}
	leaf := certs[0]
	out["subject"] = leaf.Subject.CommonName
	out["issuer"] = leaf.Issuer.CommonName
	out["not_after"] = leaf.NotAfter.UTC().Format(time.RFC3339)
	out["dns_names"] = leaf.DNSNames
	return out
}
