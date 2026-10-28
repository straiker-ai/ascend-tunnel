package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/coder/websocket"
)

const handshakeTimeout = 20 * time.Second

// tlsConfig trusts the system store - so a corporate CA installed on the machine just works - plus
// caFile when given (e.g. a TLS-inspecting proxy's CA that is not in the system store).
func tlsConfig(caFile string) (*tls.Config, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("ca_file: %w", err)
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("ca_file %s holds no PEM certificate", caFile)
		}
	}
	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}, nil
}

// proxyFunc is HTTPS_PROXY / NO_PROXY from the environment (a seam for tests).
var proxyFunc = http.ProxyFromEnvironment

// dialRelay opens the WebSocket to the relay - through HTTPS_PROXY when set, as ordinary HTTPS a
// TLS-inspecting proxy passes - and returns it as a byte stream for SSH. The returned response is
// the upgrade's, for its TLS details.
func dialRelay(ctx context.Context, relay string, tc *tls.Config) (net.Conn, *http.Response, error) {
	transport := &http.Transport{
		Proxy:               proxyFunc,
		DialContext:         dialNet,
		TLSClientConfig:     tc,
		TLSHandshakeTimeout: handshakeTimeout,
		ForceAttemptHTTP2:   false, // a WebSocket upgrade is HTTP/1.1
	}
	dctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	ws, resp, err := websocket.Dial(dctx, relay, &websocket.DialOptions{
		HTTPClient: &http.Client{Transport: transport},
	})
	if err != nil {
		return nil, resp, fmt.Errorf("relay %s: %w", redact(relay), err)
	}
	ws.SetReadLimit(64 << 20) // frames carry SSH packets; the relay chooses their size
	return websocket.NetConn(ctx, ws, websocket.MessageBinary), resp, nil
}

// relayProxy names the proxy the relay is dialled through, or "" for a direct connection.
func relayProxy(relay string) string {
	if p := relayProxyURL(relay); p != nil {
		return redact(p.String())
	}
	return ""
}

// redact drops any userinfo (a proxy password) before a URL reaches a log. It doesn't parse: a password
// with a character URLs reserve (#, ? or /) makes url.Parse fail or split in the wrong place, and the
// raw string must not leak then either. Everything before the last "@" is userinfo.
func redact(raw string) string {
	scheme, rest := "", raw
	if i := strings.Index(raw, "://"); i >= 0 {
		scheme, rest = raw[:i+3], raw[i+3:]
	}
	at := strings.LastIndex(rest, "@")
	if at < 0 {
		return raw
	}
	return scheme + "redacted@" + rest[at+1:]
}
