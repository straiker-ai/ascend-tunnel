// Package netx is the host's HTTP plumbing, on the same terms as the tunnel agent: the system trust
// store plus an optional extra CA, and HTTPS_PROXY / NO_PROXY from the environment.
package netx

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// TLSConfig trusts the system store, so a corporate CA installed on the machine just works, plus
// caFile when given (e.g. a TLS-inspecting proxy's CA that is not in the system store).
func TLSConfig(caFile string) (*tls.Config, error) {
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
	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, nil
}

// ProxyFunc is HTTPS_PROXY / NO_PROXY from the environment (a seam for tests).
var ProxyFunc = http.ProxyFromEnvironment

// Transport is an HTTP transport with the host's TLS and proxy settings.
func Transport(tc *tls.Config) *http.Transport {
	return &http.Transport{
		Proxy:                 ProxyFunc,
		TLSClientConfig:       tc,
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConnsPerHost:   4,
		ForceAttemptHTTP2:     true,
	}
}

// ProxyFor names the proxy a URL is reached through, redacted, or "" for a direct connection.
func ProxyFor(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	p, err := ProxyFunc(&http.Request{URL: u})
	if err != nil || p == nil {
		return ""
	}
	return Redact(p.String())
}

// Redact drops any userinfo (a proxy password) before a URL reaches a log or a result. It doesn't
// parse: a password with a character URLs reserve (#, ? or /) makes url.Parse fail or split in the
// wrong place, and the raw string must not leak then either. Everything before the last "@" is userinfo.
func Redact(raw string) string {
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
