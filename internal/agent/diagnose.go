package agent

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/straiker-ai/ascend-tunnel/internal/config"
)

const (
	probeTimeout = 10 * time.Second // a TLS handshake, or an HTTP answer
	// controlAddr is dialled by `check` only, never by the running agent, when nothing answers from
	// the relay: it tells "this destination is blocked" from "no direct internet at all".
	controlAddr = "www.microsoft.com:443"
	// relayServer is the Server header of Straiker's relay (websockify), which tells its answers from a
	// middlebox's; a change to the relay must keep it or update this.
	relayServer = "WebSockify"
	lbServer    = "awselb" // Straiker's load balancer, answering for a relay that is down
)

// Seams for tests, like proxyFunc: DNS, and every TCP dial a check or the relay WebSocket makes.
var (
	lookupIP = func(ctx context.Context, host string) ([]netip.Addr, error) {
		return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	}
	dialNet = (&net.Dialer{}).DialContext
)

// step is one hop of a check: what was seen and, when it did not pass, what to do about it.
type step struct {
	status string // PASS, FAIL, WARN, WAIT or INFO
	name   string
	detail string
	fix    string
	ours   bool // a failure on Straiker's side, not the customer's
}

type steps []step

func (s *steps) add(status, name, detail, fix string) {
	*s = append(*s, step{status: status, name: name, detail: detail, fix: fix})
}

func (s steps) firstFail() (step, bool) {
	for _, st := range s {
		if st.status == "FAIL" {
			return st, true
		}
	}
	return step{}, false
}

func (s steps) has(status string) bool {
	for _, st := range s {
		if st.status == status {
			return true
		}
	}
	return false
}

// verdict is a section's RESULT: its status, one line saying what it means, and the fix to act on.
type verdict struct{ status, text, fix string }

func tunnelVerdict(s steps) verdict {
	if f, ok := s.firstFail(); ok {
		if f.ours {
			return verdict{"FAIL", "Straiker's relay is unavailable; send this output to Straiker support", f.fix}
		}
		return verdict{"FAIL", fmt.Sprintf("the path from this machine to Straiker stops at %q; Straiker's relay is up, "+
			"so the block is on this machine's network", f.name), f.fix}
	}
	for _, st := range s {
		if st.status == "WAIT" {
			return verdict{"WAIT", "this machine reaches Straiker; no app lists this agent's key yet", st.fix}
		}
	}
	for _, st := range s {
		if st.status == "PASS" && st.name == "login" {
			return verdict{"PASS", "this machine reaches Straiker, and an app lists this agent", ""}
		}
	}
	return verdict{"PASS", "this machine reaches Straiker", ""}
}

func appsVerdict(s steps, n int) verdict {
	failed := 0
	for _, st := range s {
		if st.status == "FAIL" {
			failed++
		}
	}
	switch {
	case failed > 0:
		f, _ := s.firstFail()
		return verdict{"FAIL", fmt.Sprintf("this machine cannot reach %d of %d app(s)", failed, n), f.fix}
	case s.has("WARN"):
		return verdict{"PASS", "this machine reaches every app; check the WARN above before using its app URL", ""}
	}
	return verdict{"PASS", "this machine reaches every app in the allowlist", ""}
}

// probeRelay walks the path to the relay one hop at a time - DNS, TCP to each address (or the proxy
// and its CONNECT), TLS, an HTTPS request, the WebSocket, SSH, the login - so a failure names the hop
// it stopped at. checking (`check`, never the running agent) allows dials beyond the relay when it
// cannot be reached: controlAddr, this machine's PAC file, and the proxy its settings name.
func (a *Agent) probeRelay(ctx context.Context, checking bool) steps {
	var s steps
	u, err := url.Parse(a.cfg.Relay)
	if err != nil || u.Hostname() == "" {
		s.add("FAIL", "relay", fmt.Sprintf("the relay URL %q is not usable", redact(a.cfg.Relay)),
			"Fix --relay, or leave it out to use Straiker's.")
		return s
	}
	host, port := u.Hostname(), u.Port()
	if port == "" {
		port = "443"
	}
	var conn net.Conn
	if p := relayProxyURL(a.cfg.Relay); p != nil && p.Scheme != "http" && p.Scheme != "https" {
		// A SOCKS proxy speaks no HTTP to check hop by hop: the WebSocket step goes through it.
		s.add("INFO", "proxy", fmt.Sprintf("%s is checked by the WebSocket step below", redact(p.String())), "")
		a.probeTunnel(ctx, &s, host)
		return s
	} else if p != nil {
		conn = a.probeProxy(ctx, &s, p, host, net.JoinHostPort(host, port))
	} else {
		adv := a.adviseProxy(ctx, host, checking)
		for _, n := range adv.notes {
			s.add("INFO", "proxy", n, "")
		}
		conn = probeDirect(ctx, &s, host, port, checking, adv)
		if conn == nil && checking && adv.suggest != "" {
			ok, tried := a.tryProxy(ctx, adv, host, net.JoinHostPort(host, port))
			if ok {
				for i := range s {
					if s[i].status == "FAIL" {
						s[i].fix = fmt.Sprintf("This network reaches the internet through a proxy: set HTTPS_PROXY=%s, "+
							"then run check again.", redact(adv.suggest))
					}
				}
			}
			s = append(s, tried)
		}
	}
	if conn == nil {
		return s
	}
	tc := a.probeTLS(ctx, &s, conn, host)
	if tc == nil || !probeHTTPS(&s, tc, u) {
		return s
	}
	a.probeTunnel(ctx, &s, host)
	return s
}

func probeDirect(ctx context.Context, s *steps, host, port string, control bool, adv proxyAdvice) net.Conn {
	addrs := probeDNS(ctx, s, host, adv)
	if addrs == nil {
		return nil
	}
	errs := make([]error, len(addrs))
	conns := make([]net.Conn, len(addrs))
	var wg sync.WaitGroup
	for i, ip := range addrs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conns[i], errs[i] = dialWithin(ctx, net.JoinHostPort(ip.String(), port))
		}()
	}
	wg.Wait()

	var conn net.Conn
	var open, shut, shut4 []string
	for i, ip := range addrs {
		switch {
		case errs[i] != nil:
			shut = append(shut, fmt.Sprintf("%s (%s)", ip, why(errs[i])))
			if ip.Is4() {
				shut4 = append(shut4, ip.String())
			}
		case conn == nil:
			conn = conns[i]
			open = append(open, ip.String())
		default:
			conns[i].Close()
			open = append(open, ip.String())
		}
	}
	switch {
	case conn == nil:
		detail := fmt.Sprintf("nothing answered on port %s: %s", port, strings.Join(shut, ", "))
		fix := fmt.Sprintf("A firewall blocks outbound TCP %s to %s, or this machine reaches the internet only "+
			"through a proxy (set HTTPS_PROXY). Run `ascend-tunnel check` to tell which.%s", port, host, adv.hint())
		if control {
			if c, err := dialWithin(ctx, controlAddr); err == nil {
				c.Close()
				detail += fmt.Sprintf("; %s answers, so only this destination is blocked", controlAddr)
				byName := ""
				if _, err := netip.ParseAddr(host); err != nil {
					byName = ", by hostname (its addresses change)"
				}
				fix = fmt.Sprintf("Ask your network team to allow outbound TCP %s to %s%s. Their firewall log for this "+
					"machine names the rule that blocks it.", port, host, byName)
			} else {
				detail += fmt.Sprintf("; %s does not answer either", controlAddr)
				fix = fmt.Sprintf("This machine has no direct internet access: set HTTPS_PROXY to your proxy, or ask "+
					"your network team to allow outbound TCP %s to %s.%s", port, host, adv.hint())
			}
		}
		s.add("FAIL", "tcp", detail, fix)
	case len(shut4) > 0:
		s.add("FAIL", "tcp", fmt.Sprintf("port %s open on %s, but not on %s", port, strings.Join(open, ", "), strings.Join(shut, ", ")),
			fmt.Sprintf("Your firewall allows some of %s's addresses and not others: its rule resolves %s to a "+
				"different or stale set. Allow %s by hostname, resolved with the same DNS as this machine; its "+
				"addresses change.", host, host, host))
	default:
		s.add("PASS", "tcp", fmt.Sprintf("port %s open on %s", port, strings.Join(open, ", ")), "")
		if len(shut) > 0 {
			s.add("INFO", "tcp", fmt.Sprintf("IPv6 not reachable (%s); IPv4 is used, which is fine", strings.Join(shut, ", ")), "")
		}
	}
	return conn
}

func probeDNS(ctx context.Context, s *steps, host string, adv proxyAdvice) []netip.Addr {
	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip}
	}
	dctx, cancel := context.WithTimeout(ctx, checkDialTimeout)
	defer cancel()
	addrs, err := lookupIP(dctx, host)
	if err == nil && len(addrs) == 0 {
		err = errors.New("no addresses")
	}
	if err != nil {
		s.add("FAIL", "dns", fmt.Sprintf("cannot resolve %s: %v", host, err),
			fmt.Sprintf("Allow %s in this machine's DNS (or DNS filter), or set HTTPS_PROXY if this network "+
				"reaches the internet only through a proxy.%s", host, adv.hint()))
		return nil
	}
	var all, private []string
	bogus := false
	for i, ip := range addrs {
		ip = ip.Unmap()
		addrs[i] = ip
		all = append(all, ip.String())
		switch {
		case ip.IsUnspecified() || ip.IsLoopback():
			bogus = true
		case ip.IsPrivate() || ip.IsLinkLocalUnicast():
			private = append(private, ip.String())
		}
	}
	list := strings.Join(all, ", ")
	if bogus {
		s.add("FAIL", "dns", fmt.Sprintf("%s resolves to %s, which is not Straiker's relay", host, list),
			fmt.Sprintf("A DNS filter is redirecting %s: ask for it to be allowed there.", host))
		return nil
	}
	s.add("PASS", "dns", host+" -> "+list, "")
	if len(private) > 0 {
		s.add("WARN", "dns", fmt.Sprintf("%s is a private address; if the next step fails, a DNS filter may be "+
			"redirecting %s", strings.Join(private, ", "), host), "")
	}
	return addrs
}

func (a *Agent) probeProxy(ctx context.Context, s *steps, p *url.URL, host, target string) net.Conn {
	name := redact(p.String())
	addr := p.Host
	if p.Port() == "" && p.Scheme == "https" {
		addr = net.JoinHostPort(p.Hostname(), "443")
	} else if p.Port() == "" {
		addr = net.JoinHostPort(p.Hostname(), "80")
	}
	c, err := dialWithin(ctx, addr)
	if err != nil {
		s.add("FAIL", "proxy", fmt.Sprintf("cannot reach the proxy %s: %s", name, why(err)),
			"Check HTTPS_PROXY: this machine cannot reach that proxy.")
		return nil
	}
	if p.Scheme == "https" {
		tc := tls.Client(c, &tls.Config{ServerName: p.Hostname(), RootCAs: a.tls.RootCAs, MinVersion: tls.VersionTLS12})
		hctx, cancel := context.WithTimeout(ctx, probeTimeout)
		err := tc.HandshakeContext(hctx)
		cancel()
		if err != nil {
			c.Close()
			s.add("FAIL", "proxy", fmt.Sprintf("TLS to the proxy %s failed: %v", name, err),
				"Check HTTPS_PROXY's scheme and the proxy's CA (--ca-file).")
			return nil
		}
		c = tc
	}
	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", target, target)
	if p.User != nil {
		pass, _ := p.User.Password()
		req += "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(p.User.Username()+":"+pass)) + "\r\n"
	}
	_ = c.SetDeadline(time.Now().Add(probeTimeout))
	var resp *http.Response
	if _, err = io.WriteString(c, req+"\r\n"); err == nil {
		resp, err = http.ReadResponse(bufio.NewReader(c), &http.Request{Method: http.MethodConnect})
	}
	if err != nil {
		c.Close()
		s.add("FAIL", "proxy", fmt.Sprintf("the proxy %s did not answer CONNECT %s (%s)", name, target, why(err)),
			fmt.Sprintf("Ask your proxy admins to allow CONNECT to %s.", target))
		return nil
	}
	if resp.StatusCode == http.StatusOK {
		_ = c.SetDeadline(time.Time{})
		s.add("PASS", "proxy", fmt.Sprintf("%s opened a tunnel to %s", name, target), "")
		return c
	}
	c.Close()
	fix := fmt.Sprintf("Ask your proxy admins to allow CONNECT to %s.", target)
	switch {
	case resp.StatusCode == http.StatusProxyAuthRequired:
		fix = proxyAuthFix(resp.Header, host)
	case resp.StatusCode == http.StatusForbidden:
		fix = fmt.Sprintf("The proxy's policy blocks %s: ask for it to be allowed, by hostname.", host)
	case resp.StatusCode >= 500:
		fix = fmt.Sprintf("The proxy cannot reach %s itself: ask your proxy admins to allow its outbound access to %s.", host, target)
	}
	s.add("FAIL", "proxy", fmt.Sprintf("%s answered CONNECT %s with HTTP %d%s", name, target, resp.StatusCode, device(resp.Header)), fix)
	return nil
}

// probeTLS verifies the relay's certificate on conn, as the agent will. It closes conn on failure.
func (a *Agent) probeTLS(ctx context.Context, s *steps, conn net.Conn, host string) *tls.Conn {
	cfg := a.tls.Clone()
	cfg.ServerName = host
	tc := tls.Client(conn, cfg)
	hctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	err := tc.HandshakeContext(hctx)
	if err == nil {
		issuer := issuerName(tc.ConnectionState().PeerCertificates[0].Issuer)
		s.add("PASS", "tls", fmt.Sprintf("verified %s, issued by %q (a TLS-inspecting proxy shows its own CA here; "+
			"that is fine)", host, issuer), "")
		return tc
	}
	conn.Close()
	var unknown x509.UnknownAuthorityError
	var mismatch x509.HostnameError
	var invalid x509.CertificateInvalidError
	switch {
	case errors.As(err, &unknown) && unknown.Cert != nil:
		issuer := issuerName(unknown.Cert.Issuer)
		hint := ""
		if inContainer() {
			hint = " (mount it into the container: a container does not use this machine's certificate store)"
		}
		s.add("FAIL", "tls", fmt.Sprintf("%s's certificate is issued by %q, which this machine does not trust", host, issuer),
			fmt.Sprintf("Your network inspects TLS and re-signs it as %q: give the agent that CA with --ca-file%s.", issuer, hint))
	case errors.As(err, &mismatch):
		names := strings.Join(mismatch.Certificate.DNSNames, ", ")
		if names == "" {
			names = mismatch.Certificate.Subject.CommonName
		}
		s.add("FAIL", "tls", fmt.Sprintf("the certificate presented is for %s, not %s", names, host),
			fmt.Sprintf("Something other than Straiker answers for %s (a captive portal or a redirecting filter): "+
				"ask for %s to be allowed through it.", host, host))
	case errors.As(err, &invalid):
		s.add("FAIL", "tls", fmt.Sprintf("%s's certificate is not valid here: %v", host, invalid),
			"Check this machine's clock; if it is right, something other than Straiker answers for "+host+".")
	case isTimeout(err):
		s.add("FAIL", "tls", fmt.Sprintf("the connection opened, but no TLS answer came within %s", probeTimeout),
			fmt.Sprintf("Something between this machine and %s holds the connection without answering: a firewall "+
				"or proxy blocks it after the connection opens.", host))
	case isClosed(err):
		s.add("FAIL", "tls", fmt.Sprintf("the connection was closed right after the TLS hello naming %s", host),
			fmt.Sprintf("A firewall blocks %s by name (SNI or URL filtering): ask for %s to be allowed in its URL "+
				"or SSL policy.", host, host))
	default:
		s.add("FAIL", "tls", fmt.Sprintf("TLS to %s failed: %v", host, err), "")
	}
	return nil
}

var titleRE = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// probeHTTPS asks the relay for its tunnel path over plain HTTPS: Straiker's relay answers it, a web
// filter or block page answers instead. It closes tc.
func probeHTTPS(s *steps, tc *tls.Conn, u *url.URL) bool {
	defer tc.Close()
	host := u.Hostname()
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	_ = tc.SetDeadline(time.Now().Add(probeTimeout))
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: ascend-tunnel-check\r\nConnection: close\r\n\r\n", path, u.Host)
	var resp *http.Response
	_, err := io.WriteString(tc, req)
	if err == nil {
		resp, err = http.ReadResponse(bufio.NewReader(tc), nil)
	}
	if err != nil {
		s.add("FAIL", "https", fmt.Sprintf("the connection was closed instead of answering an HTTPS request (%s)", why(err)),
			fmt.Sprintf("A firewall cuts HTTPS to %s after TLS (application or URL control): ask for %s to be allowed.", host, host))
		return false
	}
	defer resp.Body.Close()
	server := resp.Header.Get("Server")
	switch {
	case strings.HasPrefix(server, relayServer):
		s.add("PASS", "https", fmt.Sprintf("reached Straiker's relay (HTTP %d)", resp.StatusCode), "")
		return true
	case resp.StatusCode == http.StatusProxyAuthRequired:
		s.add("FAIL", "https", fmt.Sprintf("a proxy on the path answered HTTP 407%s: this network intercepts HTTPS", device(resp.Header)),
			"This network has a proxy: set HTTPS_PROXY to it. "+proxyAuthFix(resp.Header, host))
		return false
	case strings.HasPrefix(server, lbServer) && resp.StatusCode >= 500:
		*s = append(*s, step{status: "FAIL", name: "https", ours: true,
			detail: fmt.Sprintf("Straiker's load balancer answered HTTP %d: the relay behind it is unavailable", resp.StatusCode),
			fix:    "This is on Straiker's side: send this output to Straiker support."})
		return false
	}
	detail := fmt.Sprintf("something other than Straiker's relay answered: HTTP %d%s", resp.StatusCode, device(resp.Header))
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if m := titleRE.FindSubmatch(body); m != nil {
		detail += fmt.Sprintf(", page %q", strings.Join(strings.Fields(string(m[1])), " "))
	}
	if loc := resp.Header.Get("Location"); loc != "" {
		detail += ", redirecting to " + loc
	}
	s.add("FAIL", "https", detail,
		fmt.Sprintf("A web filter or block page answers for %s: ask for %s to be allowed in it.", host, host))
	return false
}

// probeTunnel opens the WebSocket, then SSH inside it, as the agent does, and tries the login.
func (a *Agent) probeTunnel(ctx context.Context, s *steps, host string) {
	blocked := fmt.Sprintf("HTTPS to %s works, but WebSocket is blocked (application control such as Palo Alto "+
		"App-ID \"websocket\", or a proxy that strips Upgrade): ask for WebSocket to %s to be allowed.", host, host)
	conn, resp, err := dialRelay(ctx, a.cfg.Relay, a.tls)
	switch {
	case err != nil && resp != nil && strings.HasPrefix(resp.Header.Get("Server"), relayServer):
		// The relay upgrades every request that asks to: one answered like a plain request lost its
		// Upgrade header on the way, to a proxy or firewall that does not pass WebSocket.
		fix := fmt.Sprintf("A proxy or firewall between this machine and %s strips the WebSocket Upgrade header: "+
			"ask for WebSocket to %s to be allowed, or for %s to be exempt from TLS inspection.", host, host, host)
		if !builtInRelay(a.cfg.Relay) {
			fix += " With a custom --relay, also check its path."
		}
		s.add("FAIL", "websocket", fmt.Sprintf("the relay answered HTTP %d, as to a plain request: the WebSocket "+
			"upgrade did not reach it", resp.StatusCode), fix)
		return
	case err != nil && resp != nil:
		s.add("FAIL", "websocket", fmt.Sprintf("the WebSocket upgrade was answered with HTTP %d%s", resp.StatusCode, device(resp.Header)), blocked)
		return
	case err != nil:
		s.add("FAIL", "websocket", fmt.Sprintf("the WebSocket upgrade failed (%s)", why(err)), blocked)
		return
	}
	defer conn.Close()
	s.add("PASS", "websocket", "upgraded (HTTP 101)", "")

	var seen ssh.PublicKey
	conf, err := a.sshConfig(func(k ssh.PublicKey) { seen = k })
	if err != nil {
		s.add("FAIL", "tunnel", err.Error(), "Fix host_key: it must be the relay's SSH public key line.")
		return
	}
	_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))
	c, chans, reqs, err := ssh.NewClientConn(conn, a.relayAddr(), conf)
	switch {
	case seen == nil:
		s.add("FAIL", "tunnel", fmt.Sprintf("the WebSocket opened, but the relay's SSH greeting did not come through (%s)", why(err)),
			fmt.Sprintf("Something between this machine and %s inspects, buffers or cuts WebSocket traffic: "+
				"ask for %s to be exempt from TLS and WebSocket inspection.", host, host))
		return
	case a.cfg.HostKey == "":
		s.add("WARN", "tunnel", fmt.Sprintf("relay host key %s is not pinned (set host_key)", ssh.FingerprintSHA256(seen)), "")
	case err != nil && !isUnlisted(err):
		s.add("FAIL", "tunnel", fmt.Sprintf("relay host key %s does not match the pinned key: %v", ssh.FingerprintSHA256(seen), err),
			"Remove a --host-key, --env or --relay meant for another Straiker environment, or update the agent.")
		return
	default:
		s.add("PASS", "tunnel", "relay host key matches the pinned key", "")
	}
	switch {
	case a.id.Unsaved:
		if err == nil {
			ssh.NewClient(c, chans, reqs).Close()
		}
		s.add("INFO", "login", "not checked: the agent has no key yet (it creates one when it first runs)", "")
	case err == nil:
		ssh.NewClient(c, chans, reqs).Close()
		s.add("PASS", "login", "an Ascend app lists this agent's key: the relay accepts it", "")
	case isUnlisted(err):
		s.add("WAIT", "login", "no Ascend app lists this agent's key yet",
			fmt.Sprintf("Paste the request template above into the Ascend app (or the key into an existing app's "+
				"_tunnel_agent_keys), then click Test connection. "+
				"Already pasted? Check that the app is in org %s and lists this exact key (a new state dir means "+
				"a new key).", a.id.Tenant))
	default:
		s.add("FAIL", "login", fmt.Sprintf("relay SSH login: %v", err), "")
	}
}

// probeTargets checks each allowlisted target from this machine: reachable, and whether it speaks TLS
// or plain HTTP, which decides the app URL's scheme.
func (a *Agent) probeTargets(ctx context.Context) steps {
	var s steps
	for _, f := range a.cfg.Forwards {
		s.add("INFO", "app", fmt.Sprintf("%s is reached at %s/... (the Ascend app's URL, with its path)", f.Addr(), f.AppURL()), "")
		c, err := dialWithin(ctx, f.Addr())
		if err != nil {
			s.add("FAIL", "target", fmt.Sprintf("%s is not reachable from this machine: %s", f.Addr(), targetWhy(err, f)), targetFix(err, f))
			continue
		}
		switch speaks(ctx, c, f.Host, a.tls) {
		case "plain":
			if f.Port != 80 {
				s.add("WARN", "target", fmt.Sprintf("%s answers plain HTTP, not TLS", f.Addr()),
					fmt.Sprintf("Use http:// in the Ascend app's URL: http://%s.%s/...", f.Host, config.TunnelSuffix))
				continue
			}
			s.add("PASS", "target", f.Addr()+" reachable (plain HTTP)", "")
		case "tls":
			if f.Port == 80 {
				s.add("WARN", "target", fmt.Sprintf("%s answers TLS on port 80", f.Addr()),
					fmt.Sprintf("Use https:// in the Ascend app's URL: https://%s.%s/...", f.Host, config.TunnelSuffix))
				continue
			}
			s.add("PASS", "target", f.Addr()+" reachable (TLS)", "")
		default:
			s.add("PASS", "target", f.Addr()+" reachable", "")
		}
	}
	return s
}

// speaks says whether the target at c answers a TLS hello ("tls"), plain HTTP ("plain"), or neither
// clearly (""). The handshake verifies as usual: a certificate it cannot verify, or a TLS alert, still
// shows the target speaks TLS. It closes c.
func speaks(ctx context.Context, c net.Conn, host string, base *tls.Config) string {
	defer c.Close()
	cfg := base.Clone()
	cfg.ServerName = host // an IP is verified against the certificate's IP SANs, and sent as no SNI
	hctx, cancel := context.WithTimeout(ctx, checkDialTimeout)
	defer cancel()
	err := tls.Client(c, cfg).HandshakeContext(hctx)
	var notTLS tls.RecordHeaderError
	var unverified *tls.CertificateVerificationError
	var alert tls.AlertError
	switch {
	case err == nil, errors.As(err, &unverified), errors.As(err, &alert):
		return "tls"
	case errors.As(err, &notTLS):
		return "plain"
	}
	return ""
}

func targetWhy(err error, f config.Forward) string {
	switch w := why(err); w {
	case "not resolvable":
		return "this machine cannot resolve " + f.Host
	case "timed out":
		return "no answer (dropped by a firewall, or the host is down)"
	case "refused":
		return fmt.Sprintf("nothing listens on port %d there", f.Port)
	default:
		return w
	}
}

func targetFix(err error, f config.Forward) string {
	local := f.Host == "localhost" || strings.HasPrefix(f.Host, "127.")
	switch {
	case local && inContainer():
		return "In a container, localhost is the container itself: for an app on this machine, allow host.docker.internal instead."
	case why(err) == "not resolvable" && inContainer():
		return "Use a name the container resolves (its DNS can differ from this machine's), or the app's IP address."
	case why(err) == "not resolvable":
		return "Use a name this machine resolves, or the app's IP address."
	case why(err) == "refused":
		return fmt.Sprintf("Check the app's port: nothing is listening on %d at %s.", f.Port, f.Host)
	}
	return fmt.Sprintf("Ask your network team to let this machine reach %s.", f.Addr())
}

func dialWithin(ctx context.Context, addr string) (net.Conn, error) {
	dctx, cancel := context.WithTimeout(ctx, checkDialTimeout)
	defer cancel()
	return dialNet(dctx, "tcp", addr)
}

// why says how a connection failed, in the terms a firewall log uses.
func why(err error) string {
	var dns *net.DNSError
	var errno syscall.Errno
	switch {
	case errors.As(err, &dns):
		return "not resolvable"
	case isTimeout(err):
		return "timed out"
	case errors.As(err, &errno):
		switch errno {
		case syscall.ECONNREFUSED, 10061: // 10061..10065: Windows' WSAE* codes
			return "refused"
		case syscall.ECONNRESET, 10054:
			return "reset"
		case syscall.ENETUNREACH, syscall.EHOSTUNREACH, 10051, 10065:
			return "no route"
		}
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return "closed"
	}
	return err.Error()
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout())
}

func isClosed(err error) bool {
	w := why(err)
	return w == "closed" || w == "reset"
}

// device names the box that answered, from the headers proxies and firewalls set.
func device(h http.Header) string {
	var out string
	for _, k := range []string{"Server", "Via"} {
		if v := h.Get(k); v != "" {
			out += fmt.Sprintf(", %s %q", k, v)
		}
	}
	return out
}

func issuerName(n pkix.Name) string {
	if n.CommonName != "" {
		return n.CommonName
	}
	return n.String()
}

// relayProxyURL is the proxy the relay is dialled through, or nil for a direct connection.
func relayProxyURL(relay string) *url.URL {
	u, err := url.Parse(relay)
	if err != nil {
		return nil
	}
	u.Scheme = "https"
	p, err := proxyFunc(&http.Request{URL: u})
	if err != nil {
		return nil
	}
	return p
}

func builtInRelay(relay string) bool {
	for _, e := range config.Environments {
		if e.Relay == relay {
			return true
		}
	}
	return false
}

func inContainer() bool {
	for _, p := range []string{"/.dockerenv", "/run/.containerenv"} {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}
