package packs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/straiker-ai/ascend-tunnel/internal/agenthost/mcp"
	"github.com/straiker-ai/ascend-tunnel/internal/agenthost/policy"
)

const (
	probeTimeout   = 15 * time.Second
	probeMaxBody   = 256 << 10
	probeRedirects = 5
)

var titleRE = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// probeHeaders are the response headers worth showing; cookies and anything credential-like are not.
var probeHeaders = []string{"Content-Type", "Content-Length", "Server", "Location", "Cache-Control", "Content-Security-Policy", "X-Frame-Options"}

func httpProbe(p *policy.Policy, client *http.Client, version string, ap Approver) tool {
	props := `"target":` + targetSchema + `,"path":{"type":"string","description":"with target: path under the target's URL, e.g. /help or /api/config?x=1; default /"}`
	if ap != nil {
		props += `,"url":` + urlSchema
	}
	return tool{
		def: mcp.Tool{
			Name:        "http.probe",
			Title:       "Read a page from inside the network",
			Description: "One GET from inside the customer's network, with no cookies or credentials: a target (and an optional path under its URL), or, when the host can ask its person, a url they approve. Redirects are followed only on the same host. Returns status, selected headers, the page title and up to 256 KiB of text.",
			InputSchema: schema(`{"type":"object","properties":{` + props + `},"additionalProperties":false}`),
			Annotations: &mcp.Annotations{ReadOnlyHint: true, OpenWorldHint: true},
		},
		run: func(ctx context.Context, args json.RawMessage) mcp.Result {
			var in struct {
				Target string `json:"target"`
				Path   string `json:"path"`
				URL    string `json:"url"`
			}
			if err := decode(args, &in); err != nil {
				return failure("arguments", err)
			}
			if ap == nil && in.URL != "" {
				return refuse("this host reaches only its policy's targets")
			}
			if in.URL != "" && in.Path != "" {
				return refuse("path goes with target; put it in the url instead")
			}
			u, label, refusal, ok := site(ctx, p, ap, "http.probe", in.Target, in.URL)
			if !ok {
				return refusal
			}
			if in.Target != "" {
				var err error
				if u, err = joinPath(u, in.Path); err != nil {
					return failure("path", err)
				}
			}
			return probe(ctx, client, version, label, u)
		},
	}
}

// joinPath puts a caller's path under a target's URL. The caller never names a scheme, host, port or
// userinfo, so the request cannot leave the target; ".." cannot climb above the target's own path.
func joinPath(base *url.URL, raw string) (*url.URL, error) {
	if raw == "" {
		raw = "/"
	}
	if strings.Contains(raw, "\\") || strings.ContainsAny(raw, "\r\n\x00") {
		return nil, errors.New("path has a forbidden character")
	}
	rel, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if rel.Scheme != "" || rel.Host != "" || rel.User != nil || strings.HasPrefix(raw, "//") {
		return nil, errors.New("give a path under the target, not a URL")
	}
	if rel.Fragment != "" {
		rel.Fragment = ""
	}
	u := *base
	basePath := strings.TrimSuffix(base.Path, "/")
	joined := path.Clean("/" + rel.Path)
	if joined == "/" {
		u.Path = basePath + "/"
	} else {
		u.Path = basePath + joined
		if strings.HasSuffix(rel.Path, "/") {
			u.Path += "/"
		}
	}
	u.RawPath = ""
	u.RawQuery = rel.RawQuery
	return &u, nil
}

func probe(ctx context.Context, client *http.Client, version, target string, u *url.URL) mcp.Result {
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return failure("request", err)
	}
	req.Header.Set("User-Agent", "ascend-agent/"+version)
	req.Header.Set("Accept", "text/html,application/json;q=0.9,*/*;q=0.5")

	sameHost := *client // a copy: the redirect policy is per probe
	sameHost.Jar = nil
	var stoppedAt string
	sameHost.CheckRedirect = func(next *http.Request, via []*http.Request) error {
		if len(via) >= probeRedirects {
			stoppedAt = next.URL.String()
			return http.ErrUseLastResponse
		}
		if next.URL.Scheme != u.Scheme || next.URL.Host != u.Host {
			stoppedAt = next.URL.Scheme + "://" + next.URL.Host + "/…"
			return http.ErrUseLastResponse
		}
		return nil
	}
	start := time.Now()
	resp, err := sameHost.Do(req)
	if err != nil {
		return mcp.JSONResult(map[string]any{"target": target, "url": u.String(), "error": err.Error()}, true)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, probeMaxBody+1))
	out := map[string]any{
		"target":     target,
		"url":        resp.Request.URL.String(),
		"status":     resp.StatusCode,
		"elapsed_ms": time.Since(start).Milliseconds(),
		"headers":    selectHeaders(resp.Header),
	}
	if stoppedAt != "" {
		out["redirect_not_followed"] = stoppedAt
	}
	if err != nil {
		out["read_error"] = err.Error()
	}
	if len(body) > probeMaxBody {
		body, out["truncated"] = body[:probeMaxBody], true
	}
	out["bytes"] = len(body)
	if isText(resp.Header.Get("Content-Type"), body) {
		text := strings.ToValidUTF8(string(body), "�")
		if m := titleRE.FindStringSubmatch(text); m != nil {
			out["title"] = strings.Join(strings.Fields(m[1]), " ")
		}
		out["body"] = text
	} else {
		out["body_omitted"] = fmt.Sprintf("not text (%s)", resp.Header.Get("Content-Type"))
	}
	return mcp.JSONResult(out, false)
}

func selectHeaders(h http.Header) map[string]string {
	out := map[string]string{}
	for _, k := range probeHeaders {
		if v := h.Get(k); v != "" {
			out[k] = v
		}
	}
	return out
}

func isText(contentType string, body []byte) bool {
	mt, _, _ := mime.ParseMediaType(contentType)
	switch {
	case strings.HasPrefix(mt, "text/"), strings.HasSuffix(mt, "json"), strings.HasSuffix(mt, "xml"),
		mt == "application/javascript", mt == "application/x-www-form-urlencoded":
		return true
	case mt == "":
		return utf8.Valid(body)
	}
	return false
}
