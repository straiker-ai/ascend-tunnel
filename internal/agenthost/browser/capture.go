package browser

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// extraArgs are added to the browser's command line; tests run it headless.
var extraArgs []string

// ErrNoBrowser means no Chromium-family browser was found.
var ErrNoBrowser = errors.New("no Chrome, Edge, Brave or Chromium found (set ASCEND_AGENT_BROWSER to one)")

// Find locates a Chromium-family browser: ASCEND_AGENT_BROWSER, else the usual install places.
func Find() (string, error) {
	if p := os.Getenv("ASCEND_AGENT_BROWSER"); p != "" {
		if _, err := os.Stat(p); err != nil {
			return "", fmt.Errorf("ASCEND_AGENT_BROWSER: %w", err)
		}
		return p, nil
	}
	var candidates []string
	switch runtime.GOOS {
	case "darwin":
		home, _ := os.UserHomeDir()
		for _, app := range []string{"Google Chrome.app/Contents/MacOS/Google Chrome", "Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
			"Brave Browser.app/Contents/MacOS/Brave Browser", "Chromium.app/Contents/MacOS/Chromium"} {
			candidates = append(candidates, filepath.Join("/Applications", app), filepath.Join(home, "Applications", app))
		}
	case "windows":
		for _, base := range []string{os.Getenv("ProgramFiles"), os.Getenv("ProgramFiles(x86)"), os.Getenv("LocalAppData")} {
			if base != "" {
				candidates = append(candidates, filepath.Join(base, `Google\Chrome\Application\chrome.exe`),
					filepath.Join(base, `Microsoft\Edge\Application\msedge.exe`),
					filepath.Join(base, `BraveSoftware\Brave-Browser\Application\brave.exe`))
			}
		}
	default:
		for _, name := range []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "microsoft-edge", "brave-browser"} {
			if p, err := exec.LookPath(name); err == nil {
				candidates = append(candidates, p)
			}
		}
	}
	for _, p := range candidates {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p, nil
		}
	}
	return "", ErrNoBrowser
}

// Capture is one recording: a visible browser window the person uses, and what it sent and received.
type Capture struct {
	cmd     *exec.Cmd
	exited  chan struct{} // closed when the browser process has exited
	c       *cdp
	rec     *recorder
	version string
	cancel  context.CancelFunc
	done    chan struct{} // closed when the person closes the browser
	pages   map[string]bool
	mu      sync.Mutex
	bodies  sync.WaitGroup
	stopped sync.Once
	har     []byte
	stats   Stats
}

// Start opens exe with the dedicated profile in profileDir (persistent, so logins survive between captures, and
// separate from the person's own browsing), starts recording, and only then loads startURL.
func Start(ctx context.Context, exe, profileDir, startURL, version string) (*Capture, error) {
	if err := os.MkdirAll(profileDir, 0o700); err != nil {
		return nil, err
	}
	portFile := filepath.Join(profileDir, "DevToolsActivePort")
	_ = os.Remove(portFile)
	args := append([]string{"--user-data-dir=" + profileDir, "--remote-debugging-port=0", "--no-first-run",
		"--no-default-browser-check", "--new-window"}, extraArgs...)
	args = append(args, strings.Fields(os.Getenv("ASCEND_AGENT_BROWSER_ARGS"))...) // e.g. --headless=new, for testing
	cmd := exec.Command(exe, append(args, "about:blank")...)
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("open the browser: %w", err)
	}
	exited := make(chan struct{})
	go func() { _ = cmd.Wait(); close(exited) }()
	wsURL, err := waitPort(ctx, portFile, exited)
	if err != nil {
		_ = cmd.Process.Kill()
		return nil, err
	}
	rctx, cancel := context.WithCancel(context.Background()) // outlives the tool call that started it
	c, err := dial(ctx, wsURL)
	if err != nil {
		cancel()
		_ = cmd.Process.Kill()
		return nil, err
	}
	cp := &Capture{cmd: cmd, exited: exited, c: c, rec: newRecorder(), version: version, cancel: cancel,
		done: make(chan struct{}), pages: map[string]bool{}}
	go cp.loop(rctx, exited)
	attach := map[string]any{"autoAttach": true, "waitForDebuggerOnStart": true, "flatten": true}
	if _, err := c.call(ctx, "", "Target.setDiscoverTargets", map[string]any{"discover": true}); err != nil {
		cp.Stop()
		return nil, err
	}
	if _, err := c.call(ctx, "", "Target.setAutoAttach", attach); err != nil {
		cp.Stop()
		return nil, err
	}
	page, err := cp.firstPage(ctx)
	if err != nil {
		cp.Stop()
		return nil, err
	}
	if _, err := c.call(ctx, page, "Page.navigate", map[string]any{"url": startURL}); err != nil {
		cp.Stop()
		return nil, err
	}
	return cp, nil
}

func waitPort(ctx context.Context, portFile string, exited <-chan struct{}) (string, error) {
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if raw, err := os.ReadFile(portFile); err == nil {
			lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
			if len(lines) == 2 {
				return "ws://127.0.0.1:" + strings.TrimSpace(lines[0]) + strings.TrimSpace(lines[1]), nil
			}
		}
		select {
		case <-exited:
			return "", errors.New("the browser closed at once: is the Ascend browser window already open? Close it and try again")
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	return "", errors.New("the browser did not open its DevTools port")
}

// firstPage attaches to the window's initial blank page and returns its session.
func (cp *Capture) firstPage(ctx context.Context) (string, error) {
	raw, err := cp.c.call(ctx, "", "Target.getTargets", nil)
	if err != nil {
		return "", err
	}
	var t struct {
		TargetInfos []struct {
			TargetID string `json:"targetId"`
			Type     string `json:"type"`
			Attached bool   `json:"attached"`
		} `json:"targetInfos"`
	}
	if err := json.Unmarshal(raw, &t); err != nil {
		return "", err
	}
	for _, ti := range t.TargetInfos {
		if ti.Type != "page" {
			continue
		}
		res, err := cp.c.call(ctx, "", "Target.attachToTarget", map[string]any{"targetId": ti.TargetID, "flatten": true})
		if err != nil {
			return "", err
		}
		var a struct {
			SessionID string `json:"sessionId"`
		}
		if err := json.Unmarshal(res, &a); err != nil {
			return "", err
		}
		cp.track(ti.TargetID, true)
		cp.prepare(ctx, a.SessionID)
		return a.SessionID, nil
	}
	return "", errors.New("the browser opened no window")
}

// prepare records a session's network and follows its frames and workers, then lets it run.
func (cp *Capture) prepare(ctx context.Context, session string) {
	_, _ = cp.c.call(ctx, session, "Network.enable", map[string]any{"maxPostDataSize": maxBodyBytes})
	_, _ = cp.c.call(ctx, session, "Target.setAutoAttach",
		map[string]any{"autoAttach": true, "waitForDebuggerOnStart": true, "flatten": true})
	_, _ = cp.c.call(ctx, session, "Runtime.runIfWaitingForDebugger", nil)
}

func (cp *Capture) track(targetID string, open bool) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	if open {
		cp.pages[targetID] = true
		return
	}
	delete(cp.pages, targetID)
}

func (cp *Capture) loop(ctx context.Context, exited <-chan struct{}) {
	closed := func() {
		select {
		case <-cp.done:
		default:
			close(cp.done)
		}
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-exited:
			closed()
			return
		case <-cp.c.closed:
			closed()
			return
		case ev := <-cp.c.events:
			switch ev.Method {
			case "Target.attachedToTarget":
				var p struct {
					SessionID  string `json:"sessionId"`
					TargetInfo struct {
						TargetID string `json:"targetId"`
						Type     string `json:"type"`
					} `json:"targetInfo"`
				}
				if json.Unmarshal(ev.Params, &p) == nil {
					if p.TargetInfo.Type == "page" {
						cp.track(p.TargetInfo.TargetID, true)
					}
					go cp.prepare(ctx, p.SessionID)
				}
			case "Target.targetCreated":
				var p struct {
					TargetInfo struct {
						TargetID string `json:"targetId"`
						Type     string `json:"type"`
					} `json:"targetInfo"`
				}
				if json.Unmarshal(ev.Params, &p) == nil && p.TargetInfo.Type == "page" {
					cp.track(p.TargetInfo.TargetID, true)
				}
			case "Target.targetDestroyed":
				var p struct {
					TargetID string `json:"targetId"`
				}
				if json.Unmarshal(ev.Params, &p) == nil {
					cp.track(p.TargetID, false)
					cp.mu.Lock()
					none := len(cp.pages) == 0
					cp.mu.Unlock()
					if none { // the person closed the last window: the capture is over
						closed()
					}
				}
			default:
				body, stream := cp.rec.handle(ev)
				if body != "" {
					cp.bodies.Add(1)
					go cp.fetchBody(ctx, ev.SessionID, body)
				}
				if stream != "" {
					go cp.follow(ctx, ev.SessionID, stream)
				}
			}
		}
	}
}

func (cp *Capture) fetchBody(ctx context.Context, session, id string) {
	defer cp.bodies.Done()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	raw, err := cp.c.call(ctx, session, "Network.getResponseBody", map[string]any{"requestId": id})
	if err != nil {
		return
	}
	var b struct {
		Body          string `json:"body"`
		Base64Encoded bool   `json:"base64Encoded"`
	}
	if json.Unmarshal(raw, &b) != nil {
		return
	}
	cp.rec.setBody(session, id, b.Body, b.Base64Encoded)
}

// follow asks Chrome for a stream's chunks as they arrive (Network.dataReceived carries them), with what it has
// buffered so far. A Chrome without it leaves the stream unrecorded, as before.
func (cp *Capture) follow(ctx context.Context, session, id string) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	raw, err := cp.c.call(ctx, session, "Network.streamResourceContent", map[string]any{"requestId": id})
	if err != nil {
		return
	}
	var b struct {
		BufferedData string `json:"bufferedData"`
	}
	if json.Unmarshal(raw, &b) == nil {
		cp.rec.streamStarted(session, id, b.BufferedData)
	}
}

// Done is closed when the person closes the browser window.
func (cp *Capture) Done() <-chan struct{} { return cp.done }

// Stop ends the recording, closes the browser, and returns the redacted HAR. Safe to call more than once.
func (cp *Capture) Stop() ([]byte, Stats) {
	cp.stopped.Do(func() {
		waited := make(chan struct{})
		go func() { cp.bodies.Wait(); close(waited) }()
		select {
		case <-waited:
		case <-time.After(5 * time.Second):
		}
		cp.har, cp.stats = cp.rec.har(cp.version)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_, _ = cp.c.call(ctx, "", "Browser.close", nil)
		cancel()
		cp.c.close()
		cp.cancel()
		// Wait for the browser to exit, so its profile is unlocked for the next capture.
		select {
		case <-cp.exited:
		case <-time.After(5 * time.Second):
			_ = cp.cmd.Process.Kill()
			<-cp.exited
		}
	})
	return cp.har, cp.stats
}
