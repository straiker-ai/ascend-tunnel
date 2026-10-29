package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	xterm "github.com/charmbracelet/x/term"

	"github.com/straiker-ai/ascend-tunnel/internal/agentclient"
	"github.com/straiker-ai/ascend-tunnel/internal/agenthost/browser"
)

var (
	styleDim      = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	styleBold     = lipgloss.NewStyle().Bold(true)
	styleQuestion = lipgloss.NewStyle().Foreground(lipgloss.Color("11")).Bold(true)
	styleGood     = lipgloss.NewStyle().Foreground(lipgloss.Color("10"))
	styleBad      = lipgloss.NewStyle().Foreground(lipgloss.Color("9"))
	styleUser     = lipgloss.NewStyle().Foreground(lipgloss.Color("12"))
	styleBar      = lipgloss.NewStyle().Foreground(lipgloss.Color("7")).Background(lipgloss.Color("236"))
)

const (
	placeholderIdle   = "ask anything, e.g. connect https://chat.example.com/api/chat as support-bot"
	placeholderAnswer = "answer the agent's question"
)

const chatHelp = `Talk to Ascend Agent in plain language. It can connect a new application ("connect <its
chat URL> as <name>"; you confirm here before anything is created), build an adaptor for one of your
applications (give it the app id from the Ascend console), and check what this machine can reach.
  /apps                 your Ascend applications
  /status               session, app, host and spend
  The commands below act on the current application (the status bar shows it); to change it, tell the
  agent ("work on support-bot").
  /source               print the current app's proposed adaptor
  /save <file>          write it to a new file
  /diff                 what the current app's latest build changed
  /har <file>           attach a HAR of the current app's chat (its next build uses it); before there
                        is an app, the agent finds the chat API in it
  /tunnel               what this machine lets Straiker reach (/tunnel close [host] to stop)
  /sites                sites you always allow from this machine (/sites forget <host>)
  /usage                today's Ascend Agent budget for your organisation
  /done                 finish a browser capture (or close its window)
  /stop                 end the session           /new   start a fresh one
  /exit                 leave (the session keeps running in the cloud for a while)
  Esc interrupts the agent. Ctrl-C twice leaves.`

type chatConfig struct {
	appID, hostID, hostMode, env, resume, user, org, policyPath string
	targets, allowHosts                                         []string
	approvals                                                   bool // the person can approve sites here
	budget                                                      agentclient.Budget
	tun                                                         *tunnels // the chat's built-in tunnel; nil when ascend-agent run serves the host
}

type approval int

const (
	approveNo approval = iota
	approveOnce
	approveAlways
)

// captureMsg is the host's capture browser opening; captureClosedMsg is the person closing its window.
type captureMsg struct {
	cp                                    *browser.Capture
	url, host, appID, instructions, agent string
	release                               func()
}

type captureClosedMsg struct{}

// What a prompt asks of the person: a site to allow (y / a / n), one action to confirm (y / n), or a secret to type.
const (
	askSite = iota
	askConfirm
	askSecret
)

// approvalMsg is the host asking the person something; reply (or secret, for a secret) takes the answer.
type approvalMsg struct {
	kind                   int
	agent, tool, url, host string
	text                   string // the question, for a confirmation or a secret
	reply                  chan approval
	secret                 chan string
	ctx                    context.Context // the host call waiting on it; once it ends, nobody is listening
}

func (a approvalMsg) expired() bool { return a.ctx != nil && a.ctx.Err() != nil }

type chatModel struct {
	ctx     context.Context
	api     *agentclient.Client
	cfg     chatConfig
	appName string
	input   textinput.Model
	spin    spinner.Model
	width   int
	sid     string
	status  string
	cost    float64
	ended   bool
	busy    bool                              // a request is in flight
	doing   string                            // the running tool, for the spinner line
	asked   bool                              // the agent is waiting for an answer
	armed   bool                              // Ctrl-C pressed once
	cands   map[string]*agentclient.Candidate // each application's latest proposal, by app id
	diffs   map[string]string                 // what each application's latest build changed
	stop    context.CancelFunc
	events  chan agentclient.Event
	asks    []approvalMsg // prompts waiting for the person, oldest first
	typed   []rune        // a secret being typed: never shown, never sent to the agent
	capture *captureMsg   // the capture browser, while it records
}

type (
	eventMsg   agentclient.Event
	startedMsg struct {
		s    *agentclient.Session
		then tea.Cmd
	}
	errMsg    struct{ err error }
	doneMsg   struct{}
	followEnd struct{}
	printMsg  struct{ line string }
)

func newChatModel(ctx context.Context, api *agentclient.Client, cfg chatConfig) *chatModel {
	in := textinput.New()
	in.Prompt = you + " "
	in.Placeholder = placeholderIdle
	in.CharLimit = 2000
	in.Focus()
	sp := spinner.New()
	sp.Spinner = spinner.Dot
	return &chatModel{ctx: ctx, api: api, cfg: cfg, input: in, spin: sp, width: 80}
}

func (m *chatModel) Init() tea.Cmd {
	sites := "you approve each site an agent wants to reach from this machine"
	if len(m.cfg.allowHosts) > 0 && !slices.Contains(m.cfg.allowHosts, "*") {
		sites = "you may approve sites under " + strings.Join(m.cfg.allowHosts, ", ")
	}
	switch {
	case !m.cfg.approvals && len(m.cfg.targets) > 0:
		sites = "agents reach only " + strings.Join(m.cfg.targets, ", ")
	case !m.cfg.approvals:
		sites = "agents can reach no sites from this machine"
	case len(m.cfg.targets) > 0:
		sites += "; " + strings.Join(m.cfg.targets, ", ") + " need no approval"
	}
	if m.cfg.policyPath != "" {
		sites += " (policy " + m.cfg.policyPath + ")"
	}
	lines := []string{
		banner(terminalWidth(), "agent "+version+" · your terminal, Straiker's red-teaming agents"),
		"",
		styleDim.Render(fmt.Sprintf("%s · org %s (%s) · host %s, %s", orNone(m.cfg.user), m.cfg.org, m.cfg.env,
			m.cfg.hostID, m.cfg.hostMode)),
		styleDim.Render(sites),
	}
	if m.cfg.appID != "" {
		lines = append(lines, styleDim.Render("app "+m.cfg.appID))
	}
	if b := m.cfg.budget; b.LimitUSD > 0 {
		lines = append(lines, styleDim.Render(fmt.Sprintf("today: $%.2f of $%.2f used (resets 00:00 UTC)", b.SpentUSD, b.LimitUSD)))
	}
	lines = append(lines, styleDim.Render("type anything to start · /help"))
	cmds := []tea.Cmd{textinput.Blink, m.spin.Tick, tea.Println(strings.Join(lines, "\n"))}
	if m.cfg.resume != "" {
		m.busy = true
		cmds = append(cmds, m.reattach(m.cfg.resume))
	}
	return tea.Batch(cmds...)
}

func (m *chatModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.input.Width = max(20, msg.Width-4)
		return m, nil
	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spin, cmd = m.spin.Update(msg)
		return m, tea.Batch(cmd, m.prune())
	case tea.KeyMsg:
		if pruned := m.prune(); len(m.asks) > 0 {
			if model, cmd, ok := m.answer(msg); ok {
				return model, tea.Batch(pruned, cmd)
			}
		}
		return m.key(msg)
	case approvalMsg:
		m.asks = append(m.asks, msg)
		return m, nil
	case captureMsg:
		m.capture = &msg
		line := "⏺ recording in the Ascend browser: " + agentclient.Clean(msg.url)
		if msg.instructions != "" {
			line += "\n  " + agentclient.Clean(msg.instructions)
		}
		line += styleDim.Render("\n  type /done when you have finished, or close the window. Cookies, auth headers and passwords are removed on this machine.")
		done := msg.cp.Done()
		return m, tea.Batch(m.print(line), func() tea.Msg { <-done; return captureClosedMsg{} })
	case captureClosedMsg:
		return m, m.finishCapture()
	case startedMsg:
		m.busy = false
		m.sid, m.status = msg.s.SID, msg.s.Status
		if msg.s.AppID != "" && m.cfg.appID == "" {
			m.cfg.appID = msg.s.AppID
			m.input.Prompt = promptFor(m.cfg.appID, m.appName)
		}
		note := "session " + m.sid
		if len(msg.s.HostTools) > 0 {
			note += " · agents may use " + strings.Join(msg.s.HostTools, ", ") + " on this machine"
		}
		return m, tea.Batch(tea.Println(styleDim.Render(note)), m.follow(), msg.then)
	case eventMsg:
		return m, tea.Batch(m.event(agentclient.Event(msg)), m.next())
	case followEnd:
		return m, nil
	case printMsg:
		return m, tea.Println(msg.line)
	case errMsg:
		m.busy = false
		// Wrapped to the terminal: an unwrapped long line is drawn over the input line.
		return m, m.print(styleBad.Width(max(20, m.width-2)).Render("✗ " + agentclient.Clean(msg.err.Error())))
	case doneMsg:
		m.busy = false
		return m, nil
	}
	return m, nil
}

// prune drops approvals whose host call already gave up, so a stale prompt never holds the terminal.
func (m *chatModel) prune() tea.Cmd {
	var cmds []tea.Cmd
	kept := m.asks[:0]
	for _, a := range m.asks {
		if a.expired() {
			what := agentclient.Clean(a.host) + " was not allowed"
			if a.kind != askSite {
				what, m.typed = "nothing was done", nil
			}
			cmds = append(cmds, m.print(styleDim.Render("✗ no answer in time: "+what)))
			continue
		}
		kept = append(kept, a)
	}
	m.asks = kept
	return tea.Batch(cmds...)
}

// answer takes y / a / n (Esc is no) for the oldest pending site approval, when the input line is empty; any
// other key types as usual, so commands such as /stop still work while a prompt is showing.
func (m *chatModel) answer(k tea.KeyMsg) (tea.Model, tea.Cmd, bool) {
	ask := m.asks[0]
	switch ask.kind {
	case askSecret:
		return m.answerSecret(k)
	case askConfirm:
		return m.answerConfirm(k)
	}
	var ans approval
	var line string
	key := k.String()
	switch {
	case k.Type == tea.KeyEsc:
		ans, line = approveNo, styleDim.Render("✗ not allowed: "+agentclient.Clean(ask.host))
	case m.input.Value() != "":
		return m, nil, false
	case key == "y":
		ans, line = approveOnce, styleGood.Render("✔ allowed for this session: "+agentclient.Clean(ask.host))
	case key == "a":
		ans, line = approveAlways, styleGood.Render("✔ always allowed: "+agentclient.Clean(ask.host)+" (/sites to review)")
	case key == "n":
		ans, line = approveNo, styleDim.Render("✗ not allowed: "+agentclient.Clean(ask.host))
	default:
		return m, nil, false
	}
	ask.reply <- ans
	m.asks = m.asks[1:]
	return m, m.print(line), true
}

// answerConfirm takes y / n (Esc is no) for a confirmation, when the input line is empty.
func (m *chatModel) answerConfirm(k tea.KeyMsg) (tea.Model, tea.Cmd, bool) {
	ask := m.asks[0]
	var ans approval
	var line string
	switch key := k.String(); {
	case k.Type == tea.KeyEsc || (m.input.Value() == "" && key == "n"):
		ans, line = approveNo, styleDim.Render("✗ not confirmed: nothing was done")
	case m.input.Value() == "" && key == "y":
		ans, line = approveOnce, styleGood.Render("✔ confirmed")
	default:
		return m, nil, false
	}
	ask.reply <- ans
	m.asks = m.asks[1:]
	return m, m.print(line), true
}

// answerSecret takes every key while a secret is asked for: Enter gives it to the tool, Esc cancels. What is typed
// is never shown and never reaches the input line.
func (m *chatModel) answerSecret(k tea.KeyMsg) (tea.Model, tea.Cmd, bool) {
	ask := m.asks[0]
	switch k.Type {
	case tea.KeyEnter:
		ask.secret <- string(m.typed)
		m.typed, m.asks = nil, m.asks[1:]
		return m, m.print(styleGood.Render("✔ entered (not shown)")), true
	case tea.KeyEsc, tea.KeyCtrlC:
		ask.secret <- ""
		m.typed, m.asks = nil, m.asks[1:]
		return m, m.print(styleDim.Render("✗ cancelled: nothing was done")), true
	case tea.KeyBackspace:
		if len(m.typed) > 0 {
			m.typed = m.typed[:len(m.typed)-1]
		}
	case tea.KeyRunes, tea.KeySpace:
		if len(m.typed) < 4096 {
			m.typed = append(m.typed, k.Runes...)
		}
	}
	return m, nil, true
}

func (m *chatModel) key(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch k.Type {
	case tea.KeyCtrlC:
		if m.armed {
			return m, m.quit()
		}
		m.armed = true
		return m, m.print(styleDim.Render("Press Ctrl-C again to leave. /stop ends the session first."))
	case tea.KeyCtrlD:
		if m.input.Value() == "" {
			return m, m.quit()
		}
	case tea.KeyEsc:
		if m.sid != "" && !m.ended && m.status != "awaiting_input" {
			sid := m.sid
			return m, m.call(func(ctx context.Context) error { return m.api.Interrupt(ctx, sid) }, "interrupting…")
		}
		return m, nil
	case tea.KeyEnter:
		m.armed = false
		line := strings.TrimSpace(m.input.Value())
		m.input.SetValue("")
		if line == "" {
			return m, nil
		}
		if strings.HasPrefix(line, "/") {
			return m.command(line)
		}
		return m, m.say(line)
	}
	m.armed = false
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(k)
	return m, cmd
}

// uploadTime bounds a HAR upload: under the gateway's 300 s response timeout.
const uploadTime = 280 * time.Second

// session runs fn against the current session, starting one first if there is none.
func (m *chatModel) session(first string, fn func(ctx context.Context, sid string) error) tea.Cmd {
	return m.sessionWithin(60*time.Second, first, fn)
}

func (m *chatModel) sessionWithin(limit time.Duration, first string, fn func(ctx context.Context, sid string) error) tea.Cmd {
	if m.busy {
		return m.print(styleDim.Render("still sending the last message…"))
	}
	if m.ended {
		return m.print(styleDim.Render("this session has ended: /new starts another"))
	}
	m.busy = true
	m.asked = false
	m.input.Placeholder = placeholderIdle
	if m.sid == "" {
		req := agentclient.StartRequest{Message: first, AppID: m.cfg.appID, HostID: m.cfg.hostID}
		return func() tea.Msg {
			ctx, cancel := context.WithTimeout(m.ctx, 90*time.Second)
			defer cancel()
			s, err := m.api.StartSession(ctx, req)
			if err != nil {
				return errMsg{err}
			}
			var then tea.Cmd
			if fn != nil {
				sid := s.SID
				then = func() tea.Msg {
					ctx, cancel := context.WithTimeout(m.ctx, limit)
					defer cancel()
					if err := fn(ctx, sid); err != nil {
						return errMsg{err}
					}
					return doneMsg{}
				}
			}
			return startedMsg{s: s, then: then}
		}
	}
	sid := m.sid
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(m.ctx, limit)
		defer cancel()
		if err := fn(ctx, sid); err != nil {
			return errMsg{err}
		}
		return doneMsg{}
	}
}

func (m *chatModel) say(text string) tea.Cmd {
	if m.sid == "" {
		return m.session(text, nil)
	}
	return m.session("", func(ctx context.Context, sid string) error { return m.api.Send(ctx, sid, text) })
}

func (m *chatModel) attachHAR(arg string) tea.Cmd {
	path, app, label := strings.TrimSpace(arg), m.cfg.appID, m.appLabel()
	if app == "" {
		label = "this session (no application yet: the agent finds the chat API in it)"
	}
	if path == "" {
		return m.print(styleDim.Render("usage: /har <file> (for the current application, or before there is one)"))
	}
	info, err := os.Stat(path)
	if err != nil {
		return m.print(styleBad.Render("✗ " + err.Error()))
	}
	if info.Size() > 512<<20 {
		return m.print(styleBad.Render(fmt.Sprintf("✗ %s is %d MB; record a shorter session", path, info.Size()>>20)))
	}
	upload := func(ctx context.Context, sid string) error {
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		har, _, err := browser.Shrink(raw, browser.MaxUploadBytes)
		if err != nil {
			return err
		}
		_, err = m.api.UploadHAR(ctx, sid, app, "", "I attached a HAR of the chat ("+fileBase(path)+").", har)
		if err != nil {
			return fmt.Errorf("HAR upload for %s: %w", label, err)
		}
		return nil
	}
	return tea.Batch(m.print(styleDim.Render(fmt.Sprintf("⏺ uploading %s (%d KB) for %s: Straiker keeps only a redacted trace",
		fileBase(path), info.Size()>>10, label))), m.sessionWithin(uploadTime, "", upload))
}

// finishCapture stops the capture browser, keeps a redacted copy, and sends the HAR to the session.
func (m *chatModel) finishCapture() tea.Cmd {
	c := m.capture
	if c == nil {
		return nil
	}
	m.capture = nil
	full, st := c.cp.Stop()
	c.release()
	path, err := keepCapture(full)
	if err != nil {
		return m.print(styleBad.Render("✗ " + err.Error()))
	}
	har, _, err := browser.Shrink(full, browser.MaxUploadBytes)
	if err != nil {
		return m.print(styleBad.Render("✗ " + err.Error() + " (saved at " + path + ")"))
	}
	app := c.appID
	if app == "" {
		app = m.cfg.appID
	}
	host := ""
	if app == "" {
		host = c.host // no application yet: the recorded page's host picks the requests that matter
	}
	note := fmt.Sprintf("⏺ captured %d requests (%d API calls), saved to %s", st.Requests, st.API, path)
	text := fmt.Sprintf("I used the browser as asked and finished (%d requests, %d API calls captured).", st.Requests, st.API)
	return tea.Batch(m.print(styleDim.Render(note)), m.sessionWithin(uploadTime, "", func(ctx context.Context, sid string) error {
		if _, err := m.api.UploadHAR(ctx, sid, app, host, text, har); err != nil {
			return fmt.Errorf("HAR upload: %w (it is saved at %s: /har %s sends it again)", err, path, path)
		}
		return nil
	}))
}

// agentName is how a person sees the agent asking: Straiker's agents by name, anything else as signed.
func agentName(id string) string {
	switch id {
	case "ascend":
		return "Ascend Agent"
	case "adaptor-builder":
		return "the adaptor builder"
	}
	return orNone(agentclient.Clean(id))
}

// apps lists the person's Ascend applications straight from Straiker, with their own login: no agent, no model.
func (m *chatModel) apps() tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(m.ctx, 30*time.Second)
		defer cancel()
		var b strings.Builder
		after, n := "", 0
		for n < 300 {
			q := url.Values{"limit": {"100"}}
			if after != "" {
				q.Set("starting_after", after)
			}
			var page struct {
				Data []struct {
					ID   string `json:"id"`
					Name string `json:"name"`
					URL  string `json:"url"`
				} `json:"data"`
				HasMore bool `json:"has_more"`
			}
			if err := m.api.GetJSON(ctx, "/api/v3/ascend/applications", q, &page); err != nil {
				return errMsg{err}
			}
			for _, a := range page.Data {
				fmt.Fprintf(&b, "  %s  %s  %s\n", agentclient.Clean(a.Name), styleDim.Render(agentclient.Clean(a.ID)),
					styleDim.Render(agentclient.Clean(a.URL)))
				n++
			}
			if !page.HasMore || len(page.Data) == 0 {
				break
			}
			after = page.Data[len(page.Data)-1].ID
		}
		if n == 0 {
			return printMsg{"no Ascend applications yet: ask the agent to connect one (\"connect <chat URL> as <name>\")"}
		}
		return printMsg{fmt.Sprintf("%d application(s):\n%s", n, strings.TrimRight(b.String(), "\n"))}
	}
}

// keepCapture saves a capture (already redacted) under ~/.ascend-agent/captures, readable only by this user.
func keepCapture(har []byte) (string, error) {
	home, err := agentclient.Home()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, "captures")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, time.Now().Format("20060102-150405")+".har")
	return path, os.WriteFile(path, har, 0o600)
}

func fileBase(p string) string {
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		return p[i+1:]
	}
	return p
}

func (m *chatModel) reattach(sid string) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(m.ctx, 30*time.Second)
		defer cancel()
		s, err := m.api.GetSession(ctx, sid)
		if err != nil {
			return errMsg{err}
		}
		return startedMsg{s: s}
	}
}

func (m *chatModel) call(fn func(context.Context) error, note string) tea.Cmd {
	return tea.Batch(m.print(styleDim.Render(note)), func() tea.Msg {
		ctx, cancel := context.WithTimeout(m.ctx, 30*time.Second)
		defer cancel()
		if err := fn(ctx); err != nil {
			return errMsg{err}
		}
		return doneMsg{}
	})
}

// follow streams the session's events into the program; next delivers them one at a time.
func (m *chatModel) follow() tea.Cmd {
	if m.stop != nil {
		m.stop()
	}
	ctx, cancel := context.WithCancel(m.ctx)
	m.stop = cancel
	m.events = make(chan agentclient.Event, 64)
	sid, ch := m.sid, m.events
	go func() {
		_ = m.api.Follow(ctx, sid, "", ch)
		close(ch)
	}()
	return m.next()
}

func (m *chatModel) next() tea.Cmd {
	ch := m.events
	if ch == nil {
		return nil
	}
	return func() tea.Msg {
		e, ok := <-ch
		if !ok {
			return followEnd{}
		}
		return eventMsg(e)
	}
}

func (m *chatModel) event(e agentclient.Event) tea.Cmd {
	switch e.Type {
	case "session.status":
		m.status = e.Status
		if e.Terminal() {
			m.ended, m.doing = true, ""
		}
		if e.Status == "awaiting_input" {
			m.doing = ""
		}
	case "session.app":
		m.cfg.appID, m.appName = e.AppID, e.Name
		m.input.Prompt = promptFor(e.AppID, e.Name)
	case "usage":
		m.cost = e.CostUSD
		if e.DailyUSD > 0 {
			m.cfg.budget.SpentUSD, m.cfg.budget.LimitUSD = e.TodayUSD, e.DailyUSD
		}
	case "tool.start":
		m.doing = toolLabel(e.Name, e.Where)
	case "tool.end":
		m.doing = ""
	case "build.start":
		m.doing = "adaptor builder"
	case "agent.question":
		m.asked = true
		m.input.Placeholder = placeholderAnswer
	case "build.result":
		m.doing = ""
		app := pick(e.AppID, m.cfg.appID)
		if m.cands == nil {
			m.cands, m.diffs = map[string]*agentclient.Candidate{}, map[string]string{}
		}
		if e.Cand != nil && e.Cand.Source != "" {
			m.cands[app] = e.Cand
		} else {
			delete(m.cands, app) // a build that proposed nothing leaves nothing to save for that app
		}
		m.diffs[app] = e.Diff
	}
	lines := renderEvent(e, m.width)
	if len(lines) == 0 {
		return nil
	}
	return tea.Println(strings.Join(lines, "\n"))
}

func (m *chatModel) command(line string) (tea.Model, tea.Cmd) {
	name, arg, _ := strings.Cut(line, " ")
	arg = strings.TrimSpace(arg)
	switch name {
	case "/help":
		return m, m.print(chatHelp)
	case "/status":
		app := orNone(m.cfg.appID)
		if m.appName != "" {
			app = m.appName + " (" + m.cfg.appID + ")"
		}
		return m, m.print(fmt.Sprintf("session %s · %s · $%.2f · app %s · host %s (%s)", orNone(m.sid), orNone(m.status),
			m.cost, agentclient.Clean(app), m.cfg.hostID, m.cfg.hostMode))
	case "/source":
		cand, why := m.current()
		if cand == nil {
			return m, m.print(styleDim.Render(why))
		}
		return m, m.print(styleDim.Render("adaptor for "+m.appLabel()+":") + "\n" + agentclient.Clean(cand.Source))
	case "/diff":
		if m.cfg.appID == "" {
			return m, m.print(styleDim.Render(noCurrentApp))
		}
		if m.diffs[m.cfg.appID] == "" {
			return m, m.print(styleDim.Render("no diff for " + m.appLabel() + ": its latest build did not revise an earlier adaptor"))
		}
		return m, m.print(styleDim.Render("changes for "+m.appLabel()+":") + "\n" + agentclient.Clean(m.diffs[m.cfg.appID]))
	case "/save":
		return m, m.save(arg)
	case "/har":
		return m, m.attachHAR(arg)
	case "/sites":
		return m, m.sites(arg)
	case "/tunnel", "/tunnels":
		return m, m.tunnel(arg)
	case "/done":
		if m.capture == nil {
			return m, m.print(styleDim.Render("no browser capture is running"))
		}
		return m, m.finishCapture()
	case "/apps":
		return m, m.apps()
	case "/usage":
		return m, func() tea.Msg {
			ctx, cancel := context.WithTimeout(m.ctx, 20*time.Second)
			defer cancel()
			b, err := m.api.Usage(ctx)
			if err != nil {
				return errMsg{err}
			}
			m.cfg.budget = *b
			return printMsg{fmt.Sprintf("today (UTC) your organisation has used $%.2f of $%.2f; $%.2f left; resets %s",
				b.SpentUSD, b.LimitUSD, b.RemainingUSD, agentclient.Clean(b.ResetsAt))}
		}
	case "/stop":
		if m.sid == "" || m.ended {
			return m, m.print(styleDim.Render("no session is running"))
		}
		sid := m.sid
		return m, m.call(func(ctx context.Context) error { return m.api.Cancel(ctx, sid) }, "ending the session…")
	case "/new":
		var cmd tea.Cmd
		if m.sid != "" && !m.ended {
			sid := m.sid
			cmd = m.call(func(ctx context.Context) error { return m.api.Cancel(ctx, sid) }, "ending the session…")
		}
		if m.stop != nil {
			m.stop()
		}
		m.sid, m.status, m.ended, m.cands, m.diffs, m.cost, m.events, m.asked = "", "", false, nil, nil, 0, nil, false
		m.input.Placeholder = placeholderIdle
		return m, tea.Batch(cmd, m.print(styleDim.Render("Your next message starts a new session.")))
	case "/exit", "/quit":
		return m, m.quit()
	}
	return m, m.print(styleDim.Render("unknown command " + name + ": /help lists them"))
}

// sites lists the sites always allowed for this org, or forgets one.
func (m *chatModel) sites(arg string) tea.Cmd {
	if host, ok := strings.CutPrefix(arg, "forget "); ok {
		host = strings.TrimSpace(host)
		removed, err := agentclient.ForgetSite(m.cfg.org, host)
		switch {
		case err != nil:
			return m.print(styleBad.Render("✗ " + err.Error()))
		case !removed:
			return m.print(styleDim.Render(agentclient.Clean(host) + " was not always allowed"))
		}
		return m.print(styleDim.Render("forgot " + agentclient.Clean(host) + ": you will be asked again"))
	}
	list := agentclient.Sites(m.cfg.org)
	if len(list) == 0 {
		return m.print(styleDim.Render("no sites are always allowed; you are asked about each one"))
	}
	return m.print("always allowed for org " + m.cfg.org + ":\n  " + strings.Join(list, "\n  ") +
		styleDim.Render("\n/sites forget <host> to be asked again"))
}

// promptFor is the input line's prompt: the current application before it, as a shell shows the git branch.
func promptFor(appID, name string) string {
	switch {
	case name != "":
		return styleDim.Render("("+agentclient.Clean(name)+")") + " " + you + " "
	case appID != "":
		return styleDim.Render("("+appID[:min(8, len(appID))]+")") + " " + you + " "
	}
	return you + " "
}

// noCurrentApp is what a command that acts on the current application says when there is none.
const noCurrentApp = "no current application: tell the agent which one to work on (e.g. \"work on support-bot\")"

// current is the current application's latest proposal, or why there is none.
func (m *chatModel) current() (*agentclient.Candidate, string) {
	if m.cfg.appID == "" {
		return nil, noCurrentApp
	}
	if c := m.cands[m.cfg.appID]; c != nil {
		return c, ""
	}
	return nil, "no proposed adaptor for " + m.appLabel() + " yet"
}

// appLabel names the current application: its name and id, or its id.
func (m *chatModel) appLabel() string {
	if m.appName != "" {
		return agentclient.Clean(m.appName) + " (" + m.cfg.appID + ")"
	}
	return m.cfg.appID
}

// tunnel lists what the chat's built-in tunnel lets Straiker reach, or closes it ("close", or "close <host>").
func (m *chatModel) tunnel(arg string) tea.Cmd {
	if m.cfg.tun == nil {
		return m.print(styleDim.Render("no tunnel in this chat: ascend-agent run serves this machine"))
	}
	if what, ok := strings.CutPrefix(arg+" ", "close "); ok {
		gone, err := m.cfg.tun.shut(strings.TrimSpace(what))
		if err != nil {
			return m.print(styleDim.Render(err.Error()))
		}
		return m.print(styleGood.Render("✔ closed "+strings.Join(gone, ", ")+": Straiker no longer reaches it through this machine") +
			styleDim.Render("\n  applications on its tunnel address fail until a tunnel runs again; to keep one running:\n  "+
				m.cfg.tun.keepCommand(gone)))
	}
	if arg != "" {
		return m.print(styleDim.Render("usage: /tunnel, or /tunnel close [host]"))
	}
	open := m.cfg.tun.list()
	if len(open) == 0 {
		return m.print(styleDim.Render("no tunnel open: Straiker reaches nothing through this machine"))
	}
	lines := []string{"Straiker reaches through this machine, until you exit or /tunnel close:"}
	for _, o := range open {
		use := fmt.Sprintf("%d connection(s)", o.conns)
		if o.failed > 0 {
			use += fmt.Sprintf(", %d failed", o.failed)
		}
		lines = append(lines, fmt.Sprintf("  ⇄ %s  open %s · %s", o.addr, time.Since(o.since).Round(time.Second), use))
	}
	return m.print(strings.Join(lines, "\n"))
}

func (m *chatModel) save(path string) tea.Cmd {
	cand, why := m.current()
	if cand == nil {
		return m.print(styleDim.Render(why))
	}
	if path == "" {
		return m.print(styleDim.Render("usage: /save <file>"))
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return m.print(styleBad.Render("✗ " + err.Error()))
	}
	_, err = f.WriteString(cand.Source)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return m.print(styleBad.Render("✗ " + err.Error()))
	}
	return m.print(styleGood.Render(fmt.Sprintf("✔ wrote %s: the adaptor for %s (%d bytes)", path, m.appLabel(), len(cand.Source))))
}

func (m *chatModel) quit() tea.Cmd {
	if m.stop != nil {
		m.stop()
	}
	if m.capture != nil {
		m.capture.cp.Stop()
		m.capture.release()
		m.capture = nil
	}
	return tea.Quit
}

func (m *chatModel) print(s string) tea.Cmd { return tea.Println(s) }

func (m *chatModel) View() string {
	var b strings.Builder
	if len(m.asks) > 0 && m.asks[0].kind == askConfirm {
		a := m.asks[0]
		b.WriteString(styleQuestion.Render(fmt.Sprintf("? Allow %s to %s?", agentName(a.agent), agentclient.Clean(a.text))) + "\n")
		b.WriteString("  [y] yes   [n] no\n")
	} else if len(m.asks) > 0 && m.asks[0].kind == askSecret {
		b.WriteString(styleQuestion.Render("? "+agentclient.Clean(m.asks[0].text)) + "\n")
		b.WriteString(fmt.Sprintf("  type it and press Enter (%d characters, not shown); Esc cancels\n", len(m.typed)))
	} else if len(m.asks) > 0 {
		a := m.asks[0]
		verb := map[string]string{"http.probe": "read", "net.check": "check that it can reach",
			"browser.capture": "open a browser and record you using"}[a.tool]
		if verb == "" {
			verb = "use " + a.tool + " on"
		}
		b.WriteString(styleQuestion.Render(fmt.Sprintf("? Allow %s to %s %s from this machine?",
			agentName(a.agent), verb, agentclient.Clean(a.url))) + "\n")
		b.WriteString(fmt.Sprintf("  [y] this session   [a] always for %s   [n] no\n", agentclient.Clean(a.host)))
	}
	if m.capture != nil {
		b.WriteString(styleQuestion.Render("● recording "+agentclient.Clean(m.capture.host)+" in the Ascend browser") +
			styleDim.Render("  /done when finished") + "\n")
	}
	switch {
	case m.asked:
		b.WriteString(styleQuestion.Render("? waiting for your answer") + "\n")
	case m.doing != "":
		b.WriteString(m.spin.View() + " " + m.doing + styleDim.Render("  (Esc to interrupt)") + "\n")
	case m.busy || m.status == "running" || m.status == "building":
		b.WriteString(m.spin.View() + " thinking…" + styleDim.Render("  (Esc to interrupt)") + "\n")
	}
	b.WriteString(m.input.View() + "\n")
	bar := fmt.Sprintf(" Ascend Agent · %s · $%.2f · host %s ", orNone(m.status), m.cost, m.cfg.hostID)
	if b := m.cfg.budget; b.LimitUSD > 0 {
		bar = fmt.Sprintf(" Ascend Agent · %s · today $%.2f of $%.2f · host %s ", orNone(m.status), b.SpentUSD, b.LimitUSD, m.cfg.hostID)
	}
	if m.cfg.appID != "" {
		app := m.cfg.appID[:8]
		if m.appName != "" {
			app = agentclient.Clean(m.appName)
		}
		bar += "· app " + app + " "
	}
	if m.cfg.tun != nil {
		if open := m.cfg.tun.list(); len(open) > 0 {
			addrs := make([]string, len(open))
			for i, o := range open {
				addrs[i] = o.addr
			}
			bar += "· ⇄ " + strings.Join(addrs, ", ") + " "
		}
	}
	b.WriteString(styleBar.Render(bar))
	return b.String()
}

func toolLabel(name, where string) string {
	label := strings.TrimPrefix(name, "host_")
	switch name {
	case "build_adaptor":
		return "adaptor builder"
	case "get_app":
		return "looking up the application"
	case "ask_user":
		return "question for you"
	}
	if where == "local" {
		return label + " · on this machine"
	}
	return label + " · cloud"
}

// renderEvent turns one event into lines for the transcript. Every string from the cloud goes through Clean.
func renderEvent(e agentclient.Event, width int) []string {
	wrap := lipgloss.NewStyle().Width(max(20, width-2))
	c := agentclient.Clean
	switch e.Type {
	case "user.message":
		return []string{styleUser.Render(wrap.Render(you + " " + c(e.Text)))}
	case "assistant.text":
		return []string{styleBrand.Render(star) + " " + lipgloss.NewStyle().Width(max(20, width-4)).Render(c(e.Text))}
	case "tool.start":
		switch e.Name {
		case "ask_user", "needs_human", "build_adaptor", "get_app":
			return nil // shown by their own events
		}
		line := "⏺ " + toolLabel(c(e.Name), e.Where)
		if e.Detail != "" {
			line += styleDim.Render("  " + c(e.Detail))
		}
		return []string{line}
	case "tool.event":
		if e.Tool == "ask_user" || e.Tool == "needs_human" {
			return nil
		}
		return []string{styleDim.Render(wrap.Render("  └ " + c(e.Summary)))}
	case "agent.question":
		return []string{styleQuestion.Render(wrap.Render("? " + c(e.Question)))}
	case "session.app":
		label := c(e.AppID)
		if e.Name != "" {
			label = c(e.Name) + " (" + label + ")"
		}
		return []string{styleDim.Render("· app " + label)}
	case "note":
		return []string{styleDim.Render(wrap.Render("· " + c(e.Message)))}
	case "build.start":
		what := "⏺ adaptor builder: building"
		if e.Revising {
			what = "⏺ adaptor builder: revising the last adaptor"
		}
		return []string{what + styleDim.Render(" ("+c(e.Model)+")")}
	case "build.result":
		return renderResult(e, wrap)
	case "error":
		return []string{styleBad.Render(wrap.Render("✗ " + c(e.Message)))}
	case "session.status":
		if e.Terminal() {
			line := "session " + c(e.Status)
			if e.Reason != "" {
				line += ": " + c(e.Reason)
			}
			return []string{styleDim.Render(line)}
		}
	}
	return nil
}

func renderResult(e agentclient.Event, wrap lipgloss.Style) []string {
	c := agentclient.Clean
	switch e.Status {
	case "proposed":
		head := "  ✔ proposed an adaptor"
		if e.Cand != nil {
			head += fmt.Sprintf(" (%d bytes)", e.Cand.Bytes)
		}
		if e.Path == "fast" {
			head += ": a standard chat API (" + c(e.Pattern) + "), no model needed"
		}
		lines := []string{styleGood.Render(head)}
		if e.Checks != nil && len(e.Checks.Warnings) > 0 {
			lines = append(lines, styleQuestion.Render(wrap.Render("    warnings: "+c(joinRaw(e.Checks.Warnings)))))
		}
		return append(lines, styleDim.Render("    /source to read it · /save <file> to keep it (while this application is current)"))
	case "needs_human":
		return []string{styleQuestion.Render(wrap.Render("  ⚠ the builder stopped: " + c(e.Reason)))}
	case "cancelled":
		return []string{styleDim.Render("  build stopped")}
	}
	return []string{styleBad.Render(wrap.Render("  ✗ build " + c(e.Status) + ": " + c(e.Reason)))}
}

func joinRaw(items []json.RawMessage) string {
	parts := make([]string, 0, len(items))
	for _, it := range items {
		var s string
		if json.Unmarshal(it, &s) == nil {
			parts = append(parts, s)
		} else {
			parts = append(parts, string(it))
		}
	}
	return strings.Join(parts, "; ")
}

// readSecret reads a line without echo from a terminal, or plainly from a pipe (through in, which may have
// buffered input already).
func readSecret(stdin io.Reader, in *bufio.Reader) (string, error) {
	if f, ok := stdin.(*os.File); ok && xterm.IsTerminal(f.Fd()) {
		b, err := xterm.ReadPassword(f.Fd())
		return strings.TrimSpace(string(b)), err
	}
	line, err := in.ReadString('\n')
	if err == io.EOF && line != "" {
		err = nil
	}
	return strings.TrimSpace(line), err
}
