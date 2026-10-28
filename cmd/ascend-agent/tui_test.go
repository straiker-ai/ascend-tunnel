package main

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/straiker-ai/ascend-tunnel/internal/agentclient"
)

func TestTranscriptLinesNeverCarryEscapes(t *testing.T) {
	evil := "\x1b]8;;https://evil\x07click me\x1b]8;;\x07\x1b[2J"
	for _, e := range []agentclient.Event{
		{Type: "assistant.text", Text: evil},
		{Type: "tool.event", Summary: evil},
		{Type: "agent.question", Question: evil},
		{Type: "error", Message: evil},
		{Type: "tool.start", Name: "host_http_probe", Where: "local", Detail: evil},
		{Type: "build.result", Status: "failed", Reason: evil},
		{Type: "build.result", Status: "proposed", Notes: evil, Cand: &agentclient.Candidate{Source: "x", Bytes: 1},
			Checks: &agentclient.Checks{Warnings: []json.RawMessage{mustJSON(evil)}}},
	} {
		for _, line := range renderEvent(e, 80) {
			if strings.Contains(line, "evil") || strings.Contains(line, "2J") {
				t.Errorf("%s rendered an escape payload: %q", e.Type, line)
			}
		}
	}
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func TestQuestionsShowOnce(t *testing.T) {
	q := "Which button opens the chat?"
	var shown int
	for _, e := range []agentclient.Event{
		{Type: "tool.start", Name: "ask_user", Where: "cloud", Detail: q},
		{Type: "tool.event", Tool: "ask_user", Summary: q},
		{Type: "agent.question", Question: q},
	} {
		shown += strings.Count(strings.Join(renderEvent(e, 120), "\n"), q)
	}
	if shown != 1 {
		t.Errorf("the question was shown %d times", shown)
	}
}

func TestToolsShowWhereTheyRan(t *testing.T) {
	local := strings.Join(renderEvent(agentclient.Event{Type: "tool.start", Name: "host_http_probe", Where: "local", Detail: "intranet/help"}, 80), "")
	cloud := strings.Join(renderEvent(agentclient.Event{Type: "tool.start", Name: "test", Where: "cloud"}, 80), "")
	if !strings.Contains(local, "http_probe · on this machine") || !strings.Contains(local, "intranet/help") {
		t.Errorf("local: %q", local)
	}
	if !strings.Contains(cloud, "test · cloud") {
		t.Errorf("cloud: %q", cloud)
	}
}

func TestHostNamesAreWhatEnrolmentAccepts(t *testing.T) {
	if got := safeName("Ya's MacBook Pro (2)"); got != "Yas MacBook Pro 2" {
		t.Errorf("safeName = %q", got)
	}
	if got := safeName(strings.Repeat("a", 100)); len(got) != 64 {
		t.Errorf("not capped: %d", len(got))
	}
}

func TestAppIDsAreConsoleUUIDs(t *testing.T) {
	if !appIDRE.MatchString("01a16263-de1f-7754-bd60-490a7cf2945f") || appIDRE.MatchString("aapp_6s7KARgl52Ogs18VJyQKRc") {
		t.Error("an app id is the uuid the console shows")
	}
}

func TestApprovalsAnswerWithOneKey(t *testing.T) {
	m := newChatModel(context.Background(), nil, chatConfig{org: "1"})
	reply := make(chan approval, 1)
	m.Update(approvalMsg{agent: "adaptor-builder", tool: "http.probe", url: "https://www.sharkninja.com/", host: "www.sharkninja.com", reply: reply})
	if v := m.View(); !strings.Contains(v, "Allow adaptor-builder to read https://www.sharkninja.com/") || !strings.Contains(v, "[a] always") {
		t.Fatalf("view: %q", v)
	}
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("x")}) // other keys type as usual
	if len(m.asks) != 1 || m.input.Value() != "x" {
		t.Fatalf("only y, a, n or Esc answer: asks %d input %q", len(m.asks), m.input.Value())
	}
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("y")}) // into the input: it is not empty
	if len(m.asks) != 1 {
		t.Fatal("a y typed mid-line is text, not an answer")
	}
	m.input.SetValue("")
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("y")})
	if got := <-reply; got != approveOnce || len(m.asks) != 0 {
		t.Fatalf("answer %v, pending %d", got, len(m.asks))
	}
	m.Update(approvalMsg{host: "x", reply: reply})
	m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if got := <-reply; got != approveNo {
		t.Fatalf("Esc declines, got %v", got)
	}
}

func TestAPromptWhoseCallGaveUpGoesAway(t *testing.T) {
	m := newChatModel(context.Background(), nil, chatConfig{org: "1"})
	ctx, cancel := context.WithCancel(context.Background())
	m.Update(approvalMsg{host: "x.example", reply: make(chan approval, 1), ctx: ctx})
	cancel()
	m.Update(spinner.TickMsg{})
	if len(m.asks) != 0 || strings.Contains(m.View(), "Allow") {
		t.Fatal("an expired approval must not hold the terminal")
	}
}

func TestThisSessionApprovalsAreRemembered(t *testing.T) {
	t.Setenv("ASCEND_AGENT_HOME", t.TempDir())
	a := &termApprover{org: "1"}
	var asked int
	a.setSend(func(msg tea.Msg) {
		asked++
		msg.(approvalMsg).reply <- approveOnce
	})
	u, _ := url.Parse("https://chat.example.com/x")
	for i := 0; i < 3; i++ {
		if !a.Approve(context.Background(), "adaptor-builder", "http.probe", u) {
			t.Fatal("approved")
		}
	}
	if asked != 1 {
		t.Fatalf("asked %d times; [y] covers the session", asked)
	}
	if agentclient.SiteAllowed("1", "chat.example.com") {
		t.Fatal("[y] is not [a]: nothing is saved")
	}
}

func TestTheBannerFitsItsTerminal(t *testing.T) {
	wide := banner(100, "agent dev")
	t.Log("\n" + wide)
	if !strings.Contains(wide, "█▀█  ▀█") || !strings.Contains(wide, "agent dev") || strings.Count(wide, "\n") < 5 {
		t.Fatalf("wide: %q", wide)
	}
	for _, line := range strings.Split(wide, "\n") {
		if lipgloss.Width(line) > 100 {
			t.Fatalf("too wide: %q", line)
		}
	}
	if narrow := banner(40, "agent dev"); strings.Contains(narrow, "\n") || !strings.Contains(narrow, "Ascend Agent") {
		t.Fatalf("narrow: %q", narrow)
	}
}
