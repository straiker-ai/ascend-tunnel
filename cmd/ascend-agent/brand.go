package main

import (
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
	xterm "github.com/charmbracelet/x/term"
)

// The Ascend brand: the logo's red, the X-oriented star in half blocks, and the "ASCEND" wordmark on a 3x8
// grid. The red marks Ascend acting, and nothing else.
var (
	brandRed   = lipgloss.Color("#FF5378")
	styleBrand = lipgloss.NewStyle().Foreground(brandRed)
)

const (
	star = "✖" // the mark at one cell: Ascend's replies and actions
	you  = "›" // the person's lines
)

var markSmall = []string{
	"    ▀▄    ▄▀",
	"      ████",
	"      ████",
	"    ▄█▀   ▀▄",
	"  ▄▀▀ ▄ ▄",
	"▄▀    ▄▀▄",
}

var wordmark = []string{
	"▄▀▄ █▀█ █▀█ █▀▀ █  █ █▀▄",
	"█ █ █▄  █   █▄  ██ █ █ █",
	"█▀█  ▀█ █   █   █ ██ █ █",
	"█ █ █▄█ █▄█ █▄▄ █  █ █▄▀",
}

// terminalWidth is the output's width, or 80 when it is not a terminal.
func terminalWidth() int {
	if w, _, err := xterm.GetSize(os.Stdout.Fd()); err == nil && w > 0 {
		return w
	}
	return 80
}

// banner is the mark beside the wordmark and a tagline, or a one-line lockup where that does not fit.
func banner(width int, tagline string) string {
	if width < 60 {
		return styleBrand.Render(star) + " " + styleBold.Render("Ascend Agent") + styleDim.Render("  "+tagline)
	}
	markWidth := 0
	for _, l := range markSmall {
		markWidth = max(markWidth, lipgloss.Width(l))
	}
	right := append(append([]string{}, wordmark...), "", styleDim.Render(tagline))
	rows := max(len(markSmall), len(right))
	lines := make([]string, 0, rows)
	for i := 0; i < rows; i++ {
		left := ""
		if i < len(markSmall) {
			left = markSmall[i]
		}
		left += strings.Repeat(" ", markWidth-lipgloss.Width(left))
		text := ""
		if i < len(right) {
			text = right[i]
			if i < len(wordmark) {
				text = styleBrand.Bold(true).Render(text)
			}
		}
		lines = append(lines, styleBrand.Render(left)+"   "+text)
	}
	return strings.Join(lines, "\n")
}
