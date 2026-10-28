package agentclient

import (
	"regexp"
	"strings"
)

// Escape sequences: CSI, OSC (BEL- or ST-terminated, which carries hyperlinks and window titles), DCS/SOS/PM/APC,
// and two-byte escapes.
var escapes = regexp.MustCompile(`\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?|\x1b[PX^_][^\x1b]*(?:\x1b\\)?|\x1b[@-Z\\-_]?`)

// Clean makes text from the cloud (agent output, target replies) safe to print: no escape sequences, no control
// characters except newline and tab, and no C1 controls.
func Clean(s string) string {
	s = escapes.ReplaceAllString(s, "")
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\t':
			return r
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) || r == ' ' || r == ' ':
			return -1
		}
		return r
	}, s)
}
