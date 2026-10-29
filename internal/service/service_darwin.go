//go:build darwin

package service

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Label is the LaunchAgent's label.
const Label = "ai.straiker.ascend-tunnel"

// Kind says what Install sets up, for its summary.
const Kind = "a LaunchAgent: it starts when you log in and restarts if it stops"

func plistPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "LaunchAgents", Label+".plist"), nil
}

func domain() string { return fmt.Sprintf("gui/%d", os.Getuid()) }

// Install writes the LaunchAgent and (re)starts it. It runs as the person, so it needs no sudo and uses their key.
func Install(s Spec, out io.Writer) error {
	if os.Geteuid() == 0 {
		return errors.New("run it without sudo: it installs a LaunchAgent that runs as you, with your agent key")
	}
	path, err := plistPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(path, plist(s, filepath.Join(s.StateDir, "service.log")), 0o644); err != nil {
		return err
	}
	_ = launchctl("bootout", domain()+"/"+Label) // an earlier install; "not loaded" is fine
	var last error
	for i := 0; i < 5; i++ { // bootout finishes asynchronously: bootstrap fails with EIO until it has
		if last = launchctl("bootstrap", domain(), path); last == nil {
			return nil
		}
		time.Sleep(time.Second)
	}
	return last
}

// Uninstall stops the LaunchAgent and removes it. The agent key stays.
func Uninstall(out io.Writer) error {
	path, err := plistPath()
	if err != nil {
		return err
	}
	_ = launchctl("bootout", domain()+"/"+Label)
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// Status is the LaunchAgent's state as launchd reports it.
func Status() (string, error) {
	path, err := plistPath()
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return "not installed", nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	b, err := exec.CommandContext(ctx, "launchctl", "print", domain()+"/"+Label).Output()
	if err != nil {
		return "installed, not loaded (log in again, or reinstall)", nil
	}
	state, pid := "", ""
	for _, line := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), " = ")
		switch {
		case !ok:
		case k == "state" && state == "":
			state = v
		case k == "pid" && pid == "":
			pid = v
		}
	}
	if pid != "" {
		return fmt.Sprintf("%s (pid %s)", state, pid), nil
	}
	return state, nil
}

// RunIfService is for Windows; launchd runs the command line as it is.
func RunIfService(func(context.Context) int) (int, bool) { return 0, false }

func launchctl(args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if b, err := exec.CommandContext(ctx, "launchctl", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("launchctl %s: %v: %s", args[0], err, strings.TrimSpace(string(b)))
	}
	return nil
}

// plist is the LaunchAgent: the command, kept alive, its environment, and stderr to log (stdout repeats the audit
// log, which the agent keeps itself).
func plist(s Spec, log string) []byte {
	var b bytes.Buffer
	str := func(v string) {
		b.WriteString("<string>")
		_ = xml.EscapeText(&b, []byte(v))
		b.WriteString("</string>")
	}
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key>`)
	str(Label)
	b.WriteString("\n<key>ProgramArguments</key><array>")
	for _, a := range append([]string{s.Exe}, s.Args...) {
		str(a)
	}
	b.WriteString("</array>\n")
	if len(s.Env) > 0 {
		b.WriteString("<key>EnvironmentVariables</key><dict>")
		for _, kv := range s.Env {
			k, v, _ := strings.Cut(kv, "=")
			b.WriteString("<key>")
			_ = xml.EscapeText(&b, []byte(k))
			b.WriteString("</key>")
			str(v)
		}
		b.WriteString("</dict>\n")
	}
	b.WriteString("<key>RunAtLoad</key><true/>\n<key>KeepAlive</key><true/>\n<key>ThrottleInterval</key><integer>5</integer>\n")
	b.WriteString("<key>StandardOutPath</key><string>/dev/null</string>\n<key>StandardErrorPath</key>")
	str(log)
	b.WriteString("\n</dict></plist>\n")
	return b.Bytes()
}
