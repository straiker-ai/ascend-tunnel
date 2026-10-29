//go:build windows

package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// Name is the Windows service; it runs as its own virtual account, NT SERVICE\AscendTunnel.
const Name = "AscendTunnel"

// Kind says what Install sets up, for its summary.
const Kind = "a Windows service (AscendTunnel): it starts with Windows and restarts if it stops"

const account = `NT SERVICE\` + Name

// installDir is where the service's copy of the binary lives: a service account cannot run one from a person's
// Downloads folder, and the copy survives that file being moved or deleted.
func installDir() string {
	return filepath.Join(os.Getenv("ProgramFiles"), "Straiker", "ascend-tunnel")
}

// Install creates or updates the service and starts it. It needs an Administrator terminal.
func Install(s Spec, out io.Writer) error {
	m, err := mgr.Connect()
	if err != nil {
		return elevated(err)
	}
	defer m.Disconnect()
	h, err := m.OpenService(Name)
	exists := err == nil
	if exists {
		defer h.Close()
		stop(h) // its binary is locked while it runs
	}
	exe, err := copyExe(s.Exe)
	if err != nil {
		return err
	}
	c := mgr.Config{DisplayName: "Straiker Ascend tunnel agent",
		Description: "Lets Straiker Ascend reach AI apps in this network through one outbound HTTPS connection.",
		StartType:   mgr.StartAutomatic, DelayedAutoStart: true, ServiceStartName: account,
		SidType: windows.SERVICE_SID_TYPE_UNRESTRICTED}
	if exists {
		cur, err := h.Config()
		if err != nil {
			return err
		}
		c.ServiceType, c.ErrorControl = cur.ServiceType, cur.ErrorControl
		c.BinaryPathName = commandLine(exe, s.Args)
		if err := h.UpdateConfig(c); err != nil {
			return err
		}
	} else {
		if h, err = m.CreateService(Name, exe, c, s.Args...); err != nil {
			return err
		}
		defer h.Close()
	}
	restart := mgr.RecoveryAction{Type: mgr.ServiceRestart, Delay: 5 * time.Second}
	if err := h.SetRecoveryActions([]mgr.RecoveryAction{restart, restart, restart}, 24*60*60); err != nil {
		return err
	}
	if err := h.SetRecoveryActionsOnNonCrashFailures(true); err != nil {
		return err
	}
	if err := setEnv(s.Env); err != nil {
		return err
	}
	if err := grant(s.StateDir); err != nil {
		return err
	}
	if err := h.Start(); err != nil {
		return err
	}
	return waitFor(h, svc.Running, 15*time.Second)
}

// Uninstall stops the service and deletes it, with its copy of the binary. The agent key stays.
func Uninstall(out io.Writer) error {
	m, err := mgr.Connect()
	if err != nil {
		return elevated(err)
	}
	defer m.Disconnect()
	h, err := m.OpenService(Name)
	if err != nil {
		return nil // not installed
	}
	stop(h)
	err = h.Delete()
	h.Close()
	if err != nil {
		return err
	}
	_ = os.RemoveAll(installDir())
	return nil
}

// Status is the service's state, from sc.exe, which needs no Administrator terminal.
func Status() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	b, err := exec.CommandContext(ctx, "sc.exe", "query", Name).Output()
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == 1060 { // ERROR_SERVICE_DOES_NOT_EXIST
		return "not installed", nil
	}
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(line, ":"); ok && strings.TrimSpace(k) == "STATE" {
			if f := strings.Fields(v); len(f) > 1 {
				return strings.ToLower(f[1]), nil
			}
		}
	}
	return "unknown", nil
}

// RunIfService runs the agent under the service control manager when Windows started this process as the service:
// a stop or shutdown cancels run's context.
func RunIfService(run func(context.Context) int) (int, bool) {
	if ok, err := svc.IsWindowsService(); err != nil || !ok {
		return 0, false
	}
	h := &handler{run: run}
	if err := svc.Run(Name, h); err != nil {
		return 1, true
	}
	return h.code, true
}

type handler struct {
	run  func(context.Context) int
	code int
}

func (h *handler) Execute(_ []string, req <-chan svc.ChangeRequest, st chan<- svc.Status) (bool, uint32) {
	st <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan int, 1)
	go func() { done <- h.run(ctx) }()
	st <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				st <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				st <- svc.Status{State: svc.StopPending}
				cancel()
				h.code = <-done
				return false, 0
			}
		case h.code = <-done: // it ended on its own (a configuration error): exit non-zero, so recovery restarts it
			if h.code == 0 {
				h.code = 1
			}
			return true, uint32(h.code)
		}
	}
}

func elevated(err error) error {
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		return errors.New("installing a service needs an Administrator terminal: right-click PowerShell or Terminal, " +
			"Run as administrator, and run the same command there")
	}
	return err
}

func stop(h *mgr.Service) {
	if st, err := h.Query(); err == nil && st.State != svc.Stopped {
		_, _ = h.Control(svc.Stop)
		_ = waitFor(h, svc.Stopped, 20*time.Second)
	}
}

func waitFor(h *mgr.Service, want svc.State, d time.Duration) error {
	deadline := time.Now().Add(d)
	for {
		st, err := h.Query()
		if err != nil {
			return err
		}
		if st.State == want {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("the service is %s, not %s, after %s", stateName(st.State), stateName(want), d)
		}
		time.Sleep(300 * time.Millisecond)
	}
}

func stateName(s svc.State) string {
	return map[svc.State]string{svc.Stopped: "stopped", svc.StartPending: "starting", svc.StopPending: "stopping",
		svc.Running: "running", svc.ContinuePending: "resuming", svc.PausePending: "pausing", svc.Paused: "paused"}[s]
}

// copyExe puts the binary where the service runs it from, unless it already runs from there.
func copyExe(src string) (string, error) {
	dst := filepath.Join(installDir(), "ascend-tunnel.exe")
	if same(src, dst) {
		return dst, nil
	}
	if err := os.MkdirAll(installDir(), 0o755); err != nil {
		return "", err
	}
	in, err := os.Open(src)
	if err != nil {
		return "", err
	}
	defer in.Close()
	tmp := dst + ".new"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(f, in); err != nil {
		f.Close()
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	return dst, os.Rename(tmp, dst)
}

func same(a, b string) bool {
	x, err1 := os.Stat(a)
	y, err2 := os.Stat(b)
	return err1 == nil && err2 == nil && os.SameFile(x, y)
}

// commandLine is how CreateService writes the command line, for UpdateConfig.
func commandLine(exe string, args []string) string {
	s := syscall.EscapeArg(exe)
	for _, a := range args {
		s += " " + syscall.EscapeArg(a)
	}
	return s
}

// setEnv sets the service's own environment (the proxy settings), or clears it.
func setEnv(env []string) error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\`+Name, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	if len(env) == 0 {
		if err := k.DeleteValue("Environment"); err != nil && !errors.Is(err, registry.ErrNotExist) {
			return err
		}
		return nil
	}
	return k.SetStringsValue("Environment", env)
}

// grant lets the service's account, and only it besides who already could, use the agent key's directory.
func grant(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if b, err := exec.CommandContext(ctx, "icacls.exe", dir, "/grant", account+":(OI)(CI)M", "/T", "/Q").CombinedOutput(); err != nil {
		return fmt.Errorf("icacls %s: %v: %s", dir, err, strings.TrimSpace(string(b)))
	}
	return nil
}
