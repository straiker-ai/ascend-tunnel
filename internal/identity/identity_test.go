package identity

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

type contract struct {
	Cases []struct {
		Tenant      string            `json:"tenant"`
		PublicKey   string            `json:"public_key"`
		PasteForm   string            `json:"paste_form"`
		AgentID     string            `json:"agent_id"`
		LoginSlug   string            `json:"login_slug"`
		LoginUser   string            `json:"login_user"`
		SocketDir   string            `json:"socket_dir"`
		SocketPaths map[string]string `json:"socket_paths"`
	} `json:"cases"`
}

func loadContract(t *testing.T) contract {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "contract.json"))
	if err != nil {
		t.Fatal(err)
	}
	var c contract
	if err := json.Unmarshal(data, &c); err != nil {
		t.Fatal(err)
	}
	if len(c.Cases) == 0 {
		t.Fatal("contract.json has no cases")
	}
	return c
}

func TestNamesMatchTheRelaysContract(t *testing.T) {
	for _, tc := range loadContract(t).Cases {
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(tc.PublicKey))
		if err != nil {
			t.Fatal(err)
		}
		id := AgentID(pub)
		if id != tc.AgentID {
			t.Errorf("AgentID(%s) = %s, want %s", tc.PublicKey, id, tc.AgentID)
		}
		if got := PasteForm(tc.PublicKey); got != tc.PasteForm {
			t.Errorf("PasteForm = %s, want %s", got, tc.PasteForm)
		}
		if got := LoginSlug(tc.Tenant, id); got != tc.LoginSlug {
			t.Errorf("LoginSlug(%s, %s) = %s, want %s", tc.Tenant, id, got, tc.LoginSlug)
		}
		if got := LoginUser(tc.Tenant, id); got != tc.LoginUser {
			t.Errorf("LoginUser = %s, want %s", got, tc.LoginUser)
		}
		if got := SocketDir(tc.Tenant, id); got != tc.SocketDir {
			t.Errorf("SocketDir = %s, want %s", got, tc.SocketDir)
		}
		for spec, want := range tc.SocketPaths {
			host, link, _ := strings.Cut(spec, "~")
			n, _ := strconv.Atoi(link)
			if got := SocketPath(tc.SocketDir, host, n); got != want {
				t.Errorf("SocketPath(%s) = %s, want %s", spec, got, want)
			}
		}
	}
}

func TestTheKeyIsGeneratedOnceAndKeptPrivate(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	first, err := Load("1", dir)
	if err != nil {
		t.Fatal(err)
	}
	again, err := Load("1", dir)
	if err != nil {
		t.Fatal(err)
	}
	if first.PublicKey != again.PublicKey || first.AgentID != again.AgentID {
		t.Fatal("a second start must reuse the key")
	}
	if !strings.HasPrefix(first.PublicKey, "ssh-ed25519 ") {
		t.Fatalf("want an ed25519 key, got %s", first.PublicKey)
	}
	if runtime.GOOS != "windows" {
		st, err := os.Stat(first.KeyPath)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0o600 {
			t.Fatalf("key mode %o, want 600", st.Mode().Perm())
		}
	}
	if first.User != LoginUser("1", first.AgentID) || first.SocketDir != SocketDir("1", first.AgentID) {
		t.Fatal("login and directory derive from org and key")
	}
}

func TestAnUnreadableKeyIsAnError(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, KeyFile), []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load("1", dir); err == nil {
		t.Fatal("want an error for a corrupt key, never a silently new identity")
	}
}
