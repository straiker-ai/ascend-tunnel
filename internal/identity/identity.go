// Package identity is who the agent is on Straiker's relay: its own key, generated and kept on this
// host, and the names the relay derives from it. Every name here MUST match the relay's derivation;
// testdata/contract.json pins them, and the relay's own tests check the same file.
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

// KeyFile is the agent's private key, inside its state directory.
const KeyFile = "agent.key"

// Identity is the agent's key and its login on the relay for one org (tenant).
type Identity struct {
	Tenant    string
	AgentID   string     // sha256 of the public key blob, 8 hex
	PublicKey string     // "ssh-ed25519 AAAA..."
	User      string     // the relay login: one per org and key
	SocketDir string     // relay-side directory only this login can create sockets in
	KeyPath   string     // the private key file
	Signer    ssh.Signer // signs the relay login
}

// Load returns the agent's identity for tenant, generating its key in stateDir on first use.
func Load(tenant, stateDir string) (*Identity, error) {
	path := filepath.Join(stateDir, KeyFile)
	signer, err := ensureKey(path)
	if err != nil {
		return nil, err
	}
	id := AgentID(signer.PublicKey())
	return &Identity{
		Tenant:    tenant,
		AgentID:   id,
		PublicKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))),
		User:      LoginUser(tenant, id),
		SocketDir: SocketDir(tenant, id),
		KeyPath:   path,
		Signer:    signer,
	}, nil
}

// ensureKey loads the private key at path, generating an ed25519 key there (0600) if there is none.
// The file is OpenSSH format, so standard SSH tooling can read it.
func ensureKey(path string) (ssh.Signer, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		data, err = generateKey(path)
	}
	if err != nil {
		return nil, fmt.Errorf("agent key %s: %w", path, err)
	}
	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("agent key %s: %w", path, err)
	}
	return signer, nil
}

func generateKey(path string) ([]byte, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return nil, err
	}
	data := pem.EncodeToMemory(block)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return os.ReadFile(path) // another start won the race; use its key
	}
	if err != nil {
		return nil, err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return nil, err
	}
	return data, f.Close()
}

// AgentID is the relay's id for a public key: sha256 of its wire-format blob, first 8 hex.
func AgentID(pub ssh.PublicKey) string {
	sum := sha256.Sum256(pub.Marshal())
	return hex.EncodeToString(sum[:])[:8]
}

// PasteForm is what the customer pastes into an Ascend app: the key's base64 blob (its type is inside it).
func PasteForm(publicKey string) string {
	if f := strings.Fields(publicKey); len(f) > 1 {
		return f[1]
	}
	return publicKey
}

// LoginSlug names the relay login for an org and agent: sha256("<tenant>/<agent id>"), first 12 hex.
func LoginSlug(tenant, agentID string) string {
	sum := sha256.Sum256([]byte(tenant + "/" + agentID))
	return hex.EncodeToString(sum[:])[:12]
}

// LoginUser is the relay login for an org and agent.
func LoginUser(tenant, agentID string) string { return "t" + LoginSlug(tenant, agentID) }

// SocketDir is the relay-side directory the login binds its sockets in (always a Unix path).
func SocketDir(tenant, agentID string) string { return "/run/t/" + LoginSlug(tenant, agentID) }

// SocketPath is the relay-side socket a target's link-th forward binds: the relay reads tenant and
// agent from the directory and the target from the name.
func SocketPath(dir, host string, link int) string { return fmt.Sprintf("%s/%s~%d", dir, host, link) }
