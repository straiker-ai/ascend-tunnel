package agentclient

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// PATEnv overrides the saved token, for scripts and CI.
const PATEnv = "STRAIKER_API_KEY"

// ErrNotSignedIn means there is no saved login.
var ErrNotSignedIn = errors.New("not signed in: run `ascend-agent login`")

// Config is what `ascend-agent login` keeps in ~/.ascend-agent/config.json (mode 0600), as the AWS CLI keeps
// ~/.aws/credentials: the token, and what signing in with it found out.
type Config struct {
	Env         string            `json:"env"`
	Gateway     string            `json:"gateway"`
	Org         string            `json:"org"`
	User        string            `json:"user"`
	Token       string            `json:"token"`
	AgentAPI    string            `json:"agent_api,omitempty"`
	SessionKeys map[string]string `json:"session_keys,omitempty"` // Straiker's session-token key, pinned per env on first use
}

// Home is ~/.ascend-agent, or ASCEND_AGENT_HOME.
func Home() (string, error) {
	if d := os.Getenv("ASCEND_AGENT_HOME"); d != "" {
		return d, nil
	}
	h, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(h, ".ascend-agent"), nil
}

func homeFile(name string) (string, error) {
	d, err := Home()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, name), nil
}

// LoadConfig reads the saved login; PATEnv, when set, replaces its token.
func LoadConfig() (*Config, error) {
	c, err := readConfig()
	if err != nil {
		return nil, err
	}
	if c == nil || c.Gateway == "" || c.Token == "" {
		return nil, ErrNotSignedIn
	}
	if v := strings.TrimSpace(os.Getenv(PATEnv)); v != "" {
		c.Token = v
	}
	return c, nil
}

// readConfig is the saved file as it is, or nil if there is none.
func readConfig() (*Config, error) {
	path, err := homeFile("config.json")
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, errors.New(path + ": " + err.Error() + " (run `ascend-agent login` again)")
	}
	return &c, nil
}

// Save writes the login, readable only by this user.
func (c *Config) Save() (string, error) {
	path, err := homeFile("config.json")
	if err != nil {
		return "", err
	}
	return path, writePrivate(path, c)
}

// Logout removes the saved login. A non-prod environment stays, so the next login goes to it again.
func Logout() (string, error) {
	path, err := homeFile("config.json")
	if err != nil {
		return "", err
	}
	if c, _ := readConfig(); c != nil && c.Env != "" && c.Env != "prod" {
		return path, writePrivate(path, &Config{Env: c.Env, Gateway: c.Gateway})
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	return path, nil
}

func writePrivate(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(raw, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Sites are the sites a person chose to always allow, per org, in ~/.ascend-agent/sites.json.
func Sites(org string) []string {
	all := loadSites()
	return slices.Clone(all[org])
}

func loadSites() map[string][]string {
	all := map[string][]string{}
	if path, err := homeFile("sites.json"); err == nil {
		if raw, err := os.ReadFile(path); err == nil {
			_ = json.Unmarshal(raw, &all)
		}
	}
	return all
}

// SiteAllowed reports whether host is always allowed for org.
func SiteAllowed(org, host string) bool {
	return slices.Contains(loadSites()[org], strings.ToLower(host))
}

// AllowSite always allows host for org.
func AllowSite(org, host string) error {
	all := loadSites()
	host = strings.ToLower(host)
	if !slices.Contains(all[org], host) {
		all[org] = append(all[org], host)
		slices.Sort(all[org])
	}
	return saveSites(all)
}

// ForgetSite stops always allowing host for org. Reports whether it was allowed.
func ForgetSite(org, host string) (bool, error) {
	all := loadSites()
	i := slices.Index(all[org], strings.ToLower(host))
	if i < 0 {
		return false, nil
	}
	all[org] = slices.Delete(all[org], i, i+1)
	return true, saveSites(all)
}

func saveSites(all map[string][]string) error {
	path, err := homeFile("sites.json")
	if err != nil {
		return err
	}
	return writePrivate(path, all)
}

// Me is who a token signs in as, and what a host needs from Straiker.
type Me struct {
	Tenant     string `json:"tenant"`
	Principal  string `json:"principal"`
	SessionKey string `json:"sessionKey"`
	AgentAPI   string `json:"agentApi"`
	Budget     Budget `json:"budget"`
}

// Budget is the org's Ascend Agent budget for today (UTC).
type Budget struct {
	LimitUSD     float64 `json:"limitUsd"`
	SpentUSD     float64 `json:"spentUsd"`
	RemainingUSD float64 `json:"remainingUsd"`
	ResetsAt     string  `json:"resetsAt"`
}

// Usage is today's budget.
func (c *Client) Usage(ctx context.Context) (*Budget, error) {
	var b Budget
	if err := c.call(ctx, http.MethodGet, "/usage", nil, &b); err != nil {
		return nil, err
	}
	return &b, nil
}

// Whoami asks Straiker who this token is.
func (c *Client) Whoami(ctx context.Context) (*Me, error) {
	var m Me
	if err := c.call(ctx, http.MethodGet, "/whoami", nil, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// TargetEnv is where login signs in: prod, unless the config file names another env (Straiker's own testing:
// {"env": "dev"}), and that env's gateway unless the file names one (a stand-in).
func TargetEnv() (env, gateway string, err error) {
	c, err := readConfig()
	if err != nil {
		return "", "", err
	}
	env = "prod"
	if c != nil && c.Env != "" {
		env, gateway = c.Env, c.Gateway
	}
	if _, ok := DefaultGateway[env]; !ok {
		return "", "", errors.New(`config.json: "env": "` + env + `" is not prod, stage or dev`)
	}
	if gateway == "" {
		gateway = DefaultGateway[env]
	}
	return env, gateway, nil
}

// SignIn checks a token against env's gateway and finds who it is there.
func SignIn(ctx context.Context, httpc *http.Client, token, env, base string) (*Config, error) {
	c := &Client{Base: base, PAT: token, HTTP: httpc}
	if _, err := c.accessToken(ctx, true); err != nil {
		return nil, errors.New("this token did not sign in to Straiker (" + env + "): " + errString(err))
	}
	me, err := c.Whoami(ctx)
	if err != nil {
		return nil, errors.New("signed in to " + env + ", but Ascend Agent is not available there yet: " + err.Error())
	}
	return &Config{Env: env, Gateway: base, Org: me.Tenant, User: me.Principal, Token: token,
		AgentAPI: me.AgentAPI, SessionKeys: map[string]string{env: me.SessionKey}}, nil
}

func errString(err error) string {
	if err == nil {
		return "no answer"
	}
	return err.Error()
}
