package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/mosphox/netlog/internal/fp"
)

// Upstream is one named upstream proxy the operator can route through.
type Upstream struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	URL  string `json:"url"` // http://, https://, socks5://; credentials allowed
}

// InterceptConfig controls Burp-style request interception.
type InterceptConfig struct {
	Enabled bool   `json:"enabled"`
	Filter  string `json:"filter"` // space-separated host substrings; empty = everything
}

// Config is persisted as JSON and edited from the web UI. The web UI's own
// listen address is fixed by a flag, not stored here.
type Config struct {
	ListenPort int `json:"listen_port"` // proxy port, default 9393

	Upstreams      []Upstream `json:"upstreams"`
	ActiveUpstream string     `json:"active_upstream"` // Upstream.ID; "" = direct

	// Fingerprint is "auto" (match the browser that sent each request by its
	// User-Agent) or a profile ID. FallbackFingerprint is used by auto when
	// the client is not a recognizable Firefox or Chrome.
	Fingerprint         string `json:"fingerprint"`
	FallbackFingerprint string `json:"fallback_fingerprint"`

	ForceUA     bool `json:"force_ua"`     // overwrite the client User-Agent with the profile's
	MITMEnabled bool `json:"mitm_enabled"` // intercept & decrypt HTTPS (needs the CA trusted)

	Intercept InterceptConfig `json:"intercept"`

	UpstreamURL string `json:"upstream_url,omitempty"` // legacy single upstream; migrated on load
}

func defaultConfig() Config {
	return Config{
		ListenPort:          9393,
		Upstreams:           []Upstream{},
		Fingerprint:         "auto",
		FallbackFingerprint: fp.Default.ID,
		MITMEnabled:         true,
	}
}

// normalize migrates legacy fields and repairs references.
func (c *Config) normalize() {
	if c.UpstreamURL != "" && len(c.Upstreams) == 0 {
		c.Upstreams = []Upstream{{ID: "upstream", Name: "Upstream", URL: c.UpstreamURL}}
		c.ActiveUpstream = "upstream"
	}
	c.UpstreamURL = ""
	if c.Upstreams == nil {
		c.Upstreams = []Upstream{}
	}
	for i := range c.Upstreams {
		u := &c.Upstreams[i]
		u.URL = strings.TrimSpace(u.URL)
		if u.URL != "" && !strings.Contains(u.URL, "://") {
			u.URL = "http://" + u.URL
		}
		if u.ID == "" {
			u.ID = newID()
		}
		if strings.TrimSpace(u.Name) == "" {
			u.Name = hostOf(u.URL)
		}
	}
	if c.ActiveUpstream != "" && c.upstream(c.ActiveUpstream) == nil {
		c.ActiveUpstream = ""
	}
	if c.Fingerprint == "" {
		c.Fingerprint = "auto"
	}
	if c.Fingerprint != "auto" {
		if _, ok := fp.Lookup(c.Fingerprint); !ok {
			c.Fingerprint = "auto"
		}
	}
	if _, ok := fp.Lookup(c.FallbackFingerprint); !ok {
		c.FallbackFingerprint = fp.Default.ID
	}
}

func (c *Config) validate() error {
	if c.ListenPort < 1 || c.ListenPort > 65535 {
		return fmt.Errorf("listen port must be 1–65535")
	}
	seen := map[string]bool{}
	for _, u := range c.Upstreams {
		if seen[u.ID] {
			return fmt.Errorf("duplicate upstream id %q", u.ID)
		}
		seen[u.ID] = true
		if err := u.validate(); err != nil {
			return err
		}
	}
	return nil
}

func (u Upstream) validate() error {
	pu, err := url.Parse(u.URL)
	if err != nil || pu.Host == "" {
		return fmt.Errorf("upstream %q: %q is not a proxy URL", u.Name, u.URL)
	}
	switch pu.Scheme {
	case "http", "https", "socks5", "socks5h":
	default:
		return fmt.Errorf("upstream %q: scheme %q is not supported (use http, https or socks5)", u.Name, pu.Scheme)
	}
	return nil
}

// upstream returns the upstream with the given ID, or nil.
func (c *Config) upstream(id string) *Upstream {
	for i := range c.Upstreams {
		if c.Upstreams[i].ID == id {
			return &c.Upstreams[i]
		}
	}
	return nil
}

func newID() string {
	var b [4]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func hostOf(raw string) string {
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		return u.Host
	}
	return raw
}

type configStore struct {
	mu   sync.RWMutex
	path string
	cfg  Config
}

func newConfigStore(path string) (*configStore, error) {
	cs := &configStore{path: path, cfg: defaultConfig()}
	data, err := os.ReadFile(path)
	if err == nil {
		c := defaultConfig()
		if json.Unmarshal(data, &c) == nil {
			cs.cfg = c
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	cs.cfg.normalize()
	// Persist on first run (and after migration) so the file is discoverable.
	if err := cs.save(); err != nil {
		return nil, err
	}
	return cs, nil
}

func (cs *configStore) get() Config {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	c := cs.cfg
	c.Upstreams = append([]Upstream(nil), cs.cfg.Upstreams...)
	return c
}

func (cs *configStore) set(c Config) error {
	cs.mu.Lock()
	cs.cfg = c
	cs.mu.Unlock()
	return cs.save()
}

func (cs *configStore) save() error {
	cs.mu.RLock()
	data, _ := json.MarshalIndent(cs.cfg, "", "  ")
	cs.mu.RUnlock()
	if err := os.MkdirAll(filepath.Dir(cs.path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(cs.path, data, 0o600) // may hold proxy credentials
}
