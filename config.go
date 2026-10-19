package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

// Config holds the two runtime-settable knobs (proxy listen port and upstream)
// plus a couple of conveniences. It is persisted as JSON and edited from the web
// UI. The web UI's own listen address is fixed by a flag, not stored here.
type Config struct {
	ListenPort  int    `json:"listen_port"`  // proxy port, default 9393
	UpstreamURL string `json:"upstream_url"` // e.g. http://127.0.0.1:12345 ("" = direct)
	ForceUA     bool   `json:"force_ua"`     // overwrite client User-Agent with the FF158 UA
	MITMEnabled bool   `json:"mitm_enabled"` // intercept & decrypt HTTPS (needs the CA in Firefox)
}

func defaultConfig() Config {
	return Config{
		ListenPort:  9393,
		UpstreamURL: "http://127.0.0.1:12345",
		ForceUA:     false,
		MITMEnabled: true,
	}
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
		var c Config
		if json.Unmarshal(data, &c) == nil {
			cs.cfg = c
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	// Persist defaults on first run so the file exists and is discoverable.
	if err := cs.save(); err != nil {
		return nil, err
	}
	return cs, nil
}

func (cs *configStore) get() Config {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	return cs.cfg
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
	return os.WriteFile(cs.path, data, 0o644)
}
