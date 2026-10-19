package main

import (
	"fmt"
	"io"
	"net"
	stdhttp "net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	tls_client "github.com/bogdanfinn/tls-client"

	"netlogger/internal/fp"
)

// clientPoolSize bounds the blast radius of tls-client's cache-lock stall: a
// stalled upstream handshake only wedges the one pooled client it lands on, so
// requests round-robined to the others keep flowing. Each client carries the
// identical Firefox fingerprint.
const clientPoolSize = 8

// Server owns the proxy listener, the fingerprinted upstream client, the CA and
// the log store. The upstream client and the listener are rebuilt when config
// changes from the web UI.
type Server struct {
	cfgStore *configStore
	ca       *certAuthority
	logs     *logStore

	mu           sync.Mutex
	clients      []tls_client.HttpClient // fingerprinted pool, for https
	clientIdx    uint64                  // round-robin cursor (atomic)
	stdClient    *stdhttp.Client         // plain, for cleartext http:// (no TLS fingerprint applies)
	upstreamDesc string
	ln           net.Listener
	curPort      int
}

func NewServer(cfgStore *configStore, ca *certAuthority, logs *logStore) (*Server, error) {
	s := &Server{cfgStore: cfgStore, ca: ca, logs: logs}
	if err := s.rebuildClient(cfgStore.get()); err != nil {
		return nil, err
	}
	return s, nil
}

// rebuildClient constructs a fresh fingerprinted upstream client for the given
// config (with or without an upstream proxy) and swaps it in atomically.
func (s *Server) rebuildClient(cfg Config) error {
	desc := "direct"
	dialer := net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}

	pool := make([]tls_client.HttpClient, 0, clientPoolSize)
	for i := 0; i < clientPoolSize; i++ {
		opts := fp.Options()
		opts = append(opts,
			tls_client.WithCookieJar(nil),  // Firefox manages its own cookies
			tls_client.WithDialer(dialer),  // bound the TCP connect to the upstream
		)
		if u := strings.TrimSpace(cfg.UpstreamURL); u != "" {
			opts = append(opts, tls_client.WithProxyUrl(u))
			desc = u
		}
		c, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(), opts...)
		if err != nil {
			return err
		}
		pool = append(pool, c)
	}

	// Plain cleartext-http client, proxied the same way but without any TLS
	// fingerprinting (there is no TLS layer to fingerprint on http://).
	tr := &stdhttp.Transport{DisableCompression: true, TLSHandshakeTimeout: 15 * time.Second}
	if u := strings.TrimSpace(cfg.UpstreamURL); u != "" {
		if pu, perr := url.Parse(u); perr == nil {
			tr.Proxy = stdhttp.ProxyURL(pu)
		}
	}
	std := &stdhttp.Client{
		Transport:     tr,
		Timeout:       30 * time.Second,
		CheckRedirect: func(*stdhttp.Request, []*stdhttp.Request) error { return stdhttp.ErrUseLastResponse },
	}

	s.mu.Lock()
	old := s.clients
	s.clients = pool
	s.stdClient = std
	s.upstreamDesc = desc
	s.mu.Unlock()
	for _, c := range old {
		c.CloseIdleConnections()
	}
	return nil
}

func (s *Server) getClient() (tls_client.HttpClient, string) {
	s.mu.Lock()
	pool := s.clients
	desc := s.upstreamDesc
	s.mu.Unlock()
	if len(pool) == 0 {
		return nil, desc
	}
	i := atomic.AddUint64(&s.clientIdx, 1)
	return pool[int(i%uint64(len(pool)))], desc
}

// doPlain forwards a cleartext http:// request through the standard proxied
// client and returns a normalized response.
func (s *Server) doPlain(method, fullURL string, rr *rawRequest, cfg Config) (int, []HeaderKV, []byte, error) {
	s.mu.Lock()
	client := s.stdClient
	s.mu.Unlock()

	var body io.Reader
	if len(rr.Body) > 0 {
		body = strings.NewReader(string(rr.Body))
	}
	req, err := stdhttp.NewRequest(method, fullURL, body)
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header = stdhttp.Header{}
	for _, h := range rr.Headers {
		ln := strings.ToLower(h.Name)
		if hopByHop[ln] || ln == "host" || ln == "content-length" {
			continue
		}
		if ln == "user-agent" && cfg.ForceUA {
			continue
		}
		req.Header[h.Name] = append(req.Header[h.Name], h.Value)
	}
	if cfg.ForceUA {
		req.Header.Set("User-Agent", fp.UserAgent)
	}
	req.Host = ""

	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	out := make([]HeaderKV, 0, len(resp.Header))
	for name, vals := range resp.Header {
		for _, v := range vals {
			out = append(out, HeaderKV{Name: name, Value: v})
		}
	}
	return resp.StatusCode, out, respBody, nil
}

// StartProxy binds the proxy listener on the configured port.
func (s *Server) StartProxy() error {
	return s.startOn(s.cfgStore.get().ListenPort)
}

func (s *Server) startOn(port int) error {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.ln = ln
	s.curPort = port
	s.mu.Unlock()
	go s.acceptLoop(ln)
	return nil
}

func (s *Server) acceptLoop(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return // listener closed
		}
		go s.handleConn(c)
	}
}

func (s *Server) stopProxy() {
	s.mu.Lock()
	ln := s.ln
	s.ln = nil
	s.mu.Unlock()
	if ln != nil {
		ln.Close()
	}
}

func (s *Server) currentPort() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.curPort
}

// ApplyConfig persists new config, rebuilds the upstream client, and rebinds the
// listener if the port changed. On a failed rebind it restores the old port.
func (s *Server) ApplyConfig(newCfg Config) error {
	old := s.cfgStore.get()
	if err := s.cfgStore.set(newCfg); err != nil {
		return err
	}
	if err := s.rebuildClient(newCfg); err != nil {
		return err
	}
	if newCfg.ListenPort != old.ListenPort {
		s.stopProxy()
		if err := s.startOn(newCfg.ListenPort); err != nil {
			// roll back to the previous port so the proxy keeps working
			_ = s.startOn(old.ListenPort)
			return fmt.Errorf("could not bind port %d (%v); kept %d", newCfg.ListenPort, err, old.ListenPort)
		}
	}
	return nil
}
