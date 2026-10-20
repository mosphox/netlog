package main

import (
	"fmt"
	"io"
	"log"
	"net"
	stdhttp "net/http"
	"net/url"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	tls_client "github.com/bogdanfinn/tls-client"

	"github.com/mosphox/netlog/internal/fp"
)

// hostClientIdle is how long an unused host pool is kept before its
// connections are closed and it is forgotten.
const hostClientIdle = 3 * time.Minute

// h1ConnsPerHost mirrors Firefox's limit of parallel HTTP/1.1 connections per
// host (network.http.max-persistent-connections-per-server). An HTTP/2 host
// gets a single connection, as in Firefox.
const h1ConnsPerHost = 6

// pooledClient is one fingerprinted client inside a host pool.
type pooledClient struct {
	c        tls_client.HttpClient
	inflight int // guarded by Server.mu
}

// hostPool holds the clients dedicated to one upstream authority. tls-client
// holds a client-wide lock across each upstream dial and TLS handshake, so
// sharing a client between hosts lets one slow host stall every other; and
// within an HTTP/1.1 host, parallel requests need parallel dials, which one
// client would serialize. Hence: clients per host, several for h1 hosts.
type hostPool struct {
	clients  []*pooledClient
	h1       bool // the host answered over HTTP/1.1, so it may use several connections
	lastUsed time.Time
	loopback bool
}

// Server owns the proxy listener, the fingerprinted upstream clients, the CA
// and the log store. Clients and the listener are rebuilt when config changes
// from the web UI.
type Server struct {
	cfgStore *configStore
	ca       *certAuthority
	logs     *logStore

	mu           sync.Mutex
	hosts        map[string]*hostPool // authority -> fingerprinted clients, for https
	upstreamURL  string               // "" = direct
	stdClient    *stdhttp.Client      // plain, for cleartext http:// (no TLS fingerprint applies)
	upstreamDesc string
	ln           net.Listener
	curPort      int
}

func NewServer(cfgStore *configStore, ca *certAuthority, logs *logStore) (*Server, error) {
	s := &Server{cfgStore: cfgStore, ca: ca, logs: logs}
	if err := s.rebuildClient(cfgStore.get()); err != nil {
		return nil, err
	}
	go s.reapIdleClients()
	return s, nil
}

// rebuildClient drops every per-host client (they are recreated on demand
// with the new upstream) and rebuilds the plain-http client.
func (s *Server) rebuildClient(cfg Config) error {
	up := strings.TrimSpace(cfg.UpstreamURL)
	if up != "" {
		if _, err := url.Parse(up); err != nil {
			return fmt.Errorf("bad upstream url: %w", err)
		}
	}
	desc := nonEmpty(up, "direct")

	// Plain cleartext-http client, proxied the same way but without any TLS
	// fingerprinting (there is no TLS layer to fingerprint on http://).
	tr := &stdhttp.Transport{DisableCompression: true, TLSHandshakeTimeout: 15 * time.Second, IdleConnTimeout: 30 * time.Second}
	if up != "" {
		if pu, perr := url.Parse(up); perr == nil {
			proxyURL := stdhttp.ProxyURL(pu)
			tr.Proxy = func(r *stdhttp.Request) (*url.URL, error) {
				if isLoopbackHost(r.URL.Hostname()) {
					return nil, nil
				}
				return proxyURL(r)
			}
		}
	}
	std := &stdhttp.Client{
		Transport:     tr,
		Timeout:       upstreamTimeout,
		CheckRedirect: func(*stdhttp.Request, []*stdhttp.Request) error { return stdhttp.ErrUseLastResponse },
	}

	s.mu.Lock()
	old := s.hosts
	s.hosts = make(map[string]*hostPool)
	s.upstreamURL = up
	s.stdClient = std
	s.upstreamDesc = desc
	s.mu.Unlock()
	for _, hp := range old {
		for _, pc := range hp.clients {
			pc.c.CloseIdleConnections()
		}
	}
	return nil
}

// upstreamTimeout bounds one upstream request, body included.
const upstreamTimeout = 90 * time.Second

// acquire returns a fingerprinted client for an authority and marks it busy;
// the caller must release it. It picks the least busy client of the host's
// pool and, for HTTP/1.1 hosts, opens another one while all are busy.
// Loopback targets are dialed directly, never via the upstream.
func (s *Server) acquire(authority string) (*pooledClient, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	hp, ok := s.hosts[authority]
	if !ok {
		host := authority
		if h, _, err := net.SplitHostPort(authority); err == nil {
			host = h
		}
		hp = &hostPool{loopback: isLoopbackHost(strings.Trim(host, "[]"))}
		s.hosts[authority] = hp
	}
	hp.lastUsed = time.Now()
	desc := s.upstreamDesc
	if hp.loopback {
		desc = "direct (loopback)"
	}

	var best *pooledClient
	for _, pc := range hp.clients {
		if best == nil || pc.inflight < best.inflight {
			best = pc
		}
	}
	if best == nil || (best.inflight > 0 && hp.h1 && len(hp.clients) < h1ConnsPerHost) {
		c, err := s.newClient(hp.loopback)
		if err != nil {
			return nil, desc, err
		}
		best = &pooledClient{c: c}
		hp.clients = append(hp.clients, best)
	}
	best.inflight++
	return best, desc, nil
}

// release marks a client idle again and records the protocol the host spoke.
func (s *Server) release(authority string, pc *pooledClient, proto string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	pc.inflight--
	if hp, ok := s.hosts[authority]; ok && strings.HasPrefix(proto, "HTTP/1") {
		hp.h1 = true
	}
}

// discard removes a client after a connection-level failure so the retry
// dials a fresh connection instead of reusing a dead one. In-flight requests
// on the old client finish on their own.
func (s *Server) discard(authority string, pc *pooledClient) {
	s.mu.Lock()
	if hp, ok := s.hosts[authority]; ok {
		for i, x := range hp.clients {
			if x == pc {
				hp.clients = append(hp.clients[:i:i], hp.clients[i+1:]...)
				break
			}
		}
	}
	s.mu.Unlock()
	pc.c.CloseIdleConnections()
}

func (s *Server) newClient(loopback bool) (tls_client.HttpClient, error) {
	idle := 30 * time.Second
	opts := append(fp.Options(),
		tls_client.WithCookieJar(nil), // Firefox manages its own cookies
		tls_client.WithDialer(net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}),
		tls_client.WithTimeoutSeconds(int(upstreamTimeout/time.Second)),
		// Upstream proxies drop idle tunnels; don't reuse one that sat for long.
		tls_client.WithTransportOptions(&tls_client.TransportOptions{DisableCompression: true, IdleConnTimeout: &idle}),
	)
	if s.upstreamURL != "" && !loopback {
		opts = append(opts, tls_client.WithProxyUrl(s.upstreamURL))
	}
	return tls_client.NewHttpClient(tls_client.NewNoopLogger(), opts...)
}

func (s *Server) reapIdleClients() {
	for range time.Tick(time.Minute) {
		cutoff := time.Now().Add(-hostClientIdle)
		var stale []tls_client.HttpClient
		s.mu.Lock()
		for k, hp := range s.hosts {
			busy := false
			for _, pc := range hp.clients {
				busy = busy || pc.inflight > 0
			}
			if !busy && hp.lastUsed.Before(cutoff) {
				for _, pc := range hp.clients {
					stale = append(stale, pc.c)
				}
				delete(s.hosts, k)
			}
		}
		s.mu.Unlock()
		for _, c := range stale {
			c.CloseIdleConnections()
		}
	}
}

func (s *Server) upstreamInfo() (upstreamURL, desc string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.upstreamURL, s.upstreamDesc
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") || strings.HasSuffix(strings.ToLower(host), ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
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
		go func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("panic serving %s: %v\n%s", c.RemoteAddr(), r, debug.Stack())
					c.Close()
				}
			}()
			s.handleConn(c)
		}()
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
