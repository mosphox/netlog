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

// h1ConnsPerHost mirrors the browsers' limit of parallel HTTP/1.1 connections
// per host (6 in both Firefox and Chrome). An HTTP/2 host gets a single
// connection, as in the browsers.
const h1ConnsPerHost = 6

// upstreamTimeout bounds one upstream request, body included.
const upstreamTimeout = 90 * time.Second

// route is how one request leaves netlog: which fingerprint it presents and
// which upstream proxy it goes through (nil = direct).
type route struct {
	profile *fp.Profile
	up      *Upstream
	auto    bool // profile was picked from the client's User-Agent
}

func (r route) upstreamURL() string {
	if r.up == nil {
		return ""
	}
	return r.up.URL
}

func (r route) upstreamName() string {
	if r.up == nil {
		return "direct"
	}
	return r.up.Name
}

// routeOverride lets the repeater pin a profile or upstream for one request.
// Empty fields fall back to the config; Upstream "direct" forces no upstream.
type routeOverride struct {
	Profile  string `json:"profile"`
	Upstream string `json:"upstream"`
}

// resolveRoute picks the profile and upstream for a request.
func resolveRoute(cfg Config, userAgent string, ov routeOverride) route {
	var r route
	switch {
	case ov.Profile != "" && ov.Profile != "auto":
		r.profile, _ = fp.Lookup(ov.Profile)
	case ov.Profile == "auto" || cfg.Fingerprint == "auto":
		if p, ok := fp.Detect(userAgent); ok {
			r.profile, r.auto = p, true
		}
	default:
		r.profile, _ = fp.Lookup(cfg.Fingerprint)
	}
	if r.profile == nil {
		r.profile, _ = fp.Lookup(cfg.FallbackFingerprint)
	}
	if r.profile == nil {
		r.profile = fp.Default
	}
	switch ov.Upstream {
	case "":
		r.up = cfg.upstream(cfg.ActiveUpstream)
	case "direct":
	default:
		r.up = cfg.upstream(ov.Upstream)
	}
	return r
}

// pooledClient is one fingerprinted client inside a host pool.
type pooledClient struct {
	c        tls_client.HttpClient
	inflight int // guarded by Server.mu
}

// hostPool holds the clients for one (profile, upstream, authority). tls-client
// holds a client-wide lock across each upstream dial and TLS handshake, so
// sharing a client between hosts lets one slow host stall every other; and
// within an HTTP/1.1 host, parallel requests need parallel dials, which one
// client would serialize. Hence: clients per host, several for h1 hosts.
type hostPool struct {
	profile     *fp.Profile
	upstreamURL string
	clients     []*pooledClient
	h1          bool // the host answered over HTTP/1.1, so it may use several connections
	lastUsed    time.Time
	loopback    bool
}

// Server owns the proxy listener, the fingerprinted upstream clients, the CA,
// the log store and the interception queue.
type Server struct {
	cfgStore  *configStore
	ca        *certAuthority
	logs      *logStore
	intercept *interceptQueue

	mu         sync.Mutex
	hosts      map[string]*hostPool       // poolKey -> fingerprinted clients, for https
	stdClients map[string]*stdhttp.Client // upstream URL -> plain client, for cleartext http://
	ln         net.Listener
	curPort    int
}

func NewServer(cfgStore *configStore, ca *certAuthority, logs *logStore) (*Server, error) {
	s := &Server{cfgStore: cfgStore, ca: ca, logs: logs, intercept: newInterceptQueue(),
		hosts: make(map[string]*hostPool), stdClients: make(map[string]*stdhttp.Client)}
	go s.reapIdleClients()
	return s, nil
}

// dropClients forgets every pooled client; they are recreated on demand.
func (s *Server) dropClients() {
	s.mu.Lock()
	old := s.hosts
	s.hosts = make(map[string]*hostPool)
	s.stdClients = make(map[string]*stdhttp.Client)
	s.mu.Unlock()
	for _, hp := range old {
		for _, pc := range hp.clients {
			pc.c.CloseIdleConnections()
		}
	}
}

func poolKey(rt route, authority string) string {
	return rt.profile.ID + "|" + rt.upstreamURL() + "|" + authority
}

// acquire returns a fingerprinted client for an authority on a route and marks
// it busy; the caller must release it. It picks the least busy client of the
// pool and, for HTTP/1.1 hosts, opens another one while all are busy.
// Loopback targets are dialed directly, never via the upstream.
func (s *Server) acquire(rt route, authority string) (*pooledClient, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := poolKey(rt, authority)
	hp, ok := s.hosts[key]
	if !ok {
		host := authority
		if h, _, err := net.SplitHostPort(authority); err == nil {
			host = h
		}
		hp = &hostPool{profile: rt.profile, upstreamURL: rt.upstreamURL(), loopback: isLoopbackHost(strings.Trim(host, "[]"))}
		s.hosts[key] = hp
	}
	hp.lastUsed = time.Now()

	var best *pooledClient
	for _, pc := range hp.clients {
		if best == nil || pc.inflight < best.inflight {
			best = pc
		}
	}
	if best == nil || (best.inflight > 0 && hp.h1 && len(hp.clients) < h1ConnsPerHost) {
		c, err := newClient(hp.profile, hp.upstreamURL, hp.loopback)
		if err != nil {
			return nil, err
		}
		best = &pooledClient{c: c}
		hp.clients = append(hp.clients, best)
	}
	best.inflight++
	return best, nil
}

// release marks a client idle again and records the protocol the host spoke.
func (s *Server) release(rt route, authority string, pc *pooledClient, proto string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	pc.inflight--
	if hp, ok := s.hosts[poolKey(rt, authority)]; ok && strings.HasPrefix(proto, "HTTP/1") {
		hp.h1 = true
	}
}

// discard removes a client after a connection-level failure so the retry
// dials a fresh connection instead of reusing a dead one. In-flight requests
// on the old client finish on their own.
func (s *Server) discard(rt route, authority string, pc *pooledClient) {
	s.mu.Lock()
	if hp, ok := s.hosts[poolKey(rt, authority)]; ok {
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

func newClient(p *fp.Profile, upstreamURL string, loopback bool) (tls_client.HttpClient, error) {
	idle := 30 * time.Second
	opts := append(p.Options(),
		tls_client.WithCookieJar(nil), // the browser manages its own cookies
		tls_client.WithDialer(net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}),
		tls_client.WithTimeoutSeconds(int(upstreamTimeout/time.Second)),
		// Never let the transport decode content: bodies are relayed byte for
		// byte and decoded only for display. Upstream proxies drop idle
		// tunnels, so don't reuse one that sat for long.
		tls_client.WithTransportOptions(&tls_client.TransportOptions{DisableCompression: true, IdleConnTimeout: &idle}),
	)
	if upstreamURL != "" && !loopback {
		opts = append(opts, tls_client.WithProxyUrl(upstreamURL))
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

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") || strings.HasSuffix(strings.ToLower(host), ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// plainClient returns the cleartext-http client for an upstream. There is no
// TLS layer to fingerprint on http://, so this is the standard library.
func (s *Server) plainClient(upstreamURL string) *stdhttp.Client {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.stdClients[upstreamURL]; ok {
		return c
	}
	tr := &stdhttp.Transport{DisableCompression: true, TLSHandshakeTimeout: 15 * time.Second, IdleConnTimeout: 30 * time.Second}
	if upstreamURL != "" {
		if pu, err := url.Parse(upstreamURL); err == nil {
			proxyURL := stdhttp.ProxyURL(pu)
			tr.Proxy = func(r *stdhttp.Request) (*url.URL, error) {
				if isLoopbackHost(r.URL.Hostname()) {
					return nil, nil
				}
				return proxyURL(r)
			}
		}
	}
	c := &stdhttp.Client{
		Transport:     tr,
		Timeout:       upstreamTimeout,
		CheckRedirect: func(*stdhttp.Request, []*stdhttp.Request) error { return stdhttp.ErrUseLastResponse },
	}
	s.stdClients[upstreamURL] = c
	return c
}

// doPlain forwards a cleartext http:// request and returns a normalized
// response.
func (s *Server) doPlain(rt route, method, fullURL string, rr *rawRequest, cfg Config) (int, []HeaderKV, []byte, error) {
	client := s.plainClient(rt.upstreamURL())
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
		req.Header.Set("User-Agent", rt.profile.UserAgent)
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

// ApplyConfig validates and persists new config, drops pooled clients when
// routing changed, rebinds the listener if the port changed (restoring the
// old one on failure), and releases held requests when interception is off.
func (s *Server) ApplyConfig(newCfg Config) error {
	newCfg.normalize()
	if err := newCfg.validate(); err != nil {
		return err
	}
	old := s.cfgStore.get()
	if err := s.cfgStore.set(newCfg); err != nil {
		return err
	}
	if fmt.Sprint(old.Upstreams) != fmt.Sprint(newCfg.Upstreams) {
		s.dropClients()
	}
	if !newCfg.Intercept.Enabled {
		s.intercept.forwardAll()
	}
	if newCfg.ListenPort != old.ListenPort {
		s.stopProxy()
		if err := s.startOn(newCfg.ListenPort); err != nil {
			wanted := newCfg.ListenPort
			_ = s.startOn(old.ListenPort)
			newCfg.ListenPort = old.ListenPort
			_ = s.cfgStore.set(newCfg)
			return fmt.Errorf("could not bind port %d (%v); kept %d", wanted, err, old.ListenPort)
		}
	}
	return nil
}
