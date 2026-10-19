package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"

	http "github.com/bogdanfinn/fhttp"

	"netlogger/internal/fp"
)

// hopByHop headers are connection-scoped and must not be forwarded onto the
// upstream HTTP/2 request. "te" is deliberately NOT here: Firefox sends
// "te: trailers" on h2 and it is part of the target fingerprint.
var hopByHop = map[string]bool{
	"connection":          true,
	"keep-alive":          true,
	"proxy-connection":    true,
	"proxy-authenticate":  true,
	"proxy-authorization": true,
	"transfer-encoding":   true,
	"upgrade":             true,
}

// rawRequest is a request read straight off the wire, preserving exact header
// order and the full body.
type rawRequest struct {
	Method  string
	Target  string
	Proto   string
	Headers []HeaderKV
	Body    []byte
}

func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	rr, err := readRawRequest(br)
	if err != nil {
		return
	}
	clientAddr := conn.RemoteAddr().String()
	if strings.EqualFold(rr.Method, "CONNECT") {
		s.handleConnect(conn, br, rr, clientAddr)
		return
	}
	s.handlePlain(conn, br, rr, clientAddr)
}

// handlePlain serves absolute-form HTTP proxy requests (http:// targets),
// looping to honour keep-alive.
func (s *Server) handlePlain(conn net.Conn, br *bufio.Reader, first *rawRequest, clientAddr string) {
	rr := first
	for {
		u, err := url.Parse(rr.Target)
		if err != nil || u.Host == "" {
			writeSimple(conn, 400, "netlogger: bad proxy request target")
			return
		}
		scheme := u.Scheme
		if scheme == "" {
			scheme = "http"
		}
		if !s.doAndRelay(conn, br, scheme, urlAuthority(u.Host, scheme), u.RequestURI(), rr, clientAddr) {
			return
		}
		rr, err = readRawRequest(br)
		if err != nil {
			return
		}
		if strings.EqualFold(rr.Method, "CONNECT") {
			s.handleConnect(conn, br, rr, clientAddr)
			return
		}
	}
}

// handleConnect answers CONNECT, then either raw-tunnels (MITM off) or
// terminates TLS with a minted cert and serves the decrypted requests.
func (s *Server) handleConnect(conn net.Conn, br *bufio.Reader, rr *rawRequest, clientAddr string) {
	hostport := rr.Target
	if _, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}

	cfg := s.cfgStore.get()
	if !cfg.MITMEnabled {
		s.rawTunnel(conn, br, hostport)
		return
	}

	hostname := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		hostname = h
	}

	tlsConn := tls.Server(&prefixConn{Conn: conn, r: br}, &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"}, // keep the client leg on h1 for clean parsing
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			name := hello.ServerName
			if name == "" {
				name = hostname
			}
			return s.ca.certForHost(name)
		},
	})
	if err := tlsConn.Handshake(); err != nil {
		return
	}
	defer tlsConn.Close()

	authority := urlAuthority(hostport, "https")
	sbr := bufio.NewReader(tlsConn)
	for {
		dreq, err := readRawRequest(sbr)
		if err != nil {
			return
		}
		if !s.doAndRelay(tlsConn, sbr, "https", authority, dreq.Target, dreq, clientAddr) {
			return
		}
	}
}

// doAndRelay forwards one request upstream with the Firefox fingerprint, logs
// the full exchange, and relays the response to the client. It returns whether
// the client connection should be kept alive.
func (s *Server) doAndRelay(w io.Writer, cr *bufio.Reader, scheme, host, target string, rr *rawRequest, clientAddr string) bool {
	cfg := s.cfgStore.get()
	_, upDesc := s.upstreamInfo()
	fullURL := scheme + "://" + host + target
	keepAlive := wantsKeepAlive(rr)

	txn := &Transaction{
		Time: time.Now(), ClientAddr: clientAddr, Scheme: scheme,
		Method: rr.Method, Host: host, URL: fullURL, Upstream: upDesc,
		ReqProto: rr.Proto, ReqHeaders: rr.Headers, ReqBody: rr.Body,
	}

	if hasUpgrade(rr) {
		return s.handleUpgrade(w, cr, scheme, host, target, rr, txn, cfg)
	}

	s.exchange(txn, scheme, host, rr, cfg)
	if txn.Err != "" {
		writeSimple(w, 502, "netlogger upstream error: "+txn.Err)
		return false
	}
	if err := writeResponse(w, txn.Status, txn.RespHeaders, txn.RespBody, keepAlive); err != nil {
		return false
	}
	return keepAlive
}

// exchange performs one request upstream (with retries), fills in the
// response side of txn, and logs it. A failure is recorded as status 502 with
// txn.Err set.
func (s *Server) exchange(txn *Transaction, scheme, host string, rr *rawRequest, cfg Config) {
	fullURL := txn.URL
	start := time.Now()
	var (
		statusCode  int
		respProto   string
		respHeaders []HeaderKV
		respBody    []byte
		doErr       error
	)

	if scheme == "https" {
		// A request that dies on a dead or confused connection is replayed on a
		// fresh one, as browsers do. Non-idempotent methods get one replay;
		// the body is fully buffered so replaying is exact.
		maxAttempts := 3
		if !idempotent(rr.Method) {
			maxAttempts = 2
		}
		for attempt := 1; attempt <= maxAttempts; attempt++ {
			txn.Attempts = attempt
			pc, desc, err := s.acquire(host)
			if err != nil {
				doErr = err
				break
			}
			txn.Upstream = desc
			req, err := buildUpstreamRequest(rr, fullURL, host, cfg)
			if err != nil {
				s.release(host, pc, "")
				doErr = err
				break
			}
			resp, rerr := pc.c.Do(req)
			if rerr == nil {
				respBody, rerr = io.ReadAll(resp.Body)
				resp.Body.Close()
				s.release(host, pc, resp.Proto)
				if rerr == nil {
					doErr = nil
					statusCode = resp.StatusCode
					respProto = resp.Proto
					respHeaders = headerKVs(resp.Header)
					break
				}
			} else {
				s.release(host, pc, "")
			}
			doErr = rerr
			if !retryable(rerr) {
				break
			}
			s.discard(host, pc)
		}
	} else {
		// Cleartext http:// via the standard proxied client.
		statusCode, respHeaders, respBody, doErr = s.doPlain(rr.Method, fullURL, rr, cfg)
		respProto = "HTTP/1.1"
	}

	txn.DurationMs = time.Since(start).Milliseconds()
	if doErr != nil {
		txn.Status = 502
		txn.Err = doErr.Error()
	} else {
		txn.Status = statusCode
		txn.RespProto = respProto
		txn.RespHeaders = respHeaders
		txn.RespBody = respBody
	}
	s.logs.add(txn)
}

// Replay re-sends a logged request through the same upstream path and logs
// the result as a new transaction. Websocket handshakes cannot be replayed.
func (s *Server) Replay(orig *Transaction) (*Transaction, error) {
	u, err := url.Parse(orig.URL)
	if err != nil {
		return nil, err
	}
	rr := &rawRequest{Method: orig.Method, Target: u.RequestURI(), Proto: orig.ReqProto, Headers: orig.ReqHeaders, Body: orig.ReqBody}
	if hasUpgrade(rr) {
		return nil, errors.New("websocket handshakes cannot be replayed")
	}
	_, upDesc := s.upstreamInfo()
	txn := &Transaction{
		Time: time.Now(), ClientAddr: "replay of #" + strconv.FormatInt(orig.ID, 10), Scheme: orig.Scheme,
		Method: rr.Method, Host: orig.Host, URL: orig.URL, Upstream: upDesc,
		ReqProto: rr.Proto, ReqHeaders: rr.Headers, ReqBody: rr.Body,
	}
	s.exchange(txn, orig.Scheme, orig.Host, rr, s.cfgStore.get())
	return txn, nil
}

// buildUpstreamRequest turns the client's request into the upstream HTTP/2
// request: lowercase names, original order, Firefox's "te: trailers".
func buildUpstreamRequest(rr *rawRequest, fullURL, host string, cfg Config) (*http.Request, error) {
	var body io.Reader
	if len(rr.Body) > 0 {
		body = bytes.NewReader(rr.Body)
	}
	req, err := http.NewRequest(rr.Method, fullURL, body)
	if err != nil {
		return nil, err
	}
	req.Header = http.Header{}
	order := make([]string, 0, len(rr.Headers)+1)
	haveTE := false
	for _, h := range rr.Headers {
		ln := strings.ToLower(h.Name)
		// Skip connection-scoped headers, Host (derived from URL), and
		// Content-Length (the transport frames the body itself; forwarding
		// the client's value produces a duplicate that strict servers 400).
		if hopByHop[ln] || ln == "host" || ln == "content-length" {
			continue
		}
		if ln == "user-agent" && cfg.ForceUA {
			continue
		}
		if ln == "te" {
			haveTE = true
		}
		// HTTP/2 header names must be lowercase; real Firefox sends them
		// lowercase too. Use the lowercased name as the key (and never
		// Header.Set, which would Title-Case it).
		req.Header[ln] = append(req.Header[ln], h.Value)
		order = append(order, ln)
	}
	if cfg.ForceUA {
		req.Header["user-agent"] = []string{fp.UserAgent}
		order = append(order, "user-agent")
	}
	// Firefox always sends "te: trailers" on h2; add it if the client (on h1) didn't.
	if !haveTE {
		req.Header["te"] = []string{"trailers"}
		order = append(order, "te")
	}
	req.Header[http.HeaderOrderKey] = order
	req.Host = host
	return req, nil
}

func idempotent(method string) bool {
	switch strings.ToUpper(method) {
	case "GET", "HEAD", "OPTIONS", "PUT", "DELETE", "TRACE":
		return true
	}
	return false
}

// retryable reports whether an upstream error means the connection was dead
// or unusable rather than the request being refused: worth one more try on a
// fresh connection. Certificate, DNS and timeout errors are final.
func retryable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) || errors.Is(err, net.ErrClosed) {
		return true
	}
	msg := err.Error()
	for _, s := range []string{
		"EOF", "connection reset", "broken pipe", "use of closed network connection",
		"protocol negotiated", "does not speak", "GOAWAY", "client connection lost",
		"Proxy responded with non 200", "server closed idle connection",
	} {
		if strings.Contains(msg, s) {
			return true
		}
	}
	return false
}

// rawTunnel pipes bytes untouched between client and origin (via the upstream
// proxy if set). Used when MITM is disabled; content is not logged.
func (s *Server) rawTunnel(client net.Conn, br *bufio.Reader, hostport string) {
	cfg := s.cfgStore.get()
	var upstream net.Conn
	var err error
	if u := strings.TrimSpace(cfg.UpstreamURL); u != "" {
		upstream, err = dialViaHTTPProxy(u, hostport)
	} else {
		upstream, err = net.DialTimeout("tcp", hostport, 30*time.Second)
	}
	if err != nil {
		return
	}
	defer upstream.Close()
	go io.Copy(upstream, br)  //nolint (client -> upstream, drains buffered bytes)
	io.Copy(client, upstream) // upstream -> client
}

// --- helpers ---

// prefixConn presents a net.Conn whose reads come from a bufio.Reader (which may
// hold bytes already buffered past the CONNECT line), while writes go direct.
type prefixConn struct {
	net.Conn
	r *bufio.Reader
}

func (p *prefixConn) Read(b []byte) (int, error) { return p.r.Read(b) }

func readRawRequest(br *bufio.Reader) (*rawRequest, error) {
	line, err := readLine(br)
	if err != nil {
		return nil, err
	}
	for line == "" { // tolerate leading blank lines between keep-alive requests
		if line, err = readLine(br); err != nil {
			return nil, err
		}
	}
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 3 {
		return nil, fmt.Errorf("malformed request line: %q", line)
	}
	rr := &rawRequest{Method: parts[0], Target: parts[1], Proto: parts[2]}

	clen := -1
	chunked := false
	for {
		hl, err := readLine(br)
		if err != nil {
			return nil, err
		}
		if hl == "" {
			break
		}
		idx := strings.IndexByte(hl, ':')
		if idx < 0 {
			continue
		}
		name := strings.TrimSpace(hl[:idx])
		val := strings.TrimSpace(hl[idx+1:])
		rr.Headers = append(rr.Headers, HeaderKV{Name: name, Value: val})
		switch strings.ToLower(name) {
		case "content-length":
			clen, _ = strconv.Atoi(val)
		case "transfer-encoding":
			if strings.Contains(strings.ToLower(val), "chunked") {
				chunked = true
			}
		}
	}

	switch {
	case chunked:
		b, err := io.ReadAll(httputil.NewChunkedReader(br))
		if err != nil {
			return nil, err
		}
		rr.Body = b
	case clen > 0:
		b := make([]byte, clen)
		if _, err := io.ReadFull(br, b); err != nil {
			return nil, err
		}
		rr.Body = b
	}
	return rr, nil
}

func readLine(br *bufio.Reader) (string, error) {
	s, err := br.ReadString('\n')
	if err != nil {
		if len(s) > 0 {
			return strings.TrimRight(s, "\r\n"), nil
		}
		return "", err
	}
	return strings.TrimRight(s, "\r\n"), nil
}

func wantsKeepAlive(rr *rawRequest) bool {
	conn := ""
	for _, h := range rr.Headers {
		if strings.EqualFold(h.Name, "connection") {
			conn = strings.ToLower(h.Value)
		}
	}
	if strings.Contains(conn, "close") {
		return false
	}
	if strings.HasPrefix(rr.Proto, "HTTP/1.0") {
		return strings.Contains(conn, "keep-alive")
	}
	return true
}

func hasUpgrade(rr *rawRequest) bool {
	for _, h := range rr.Headers {
		if strings.EqualFold(h.Name, "upgrade") && strings.TrimSpace(h.Value) != "" {
			return true
		}
	}
	return false
}

func writeResponse(w io.Writer, statusCode int, headers []HeaderKV, body []byte, keepAlive bool) error {
	var b bytes.Buffer
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\n", statusCode, statusText(statusCode))

	for _, h := range headers {
		ln := strings.ToLower(h.Name)
		if ln == "transfer-encoding" || ln == "connection" || ln == "content-length" {
			continue
		}
		if strings.HasSuffix(h.Name, ":") || strings.HasPrefix(h.Name, ":") { // fhttp magic / pseudo keys
			continue
		}
		fmt.Fprintf(&b, "%s: %s\r\n", h.Name, h.Value)
	}
	fmt.Fprintf(&b, "Content-Length: %d\r\n", len(body))
	if keepAlive {
		b.WriteString("Connection: keep-alive\r\n")
	} else {
		b.WriteString("Connection: close\r\n")
	}
	b.WriteString("\r\n")
	if _, err := w.Write(b.Bytes()); err != nil {
		return err
	}
	if len(body) > 0 {
		if _, err := w.Write(body); err != nil {
			return err
		}
	}
	return nil
}

func writeSimple(w io.Writer, code int, msg string) {
	body := []byte(msg)
	fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
		code, statusText(code), len(body))
	w.Write(body)
}

func headerKVs(h http.Header) []HeaderKV {
	var out []HeaderKV
	for name, vals := range h {
		if strings.HasSuffix(name, ":") || strings.HasPrefix(name, ":") {
			continue
		}
		for _, v := range vals {
			out = append(out, HeaderKV{Name: name, Value: v})
		}
	}
	return out
}

// urlAuthority returns a URL/authority-safe host[:port] from a CONNECT target
// or parsed host: it drops the default port and brackets IPv6 literals so the
// reconstructed URL parses correctly.
func urlAuthority(hostport, scheme string) string {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		host = strings.Trim(hostport, "[]") // bare host, or bracketed IPv6 with no port
		port = ""
	}
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	if strings.Contains(host, ":") { // IPv6 literal
		host = "[" + host + "]"
	}
	if port == "" {
		return host
	}
	return host + ":" + port
}

// dialViaHTTPProxy opens a TCP tunnel to target through an HTTP CONNECT proxy.
func dialViaHTTPProxy(proxyURL, target string) (net.Conn, error) {
	u, err := url.Parse(proxyURL)
	if err != nil {
		return nil, err
	}
	conn, err := net.DialTimeout("tcp", u.Host, 30*time.Second)
	if err != nil {
		return nil, err
	}
	req := "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n"
	if u.User != nil {
		req += "Proxy-Authorization: Basic " + basicAuth(u.User.Username(), passwordOf(u.User)) + "\r\n"
	}
	req += "\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		conn.Close()
		return nil, err
	}
	r := bufio.NewReader(conn)
	line, err := readLine(r)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if !strings.Contains(line, " 200 ") {
		conn.Close()
		return nil, fmt.Errorf("upstream CONNECT failed: %s", line)
	}
	for {
		hl, err := readLine(r)
		if err != nil {
			conn.Close()
			return nil, err
		}
		if hl == "" {
			break
		}
	}
	return conn, nil
}
