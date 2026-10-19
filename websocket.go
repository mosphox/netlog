package main

import (
	"bufio"
	"bytes"
	"compress/flate"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"

	"netlogger/internal/fp"
)

// Bounds on what one websocket connection may keep in the log. The connection
// itself is never limited, only what is recorded.
const (
	wsMaxMessages = 5000
	wsMaxMsgBytes = 1 << 20  // per message
	wsMaxBytes    = 32 << 20 // per connection
)

// handleUpgrade relays an Upgrade (websocket) request: it opens its own
// connection to the origin with the Firefox ClientHello, replays the client's
// handshake byte for byte, and on 101 pipes both directions while recording
// the messages. It always ends the client connection.
func (s *Server) handleUpgrade(w io.Writer, cr *bufio.Reader, scheme, host, target string, rr *rawRequest, txn *Transaction, cfg Config) bool {
	start := time.Now()
	fail := func(err error) bool {
		txn.Status = 502
		txn.Err = err.Error()
		txn.DurationMs = time.Since(start).Milliseconds()
		s.logs.add(txn)
		writeSimple(w, 502, "netlogger upstream error: "+err.Error())
		return false
	}

	hostname, port := host, "443"
	if scheme == "http" {
		port = "80"
	}
	if h, p, err := net.SplitHostPort(host); err == nil {
		hostname, port = h, p
	}
	hostname = strings.Trim(hostname, "[]")
	dialAddr := net.JoinHostPort(hostname, port)

	upURL, desc := s.upstreamInfo()
	var raw net.Conn
	var err error
	if upURL != "" && !isLoopbackHost(hostname) {
		raw, err = dialVia(upURL, dialAddr)
	} else {
		raw, err = net.DialTimeout("tcp", dialAddr, 15*time.Second)
		desc = "direct"
	}
	txn.Upstream = desc
	txn.Attempts = 1
	if err != nil {
		return fail(err)
	}
	defer raw.Close()

	conn := raw
	if scheme == "https" {
		uc, err := fp.WebSocketClient(raw, hostname)
		if err != nil {
			return fail(err)
		}
		uc.SetDeadline(time.Now().Add(15 * time.Second))
		if err := uc.Handshake(); err != nil {
			return fail(err)
		}
		uc.SetDeadline(time.Time{})
		conn = uc
	}

	// Replay the handshake in the client's exact header order.
	var b bytes.Buffer
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\n", rr.Method, target)
	haveHost := false
	for _, h := range rr.Headers {
		if strings.EqualFold(h.Name, "host") {
			haveHost = true
		}
	}
	if !haveHost {
		fmt.Fprintf(&b, "Host: %s\r\n", host)
	}
	for _, h := range rr.Headers {
		ln := strings.ToLower(h.Name)
		if ln == "proxy-connection" || ln == "proxy-authorization" {
			continue
		}
		v := h.Value
		if ln == "user-agent" && cfg.ForceUA {
			v = fp.UserAgent
		}
		fmt.Fprintf(&b, "%s: %s\r\n", h.Name, v)
	}
	b.WriteString("\r\n")
	b.Write(rr.Body)
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err := conn.Write(b.Bytes()); err != nil {
		return fail(err)
	}
	ur := bufio.NewReader(conn)
	proto, status, headers, err := readResponseHead(ur)
	if err != nil {
		return fail(err)
	}
	txn.Status = status
	txn.RespProto = proto
	txn.RespHeaders = headers

	if status != 101 {
		// Refused upgrade: relay it as an ordinary response and close.
		body, _ := readResponseBody(ur, headers)
		conn.SetDeadline(time.Time{})
		txn.RespBody = body
		txn.DurationMs = time.Since(start).Milliseconds()
		s.logs.add(txn)
		writeResponse(w, status, headers, body, false)
		return false
	}
	conn.SetDeadline(time.Time{})

	var head bytes.Buffer
	fmt.Fprintf(&head, "%s %d %s\r\n", proto, status, statusText(status))
	for _, h := range headers {
		fmt.Fprintf(&head, "%s: %s\r\n", h.Name, h.Value)
	}
	head.WriteString("\r\n")
	if _, err := w.Write(head.Bytes()); err != nil {
		return false
	}

	ext := strings.ToLower(headerValue(headers, "sec-websocket-extensions"))
	deflate := strings.Contains(ext, "permessage-deflate")
	rec := &wsRecorder{}
	toServer := &wsStream{rec: rec, fromClient: true, deflate: deflate, noTakeover: strings.Contains(ext, "client_no_context_takeover")}
	toClient := &wsStream{rec: rec, fromClient: false, deflate: deflate, noTakeover: strings.Contains(ext, "server_no_context_takeover")}

	txn.WSOpen = true
	txn.DurationMs = time.Since(start).Milliseconds()
	id := s.logs.add(txn)
	s.logs.setLive(id, rec.snapshot)

	closeBoth := func() {
		conn.Close()
		if c, ok := w.(net.Conn); ok {
			c.Close()
		}
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		pipeTap(conn, cr, toServer)
		closeBoth()
	}()
	go func() {
		defer wg.Done()
		pipeTap(w, ur, toClient)
		closeBoth()
	}()
	wg.Wait()

	txn.WSOpen = false
	txn.WSMessages = rec.snapshot()
	txn.DurationMs = time.Since(start).Milliseconds()
	s.logs.update(txn)
	s.logs.setLive(id, nil)
	return false
}

// pipeTap copies src to dst and feeds every chunk to the frame parser.
func pipeTap(dst io.Writer, src io.Reader, tap *wsStream) {
	buf := make([]byte, 32<<10)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
			tap.feed(buf[:n])
		}
		if err != nil {
			return
		}
	}
}

// dialVia opens a TCP tunnel to target through the upstream proxy (http
// CONNECT or socks5).
func dialVia(upstream, target string) (net.Conn, error) {
	u, err := url.Parse(upstream)
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(u.Scheme, "socks") {
		d, err := proxy.FromURL(u, &net.Dialer{Timeout: 15 * time.Second})
		if err != nil {
			return nil, err
		}
		return d.Dial("tcp", target)
	}
	return dialViaHTTPProxy(upstream, target)
}

func readResponseHead(br *bufio.Reader) (proto string, status int, headers []HeaderKV, err error) {
	line, err := readLine(br)
	if err != nil {
		return "", 0, nil, err
	}
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 {
		return "", 0, nil, fmt.Errorf("malformed status line: %q", line)
	}
	if status, err = strconv.Atoi(parts[1]); err != nil {
		return "", 0, nil, fmt.Errorf("malformed status line: %q", line)
	}
	for {
		hl, err := readLine(br)
		if err != nil {
			return "", 0, nil, err
		}
		if hl == "" {
			break
		}
		if i := strings.IndexByte(hl, ':'); i > 0 {
			headers = append(headers, HeaderKV{Name: strings.TrimSpace(hl[:i]), Value: strings.TrimSpace(hl[i+1:])})
		}
	}
	return parts[0], status, headers, nil
}

func readResponseBody(br *bufio.Reader, headers []HeaderKV) ([]byte, error) {
	if strings.Contains(strings.ToLower(headerValue(headers, "transfer-encoding")), "chunked") {
		return io.ReadAll(httputil.NewChunkedReader(br))
	}
	if cl := headerValue(headers, "content-length"); cl != "" {
		n, err := strconv.Atoi(cl)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("bad content-length %q", cl)
		}
		b := make([]byte, n)
		_, err = io.ReadFull(br, b)
		return b, err
	}
	return io.ReadAll(io.LimitReader(br, 64<<20))
}

// wsRecorder collects the messages of one connection, both directions.
type wsRecorder struct {
	mu      sync.Mutex
	msgs    []WSMessage
	bytes   int
	dropped int
}

func (r *wsRecorder) add(m WSMessage) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.msgs) >= wsMaxMessages || r.bytes+len(m.Data) > wsMaxBytes {
		r.dropped++
		return
	}
	r.bytes += len(m.Data)
	r.msgs = append(r.msgs, m)
}

func (r *wsRecorder) snapshot() []WSMessage {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]WSMessage, len(r.msgs), len(r.msgs)+1)
	copy(out, r.msgs)
	if r.dropped > 0 {
		out = append(out, WSMessage{Time: time.Now(), Opcode: -1, Data: []byte(fmt.Sprintf("netlogger: %d more messages not recorded (log cap reached)", r.dropped))})
	}
	return out
}

// wsStream parses one direction of websocket frames out of the relayed byte
// stream: reassembles fragments, unmasks, and inflates permessage-deflate.
type wsStream struct {
	rec        *wsRecorder
	fromClient bool
	deflate    bool
	noTakeover bool

	buf        []byte
	frag       []byte
	fragOp     int
	fragZipped bool
	fragLen    int
	dict       []byte // inflate window carried between messages (context takeover)
	broken     bool
}

func (s *wsStream) feed(p []byte) {
	if s.broken {
		return
	}
	s.buf = append(s.buf, p...)
	for {
		if len(s.buf) < 2 {
			return
		}
		b0, b1 := s.buf[0], s.buf[1]
		fin, rsv1, op := b0&0x80 != 0, b0&0x40 != 0, int(b0&0x0f)
		masked := b1&0x80 != 0
		n := uint64(b1 & 0x7f)
		off := 2
		switch n {
		case 126:
			if len(s.buf) < 4 {
				return
			}
			n = uint64(binary.BigEndian.Uint16(s.buf[2:4]))
			off = 4
		case 127:
			if len(s.buf) < 10 {
				return
			}
			n = binary.BigEndian.Uint64(s.buf[2:10])
			off = 10
		}
		if n > 256<<20 { // not a frame we can follow; stop recording this direction
			s.broken = true
			s.buf = nil
			return
		}
		var key []byte
		if masked {
			if len(s.buf) < off+4 {
				return
			}
			key = s.buf[off : off+4]
			off += 4
		}
		if uint64(len(s.buf)-off) < n {
			return
		}
		payload := make([]byte, n)
		copy(payload, s.buf[off:off+int(n)])
		for i := range payload {
			if masked {
				payload[i] ^= key[i%4]
			}
		}
		s.buf = s.buf[off+int(n):]

		if op >= 8 { // control frame: never fragmented
			s.emit(op, payload, len(payload))
			continue
		}
		if op != 0 {
			s.fragOp, s.fragZipped, s.frag, s.fragLen = op, rsv1, nil, 0
		}
		s.fragLen += len(payload)
		if len(s.frag) < wsMaxMsgBytes*4 {
			s.frag = append(s.frag, payload...)
		}
		if !fin {
			continue
		}
		data := s.frag
		if s.fragZipped && s.deflate {
			data = s.inflate(data)
		}
		s.emit(s.fragOp, data, s.fragLen)
		s.frag = nil
	}
}

func (s *wsStream) inflate(p []byte) []byte {
	in := append(append([]byte{}, p...), 0x00, 0x00, 0xff, 0xff)
	r := flate.NewReaderDict(bytes.NewReader(in), s.dict)
	out, _ := io.ReadAll(r) // the stream has no final block, so an EOF error is expected
	if !s.noTakeover {
		s.dict = append(s.dict, out...)
		if len(s.dict) > 32<<10 {
			s.dict = append([]byte{}, s.dict[len(s.dict)-32<<10:]...)
		}
	}
	return out
}

func (s *wsStream) emit(op int, data []byte, wireLen int) {
	if len(data) > wsMaxMsgBytes {
		data = data[:wsMaxMsgBytes]
	}
	s.rec.add(WSMessage{Time: time.Now(), FromClient: s.fromClient, Opcode: op, Data: data, Len: wireLen})
}
