package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"net"
	stdhttp "net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/mosphox/netlog/internal/fp"
)

//go:embed web/index.html
var webFS embed.FS

// fingerprint constants surfaced in the UI so the operator can confirm at a
// glance what netlog presents upstream.
const (
	targetJA4    = "t13d1517h2_8daaf6152771_3cbfd9057e0d"
	targetJA3    = "9d42e90b0225e779f03141ddcd699df2"
	targetAkamai = "6ea73faa8fc5aac76bded7bd238f6433"
	targetAkText = "1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s"
)

// inlineCap bounds how many body bytes are sent to the browser for inline
// display. The full body is always available via the download endpoint.
const inlineCap = 2 << 20 // 2 MiB

type webServer struct {
	srv     *Server
	caPath  string // where the CA .pem was exported (Desktop)
	dataDir string
}

func (ws *webServer) routes() *stdhttp.ServeMux {
	mux := stdhttp.NewServeMux()
	mux.HandleFunc("GET /", ws.handleIndex)
	mux.HandleFunc("GET /api/status", ws.handleStatus)
	mux.HandleFunc("GET /api/config", ws.handleGetConfig)
	mux.HandleFunc("POST /api/config", ws.handleSetConfig)
	mux.HandleFunc("GET /api/logs", ws.handleList)
	mux.HandleFunc("GET /api/logs/{id}", ws.handleDetail)
	mux.HandleFunc("GET /api/logs/{id}/body", ws.handleBody)
	mux.HandleFunc("POST /api/logs/{id}/replay", ws.handleReplay)
	mux.HandleFunc("POST /api/clear", ws.handleClear)
	mux.HandleFunc("GET /api/har", ws.handleHAR)
	mux.HandleFunc("GET /ca.pem", ws.handleCA)
	return mux
}

// handleHAR streams the current logs as a HAR file download. Content-Disposition
// makes the browser save it through its normal download flow.
func (ws *webServer) handleHAR(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	data, err := buildHAR(ws.srv.logs.allFull())
	if err != nil {
		stdhttp.Error(w, err.Error(), 500)
		return
	}
	name := "netlog-" + time.Now().Format("20060102-150405") + ".har"
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.Write(data)
}

func (ws *webServer) handleIndex(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	data, err := webFS.ReadFile("web/index.html")
	if err != nil {
		stdhttp.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(data)
}

func (ws *webServer) handleStatus(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	cfg := ws.srv.cfgStore.get()
	_, upDesc := ws.srv.upstreamInfo()
	writeJSON(w, map[string]any{
		"proxy_port":   ws.srv.currentPort(),
		"upstream":     upDesc,
		"mitm":         cfg.MITMEnabled,
		"force_ua":     cfg.ForceUA,
		"user_agent":   fp.UserAgent,
		"ja4":          targetJA4,
		"ja3_hash":     targetJA3,
		"akamai_hash":  targetAkamai,
		"akamai_text":  targetAkText,
		"count":        ws.srv.logs.count(),
		"max_id":       ws.srv.logs.maxID(),
		"upstream_url": cfg.UpstreamURL,
		"listening":    ws.srv.currentPort() != 0,
		"ca_path":      ws.caPath,
		"data_dir":     ws.dataDir,
	})
}

func (ws *webServer) handleGetConfig(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	writeJSON(w, ws.srv.cfgStore.get())
}

func (ws *webServer) handleSetConfig(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	var in Config
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSON(w, map[string]any{"ok": false, "error": "bad json: " + err.Error()})
		return
	}
	if in.ListenPort < 1 || in.ListenPort > 65535 {
		writeJSON(w, map[string]any{"ok": false, "error": "listen port out of range"})
		return
	}
	if u := strings.TrimSpace(in.UpstreamURL); u != "" {
		if !strings.Contains(u, "://") {
			in.UpstreamURL = "http://" + u
		}
	}
	if err := ws.srv.ApplyConfig(in); err != nil {
		writeJSON(w, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, map[string]any{"ok": true, "config": ws.srv.cfgStore.get(), "proxy_port": ws.srv.currentPort()})
}

func (ws *webServer) handleList(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	q := r.URL.Query()
	after, _ := strconv.ParseInt(q.Get("after"), 10, 64)
	before, _ := strconv.ParseInt(q.Get("before"), 10, 64)
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > 5000 {
		limit = 500
	}
	entries, maxID := ws.srv.logs.list(after, before, limit)
	out := make([]map[string]any, 0, len(entries))
	for _, e := range entries {
		out = append(out, map[string]any{
			"id": e.ID, "time": e.Time.Format(time.RFC3339Nano),
			"method": e.Method, "scheme": e.Scheme, "host": e.Host, "url": e.URL,
			"status": e.Status, "req_len": e.ReqLen, "resp_len": e.RespLen,
			"duration_ms": e.DurationMs, "err": e.Err, "client": e.ClientAddr,
			"attempts": e.Attempts, "ws": e.WS, "ws_count": e.WSCount, "ct": e.CT,
		})
	}
	writeJSON(w, map[string]any{"max_id": maxID, "entries": out})
}

func (ws *webServer) handleDetail(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	t, ok := ws.srv.logs.get(id)
	if !ok {
		stdhttp.Error(w, "not found", 404)
		return
	}
	writeJSON(w, detailView(t))
}

func detailView(t *Transaction) map[string]any {
	msgs := make([]map[string]any, 0, len(t.WSMessages))
	for _, m := range t.WSMessages {
		v := map[string]any{"time": m.Time.Format(time.RFC3339Nano), "from_client": m.FromClient, "opcode": m.Opcode, "len": m.Len, "size": len(m.Data)}
		if m.Opcode == 1 || m.Opcode == -1 || (m.Opcode == 8 && len(m.Data) <= 2) || utf8.Valid(m.Data) && looksText(m.Data, "") {
			v["text"] = string(m.Data)
			if m.Opcode == 8 && len(m.Data) >= 2 {
				v["text"] = fmt.Sprintf("close %d %s", int(m.Data[0])<<8|int(m.Data[1]), m.Data[2:])
			}
		} else {
			v["hex"] = hexDump(m.Data)
		}
		msgs = append(msgs, v)
	}
	return map[string]any{
		"id": t.ID, "time": t.Time.Format(time.RFC3339Nano), "client_addr": t.ClientAddr,
		"scheme": t.Scheme, "method": t.Method, "host": t.Host, "url": t.URL, "upstream": t.Upstream,
		"req_proto": t.ReqProto, "req_headers": t.ReqHeaders, "req_body": bodyView(t.ReqHeaders, t.ReqBody),
		"status": t.Status, "resp_proto": t.RespProto, "resp_headers": t.RespHeaders,
		"resp_body":   bodyView(t.RespHeaders, t.RespBody),
		"duration_ms": t.DurationMs, "err": t.Err, "attempts": t.Attempts,
		"ws_open": t.WSOpen, "ws_messages": msgs,
	}
}

// handleReplay re-sends a logged request upstream and returns the new entry.
func (ws *webServer) handleReplay(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	t, ok := ws.srv.logs.get(id)
	if !ok {
		writeJSON(w, map[string]any{"ok": false, "error": "request not found"})
		return
	}
	nt, err := ws.srv.Replay(t)
	if err != nil {
		writeJSON(w, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, map[string]any{"ok": true, "id": nt.ID, "status": nt.Status, "err": nt.Err})
}

// handleBody streams a full body for download/viewing. side=req|resp,
// mode=raw|decoded.
func (ws *webServer) handleBody(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	t, ok := ws.srv.logs.get(id)
	if !ok {
		stdhttp.Error(w, "not found", 404)
		return
	}
	var headers []HeaderKV
	var body []byte
	if r.URL.Query().Get("side") == "req" {
		headers, body = t.ReqHeaders, t.ReqBody
	} else {
		headers, body = t.RespHeaders, t.RespBody
	}
	if r.URL.Query().Get("mode") == "decoded" {
		if dec, ok := decodeBody(headerValue(headers, "content-encoding"), body); ok {
			body = dec
		}
	}
	ct := headerValue(headers, "content-type")
	if ct == "" {
		ct = "application/octet-stream"
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.Write(body)
}

func (ws *webServer) handleClear(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	ws.srv.logs.clear()
	writeJSON(w, map[string]any{"ok": true})
}

func (ws *webServer) handleCA(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="netlog-ca.pem"`)
	w.Write(ws.srv.ca.caPEM)
}

// bodyView builds the inline, browser-friendly representation of a body:
// decoded when compressed, capped, with a flag when truncated.
func bodyView(headers []HeaderKV, body []byte) map[string]any {
	enc := headerValue(headers, "content-encoding")
	ct := headerValue(headers, "content-type")
	decoded, wasDecoded := decodeBody(enc, body)
	isText := looksText(decoded, ct)

	view := map[string]any{
		"size":         len(body),
		"decoded_size": len(decoded),
		"encoding":     enc,
		"content_type": ct,
		"was_decoded":  wasDecoded,
		"is_text":      isText,
	}
	shown := decoded
	truncated := false
	if len(shown) > inlineCap {
		shown = shown[:inlineCap]
		truncated = true
	}
	view["truncated"] = truncated
	if isText {
		view["text"] = string(shown)
	} else {
		view["text"] = ""
		view["hex"] = hexDump(shown)
	}
	return view
}

func looksText(b []byte, contentType string) bool {
	ct := strings.ToLower(contentType)
	if strings.HasPrefix(ct, "text/") ||
		strings.Contains(ct, "json") || strings.Contains(ct, "xml") ||
		strings.Contains(ct, "javascript") || strings.Contains(ct, "html") ||
		strings.Contains(ct, "urlencoded") || strings.Contains(ct, "graphql") ||
		strings.Contains(ct, "csv") || strings.Contains(ct, "svg") {
		return true
	}
	if len(b) == 0 {
		return true
	}
	sample := b
	if len(sample) > 4096 {
		sample = sample[:4096]
	}
	if !utf8.Valid(sample) {
		return false
	}
	nul := 0
	for _, c := range sample {
		if c == 0 {
			nul++
		}
	}
	return nul == 0
}

func hexDump(b []byte) string {
	const per = 16
	var sb strings.Builder
	for i := 0; i < len(b); i += per {
		fmt.Fprintf(&sb, "%08x  ", i)
		end := i + per
		if end > len(b) {
			end = len(b)
		}
		for j := i; j < i+per; j++ {
			if j < end {
				fmt.Fprintf(&sb, "%02x ", b[j])
			} else {
				sb.WriteString("   ")
			}
		}
		sb.WriteString(" ")
		for j := i; j < end; j++ {
			c := b[j]
			if c >= 32 && c < 127 {
				sb.WriteByte(c)
			} else {
				sb.WriteByte('.')
			}
		}
		sb.WriteByte('\n')
	}
	return sb.String()
}

func headerValue(headers []HeaderKV, name string) string {
	for _, h := range headers {
		if strings.EqualFold(h.Name, name) {
			return h.Value
		}
	}
	return ""
}

func writeJSON(w stdhttp.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(v)
}

// startWeb runs the web UI/API server on the given address (blocks).
func (ws *webServer) start(addr string) error {
	srv := &stdhttp.Server{
		Addr:         addr,
		Handler:      ws.routes(),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 120 * time.Second,
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return srv.Serve(ln)
}
