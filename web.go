package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	stdhttp "net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	fhttp "github.com/bogdanfinn/fhttp"

	"github.com/mosphox/netlog/internal/fp"
)

//go:embed web
var webFS embed.FS

// inlineCap bounds how many body bytes are sent to the browser for inline
// display. The full body is always available via the download endpoint.
const inlineCap = 2 << 20 // 2 MiB

type webServer struct {
	srv     *Server
	caPath  string // where the CA .pem was exported
	dataDir string
}

func (ws *webServer) routes() *stdhttp.ServeMux {
	mux := stdhttp.NewServeMux()
	static, _ := fs.Sub(webFS, "web")
	files := stdhttp.FileServerFS(static)
	mux.HandleFunc("GET /", func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		// Embedded files carry no modification time; make the browser
		// revalidate so an upgraded binary never runs a stale UI.
		w.Header().Set("Cache-Control", "no-cache")
		files.ServeHTTP(w, r)
	})
	mux.HandleFunc("GET /api/status", ws.handleStatus)
	mux.HandleFunc("GET /api/config", ws.handleGetConfig)
	mux.HandleFunc("POST /api/config", ws.handleSetConfig)
	mux.HandleFunc("GET /api/fingerprints", ws.handleFingerprints)
	mux.HandleFunc("POST /api/fingerprints/{id}/probe", ws.handleProbe)
	mux.HandleFunc("POST /api/upstreams/test", ws.handleTestUpstream)
	mux.HandleFunc("GET /api/logs", ws.handleList)
	mux.HandleFunc("GET /api/logs/{id}", ws.handleDetail)
	mux.HandleFunc("GET /api/logs/{id}/body", ws.handleBody)
	mux.HandleFunc("POST /api/logs/{id}/replay", ws.handleReplay)
	mux.HandleFunc("POST /api/send", ws.handleSend)
	mux.HandleFunc("GET /api/intercept", ws.handleInterceptList)
	mux.HandleFunc("POST /api/intercept/{id}", ws.handleInterceptDecide)
	mux.HandleFunc("POST /api/intercept/forward-all", ws.handleInterceptForwardAll)
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

func (ws *webServer) handleStatus(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	cfg := ws.srv.cfgStore.get()
	var active any
	if u := cfg.upstream(cfg.ActiveUpstream); u != nil {
		active = map[string]any{"id": u.ID, "name": u.Name, "url": redactURL(u.URL)}
	}
	writeJSON(w, map[string]any{
		"proxy_port":     ws.srv.currentPort(),
		"listening":      ws.srv.currentPort() != 0,
		"upstream":       active,
		"mitm":           cfg.MITMEnabled,
		"force_ua":       cfg.ForceUA,
		"fingerprint":    cfg.Fingerprint,
		"fallback":       cfg.FallbackFingerprint,
		"intercept":      cfg.Intercept,
		"intercept_held": len(ws.srv.intercept.list()),
		"count":          ws.srv.logs.count(),
		"max_id":         ws.srv.logs.maxID(),
		"ca_path":        ws.caPath,
		"data_dir":       ws.dataDir,
	})
}

func (ws *webServer) handleGetConfig(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	writeJSON(w, ws.srv.cfgStore.get())
}

func (ws *webServer) handleSetConfig(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	in := ws.srv.cfgStore.get()
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSON(w, map[string]any{"ok": false, "error": "bad json: " + err.Error()})
		return
	}
	if err := ws.srv.ApplyConfig(in); err != nil {
		writeJSON(w, map[string]any{"ok": false, "error": err.Error(), "config": ws.srv.cfgStore.get()})
		return
	}
	writeJSON(w, map[string]any{"ok": true, "config": ws.srv.cfgStore.get(), "proxy_port": ws.srv.currentPort()})
}

func (ws *webServer) handleFingerprints(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	writeJSON(w, map[string]any{"profiles": fp.All(), "default": fp.Default.ID})
}

// handleProbe checks one profile live against the reflection service through
// the active upstream.
func (ws *webServer) handleProbe(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	p, ok := fp.Lookup(r.PathValue("id"))
	if !ok {
		writeJSON(w, map[string]any{"ok": false, "error": "unknown profile"})
		return
	}
	cfg := ws.srv.cfgStore.get()
	upURL := ""
	if u := cfg.upstream(cfg.ActiveUpstream); u != nil {
		upURL = u.URL
	}
	res, err := fp.Probe(p, upURL)
	if err != nil {
		writeJSON(w, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, map[string]any{"ok": true, "result": res})
}

// handleTestUpstream sends one request through an upstream to an IP-info
// service and reports the exit IP, location and round-trip time.
func (ws *webServer) handleTestUpstream(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	var in struct {
		URL string `json:"url"`
	}
	json.NewDecoder(r.Body).Decode(&in)
	upURL := strings.TrimSpace(in.URL)
	if upURL != "" {
		if !strings.Contains(upURL, "://") {
			upURL = "http://" + upURL
		}
		if err := (Upstream{Name: "test", URL: upURL}).validate(); err != nil {
			writeJSON(w, map[string]any{"ok": false, "error": err.Error()})
			return
		}
	}
	client, err := newClient(fp.Default, upURL, false)
	if err != nil {
		writeJSON(w, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	defer client.CloseIdleConnections()
	req, _ := fhttp.NewRequest("GET", "https://ipinfo.io/json", nil)
	req.Header = fhttp.Header{"user-agent": {fp.Default.UserAgent}, "accept": {"application/json"}, fhttp.HeaderOrderKey: {"user-agent", "accept"}}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		writeJSON(w, map[string]any{"ok": false, "error": err.Error(), "ms": time.Since(start).Milliseconds()})
		return
	}
	defer resp.Body.Close()
	var info map[string]any
	json.NewDecoder(resp.Body).Decode(&info)
	writeJSON(w, map[string]any{"ok": resp.StatusCode == 200, "status": resp.StatusCode, "ms": time.Since(start).Milliseconds(),
		"ip": info["ip"], "country": info["country"], "city": info["city"], "org": info["org"]})
}

func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.User == nil {
		return raw
	}
	u.User = url.User(u.User.Username())
	return u.String()
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
			"source": e.Source, "profile": e.Profile, "intercepted": e.Intercepted,
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
		"source": t.Source, "profile": t.Profile, "profile_auto": t.ProfileAuto, "intercepted": t.Intercepted,
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

// handleSend performs a hand-built request (the repeater) and returns it in
// full.
func (ws *webServer) handleSend(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	var in sendRequest
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSON(w, map[string]any{"ok": false, "error": "bad json: " + err.Error()})
		return
	}
	t, err := ws.srv.Send(in, "repeater")
	if err != nil {
		writeJSON(w, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, map[string]any{"ok": true, "txn": detailView(t)})
}

func (ws *webServer) handleInterceptList(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	held := ws.srv.intercept.list()
	out := make([]map[string]any, 0, len(held))
	for _, h := range held {
		out = append(out, map[string]any{"id": h.ID, "time": h.Time.Format(time.RFC3339Nano), "client": h.Client,
			"method": h.Method, "url": h.URL, "headers": h.Headers, "body": h.Body, "body_text": utf8.Valid(h.Body)})
	}
	cfg := ws.srv.cfgStore.get()
	writeJSON(w, map[string]any{"enabled": cfg.Intercept.Enabled, "filter": cfg.Intercept.Filter, "held": out})
}

func (ws *webServer) handleInterceptDecide(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	var in struct {
		Action string       `json:"action"` // "forward" or "drop"
		Edit   *sendRequest `json:"edit"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSON(w, map[string]any{"ok": false, "error": "bad json: " + err.Error()})
		return
	}
	if in.Edit != nil {
		if err := applyEdit(&Transaction{}, in.Edit); err != nil {
			writeJSON(w, map[string]any{"ok": false, "error": err.Error()})
			return
		}
	}
	if !ws.srv.intercept.decide(id, interceptDecision{drop: in.Action == "drop", edit: in.Edit}) {
		writeJSON(w, map[string]any{"ok": false, "error": "that request is no longer held"})
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (ws *webServer) handleInterceptForwardAll(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	ws.srv.intercept.forwardAll()
	writeJSON(w, map[string]any{"ok": true})
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
