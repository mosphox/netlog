package main

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"time"
)

// HAR 1.2 export of captured transactions. Bodies are included in full: text
// inline, binary base64-encoded. Compressed response bodies are decoded for the
// `content.text` (as browser dev-tools HAR does) with the wire size recorded in
// bodySize.

type harNV struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type harPostData struct {
	MimeType string `json:"mimeType"`
	Text     string `json:"text"`
	Encoding string `json:"encoding,omitempty"`
}

type harContent struct {
	Size     int    `json:"size"`
	MimeType string `json:"mimeType"`
	Text     string `json:"text,omitempty"`
	Encoding string `json:"encoding,omitempty"`
}

func harHeaders(hs []HeaderKV) []harNV {
	out := make([]harNV, 0, len(hs))
	for _, h := range hs {
		out = append(out, harNV{Name: h.Name, Value: h.Value})
	}
	return out
}

func harQuery(rawURL string) []harNV {
	u, err := url.Parse(rawURL)
	if err != nil {
		return []harNV{}
	}
	out := []harNV{}
	for k, vs := range u.Query() {
		for _, v := range vs {
			out = append(out, harNV{Name: k, Value: v})
		}
	}
	return out
}

func buildHAR(txns []*Transaction) ([]byte, error) {
	entries := make([]map[string]any, 0, len(txns))
	for _, t := range txns {
		// Request body.
		var postData *harPostData
		if len(t.ReqBody) > 0 {
			ct := headerValue(t.ReqHeaders, "content-type")
			pd := &harPostData{MimeType: ct}
			if looksText(t.ReqBody, ct) {
				pd.Text = string(t.ReqBody)
			} else {
				pd.Text = base64.StdEncoding.EncodeToString(t.ReqBody)
				pd.Encoding = "base64"
			}
			postData = pd
		}

		// Response body: decode compression for the text, keep wire size in bodySize.
		respCT := headerValue(t.RespHeaders, "content-type")
		decoded, _ := decodeBody(headerValue(t.RespHeaders, "content-encoding"), t.RespBody)
		content := harContent{Size: len(decoded), MimeType: respCT}
		if len(decoded) > 0 {
			if looksText(decoded, respCT) {
				content.Text = string(decoded)
			} else {
				content.Text = base64.StdEncoding.EncodeToString(decoded)
				content.Encoding = "base64"
			}
		}

		reqProto := t.ReqProto
		if reqProto == "" {
			reqProto = "HTTP/1.1"
		}
		respProto := t.RespProto
		if respProto == "" {
			respProto = "HTTP/1.1"
		}

		req := map[string]any{
			"method":      t.Method,
			"url":         t.URL,
			"httpVersion": reqProto,
			"headers":     harHeaders(t.ReqHeaders),
			"queryString": harQuery(t.URL),
			"cookies":     []harNV{},
			"headersSize": -1,
			"bodySize":    len(t.ReqBody),
		}
		if postData != nil {
			req["postData"] = postData
		}

		resp := map[string]any{
			"status":      t.Status,
			"statusText":  statusText(t.Status),
			"httpVersion": respProto,
			"headers":     harHeaders(t.RespHeaders),
			"cookies":     []harNV{},
			"content":     content,
			"redirectURL": headerValue(t.RespHeaders, "location"),
			"headersSize": -1,
			"bodySize":    len(t.RespBody),
		}

		entry := map[string]any{
			"startedDateTime": t.Time.Format(time.RFC3339Nano),
			"time":            t.DurationMs,
			"request":         req,
			"response":        resp,
			"cache":           map[string]any{},
			"timings":         map[string]any{"send": 0, "wait": t.DurationMs, "receive": 0},
			"_upstream":       t.Upstream,
			"_clientAddr":     t.ClientAddr,
		}
		if t.Err != "" {
			entry["_error"] = t.Err
		}
		entries = append(entries, entry)
	}

	har := map[string]any{
		"log": map[string]any{
			"version": "1.2",
			"creator": map[string]any{"name": "netlog", "version": "1"},
			"entries": entries,
		},
	}
	return json.MarshalIndent(har, "", "  ")
}
