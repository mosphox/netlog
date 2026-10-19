package main

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"encoding/base64"
	"io"
	stdhttp "net/http"
	"net/url"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

func statusText(code int) string {
	if t := stdhttp.StatusText(code); t != "" {
		return t
	}
	return "Status"
}

func basicAuth(user, pass string) string {
	return base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
}

func passwordOf(u *url.Userinfo) string {
	p, _ := u.Password()
	return p
}

// decodeBody attempts to decompress a body given its Content-Encoding. It
// returns the decoded bytes and true on success; on any failure it returns the
// input unchanged and false so callers can fall back to showing raw bytes.
func decodeBody(encoding string, data []byte) ([]byte, bool) {
	enc := strings.ToLower(strings.TrimSpace(encoding))
	// Content-Encoding may list multiple; take the last applied (outermost first).
	if i := strings.LastIndex(enc, ","); i >= 0 {
		enc = strings.TrimSpace(enc[i+1:])
	}
	switch enc {
	case "", "identity":
		return data, false
	case "gzip", "x-gzip":
		r, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return data, false
		}
		defer r.Close()
		if out, err := io.ReadAll(r); err == nil {
			return out, true
		}
	case "deflate":
		r := flate.NewReader(bytes.NewReader(data))
		defer r.Close()
		if out, err := io.ReadAll(r); err == nil {
			return out, true
		}
	case "br":
		if out, err := io.ReadAll(brotli.NewReader(bytes.NewReader(data))); err == nil {
			return out, true
		}
	case "zstd":
		r, err := zstd.NewReader(bytes.NewReader(data))
		if err != nil {
			return data, false
		}
		defer r.Close()
		if out, err := io.ReadAll(r); err == nil {
			return out, true
		}
	}
	return data, false
}
