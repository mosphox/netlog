// Command fpprobe verifies the fp package produces the intended fingerprint by
// calling a TLS-fingerprint reflection service and printing the key fields.
//
//	go run ./cmd/fpprobe                       # direct
//	go run ./cmd/fpprobe -proxy http://127.0.0.1:12345   # via LocalRack upstream
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	http "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"

	"netlogger/internal/fp"
)

func main() {
	url := flag.String("url", "https://tls.peet.ws/api/all", "fingerprint reflection endpoint")
	proxy := flag.String("proxy", "", "upstream proxy URL, e.g. http://127.0.0.1:12345")
	raw := flag.Bool("raw", false, "print the full JSON response")
	flag.Parse()

	opts := fp.Options()
	if *proxy != "" {
		opts = append(opts, tls_client.WithProxyUrl(*proxy))
	}
	client, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(), opts...)
	if err != nil {
		fmt.Fprintln(os.Stderr, "client:", err)
		os.Exit(1)
	}

	req, err := http.NewRequest(http.MethodGet, *url, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "request:", err)
		os.Exit(1)
	}
	// A realistic Firefox top-level-navigation header set, in Firefox order.
	req.Header = http.Header{
		"user-agent":                {fp.UserAgent},
		"accept":                    {"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
		"accept-language":           {"en-GB,en;q=0.9"},
		"accept-encoding":           {"gzip, deflate, br, zstd"},
		"upgrade-insecure-requests": {"1"},
		"sec-fetch-dest":            {"document"},
		"sec-fetch-mode":            {"navigate"},
		"sec-fetch-site":            {"none"},
		"sec-fetch-user":            {"?1"},
		"priority":                  {"u=0, i"},
		"te":                        {"trailers"},
		http.HeaderOrderKey: {
			"user-agent", "accept", "accept-language", "accept-encoding",
			"upgrade-insecure-requests", "sec-fetch-dest", "sec-fetch-mode",
			"sec-fetch-site", "sec-fetch-user", "priority", "te",
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, "do:", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if *raw {
		fmt.Println(string(body))
		return
	}

	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		fmt.Println(string(body))
		return
	}
	// tls.peet.ws shape: {"tls":{...,"ja3":..,"ja3_hash":..,"ja4":..,"ja4_r":..},"http2":{"akamai_fingerprint":..,"akamai_fingerprint_hash":..}}
	pretty, _ := json.MarshalIndent(map[string]any{
		"tls":   pick(m["tls"], "ja3", "ja3_hash", "ja4", "ja4_r"),
		"http2": pick(m["http2"], "akamai_fingerprint", "akamai_fingerprint_hash", "sent_frames"),
	}, "", "  ")
	fmt.Println(string(pretty))
}

func pick(v any, keys ...string) map[string]any {
	out := map[string]any{}
	m, ok := v.(map[string]any)
	if !ok {
		return out
	}
	for _, k := range keys {
		if val, ok := m[k]; ok {
			out[k] = val
		}
	}
	return out
}
