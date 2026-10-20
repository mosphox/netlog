// Command fpprobe checks what netlog's fingerprint profiles look like on the
// wire, using a TLS-fingerprint reflection service.
//
//	go run ./cmd/fpprobe                          # every profile, summary
//	go run ./cmd/fpprobe -profile chrome_155 -raw # one profile, full JSON
//	go run ./cmd/fpprobe -check                   # verified profiles vs their captures; exits 1 on mismatch
//	go run ./cmd/fpprobe -proxy http://127.0.0.1:12345
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	http "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"

	"github.com/mosphox/netlog/internal/fp"
)

type peet struct {
	TLS struct {
		JA3Hash   string `json:"ja3_hash"`
		JA4       string `json:"ja4"`
		JA4R      string `json:"ja4_r"`
		Peetprint string `json:"peetprint_hash"`
	} `json:"tls"`
	HTTP2 struct {
		Akamai     string `json:"akamai_fingerprint"`
		AkamaiHash string `json:"akamai_fingerprint_hash"`
	} `json:"http2"`
	UserAgent string `json:"user_agent"`
}

func main() {
	url := flag.String("url", "https://tls.peet.ws/api/all", "fingerprint reflection endpoint")
	proxy := flag.String("proxy", "", "upstream proxy URL, e.g. http://127.0.0.1:12345")
	only := flag.String("profile", "", "probe only this profile id")
	raw := flag.Bool("raw", false, "print the full JSON response")
	check := flag.Bool("check", false, "probe verified profiles and compare with their captured values")
	flag.Parse()

	failed := false
	for _, p := range fp.All() {
		if *only != "" && p.ID != *only {
			continue
		}
		if *check && !p.Verified {
			continue
		}
		body, err := probe(p, *url, *proxy)
		if err != nil {
			fmt.Printf("%-12s ERROR %v\n", p.ID, err)
			failed = true
			continue
		}
		if *raw {
			fmt.Println(string(body))
			continue
		}
		var r peet
		if err := json.Unmarshal(body, &r); err != nil {
			fmt.Printf("%-12s bad response: %.200s\n", p.ID, body)
			failed = true
			continue
		}
		fmt.Printf("%-12s ja4 %s  akamai %s  ja3 %s  peetprint %s\n", p.ID, r.TLS.JA4, r.HTTP2.AkamaiHash, r.TLS.JA3Hash, r.TLS.Peetprint)
		if p.Verified {
			for _, c := range []struct{ name, want, got string }{
				{"ja4", p.JA4, r.TLS.JA4},
				{"ja4_r", p.JA4R, r.TLS.JA4R},
				{"peetprint", p.Peetprint, r.TLS.Peetprint},
				{"akamai", p.Akamai, r.HTTP2.Akamai},
				{"user-agent", p.UserAgent, r.UserAgent},
			} {
				if c.want != c.got {
					failed = true
					fmt.Printf("             MISMATCH %s\n               want %s\n               got  %s\n", c.name, c.want, c.got)
				}
			}
		}
	}
	if failed {
		os.Exit(1)
	}
}

func probe(p *fp.Profile, url, proxy string) ([]byte, error) {
	opts := p.Options()
	opts = append(opts, tls_client.WithTimeoutSeconds(30))
	if proxy != "" {
		opts = append(opts, tls_client.WithProxyUrl(proxy))
	}
	client, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(), opts...)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	// The browser's own navigation header set, in its order.
	req.Header = http.Header{}
	var order []string
	nav := p.NavHeaders
	if len(nav) == 0 {
		nav = [][2]string{{"user-agent", ""}, {"accept", "*/*"}}
	}
	hasUA := false
	for _, h := range nav {
		v := h[1]
		if h[0] == "user-agent" {
			v, hasUA = p.UserAgent, true
		}
		req.Header[h[0]] = []string{v}
		order = append(order, h[0])
	}
	if !hasUA {
		req.Header["user-agent"] = []string{p.UserAgent}
		order = append([]string{"user-agent"}, order...)
	}
	req.Header[http.HeaderOrderKey] = order
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}
