package fp

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	http "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
)

// probeServices are TLS/HTTP2 fingerprint reflection services, tried in order.
// tls.peet.ws also reports the peetprint; browserleaks does not.
var probeServices = []string{"https://tls.peet.ws/api/all", "https://tls.browserleaks.com/json"}

// ProbeResult is what the reflection service saw, and how it compares with a
// verified profile's capture.
type ProbeResult struct {
	JA4        string  `json:"ja4"`
	JA4R       string  `json:"ja4_r"`
	JA3Hash    string  `json:"ja3_hash"`
	Peetprint  string  `json:"peetprint"`
	Akamai     string  `json:"akamai"`
	AkamaiHash string  `json:"akamai_hash"`
	UserAgent  string  `json:"user_agent"`
	IP         string  `json:"ip"`
	Checks     []Check `json:"checks"` // empty for unverified profiles
	Match      bool    `json:"match"`
	Service    string  `json:"service"`
	Raw        []byte  `json:"-"`
}

type Check struct {
	Name string `json:"name"`
	Want string `json:"want"`
	Got  string `json:"got"`
	OK   bool   `json:"ok"`
}

// Probe sends the profile's navigation request to a reflection service,
// optionally through an upstream proxy, and compares the result. It falls
// back to the next service when one is unreachable.
func Probe(p *Profile, proxyURL string) (*ProbeResult, error) {
	var errs []error
	for _, svc := range probeServices {
		r, err := probeOne(p, proxyURL, svc)
		if err == nil {
			return r, nil
		}
		errs = append(errs, err)
	}
	return nil, errors.Join(errs...)
}

func probeOne(p *Profile, proxyURL, svc string) (*ProbeResult, error) {
	opts := append(p.Options(), tls_client.WithTimeoutSeconds(15))
	if proxyURL != "" {
		opts = append(opts, tls_client.WithProxyUrl(proxyURL))
	}
	client, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(), opts...)
	if err != nil {
		return nil, err
	}
	defer client.CloseIdleConnections()
	req, err := http.NewRequest(http.MethodGet, svc, nil)
	if err != nil {
		return nil, err
	}
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
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var r struct {
		IP  string `json:"ip"`
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
		// browserleaks: flat
		JA3Hash    string `json:"ja3_hash"`
		JA4        string `json:"ja4"`
		JA4R       string `json:"ja4_r"`
		AkamaiHash string `json:"akamai_hash"`
		AkamaiText string `json:"akamai_text"`
	}
	if err := json.Unmarshal(body, &r); err != nil || resp.StatusCode != 200 {
		return nil, fmt.Errorf("%s replied %d: %.120s", svc, resp.StatusCode, body)
	}
	out := &ProbeResult{JA4: r.TLS.JA4 + r.JA4, JA4R: r.TLS.JA4R + r.JA4R, JA3Hash: r.TLS.JA3Hash + r.JA3Hash, Peetprint: r.TLS.Peetprint,
		Akamai: r.HTTP2.Akamai + r.AkamaiText, AkamaiHash: r.HTTP2.AkamaiHash + r.AkamaiHash, UserAgent: r.UserAgent, IP: r.IP,
		Raw: body, Match: true, Service: svc}
	if p.Verified {
		for _, c := range []Check{
			{Name: "JA4", Want: p.JA4, Got: r.TLS.JA4},
			{Name: "JA4_r", Want: p.JA4R, Got: r.TLS.JA4R},
			{Name: "Peetprint", Want: p.Peetprint, Got: r.TLS.Peetprint},
			{Name: "Akamai HTTP/2", Want: p.Akamai, Got: r.HTTP2.Akamai},
			{Name: "User-Agent", Want: p.UserAgent, Got: r.UserAgent},
		} {
			if c.Name == "Peetprint" && c.Got == "" {
				continue // this service does not report it
			}
			c.OK = c.Want == c.Got
			out.Match = out.Match && c.OK
			out.Checks = append(out.Checks, c)
		}
	}
	return out, nil
}
