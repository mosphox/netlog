// Package fp holds the browser fingerprints netlog can present upstream: the
// TLS ClientHello plus HTTP/2 settings, priorities and pseudo-header order of
// a real browser, and the matching User-Agent.
//
// Profiles marked Verified were compared field by field with a capture of the
// real browser on tls.peet.ws (see cmd/fpprobe -check). The others wrap
// tls-client's presets and are offered as-is.
package fp

import (
	"net"
	"regexp"
	"sort"
	"strconv"

	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
	tls "github.com/bogdanfinn/utls"
)

type Browser string

const (
	Firefox Browser = "firefox"
	Chrome  Browser = "chrome"
)

// Profile is one browser fingerprint.
type Profile struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	Browser   Browser `json:"browser"`
	Version   int     `json:"version"`
	Verified  bool    `json:"verified"`
	UserAgent string  `json:"user_agent"`
	JA4       string  `json:"ja4,omitempty"`    // expected, for verified profiles
	Akamai    string  `json:"akamai,omitempty"` // expected HTTP/2 fingerprint text
	JA4R      string  `json:"ja4_r,omitempty"`  // expected raw JA4: full sorted cipher/extension/sigalg lists
	Peetprint string  `json:"peetprint,omitempty"`

	// RandomExtOrder shuffles the ClientHello extensions per connection, as
	// Chrome does. AddTE adds "te: trailers" to every request, as Firefox does
	// on HTTP/2.
	RandomExtOrder bool `json:"random_ext_order"`
	AddTE          bool `json:"add_te"`

	// NavHeaders is the browser's header set for a top-level navigation, in
	// its order, used by the probe. An empty user-agent value marks where the
	// UA goes.
	NavHeaders [][2]string `json:"-"`

	client profiles.ClientProfile
}

func preset(id, name string, b Browser, version int, ua string, addTE, shuffle bool) *Profile {
	return &Profile{ID: id, Name: name, Browser: b, Version: version, UserAgent: ua, AddTE: addTE, RandomExtOrder: shuffle, client: profiles.MappedTLSClients[id]}
}

var all = []*Profile{
	chrome155,
	firefox158,
	preset("chrome_152", "Chrome 152", Chrome, 152, chromeUA(152), false, true),
	preset("chrome_146", "Chrome 146", Chrome, 146, chromeUA(146), false, true),
	preset("firefox_148", "Firefox 148", Firefox, 148, firefoxUA(148), true, false),
	preset("firefox_147", "Firefox 147", Firefox, 147, firefoxUA(147), true, false),
}

func chromeUA(v int) string {
	return "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + strconv.Itoa(v) + ".0.0.0 Safari/537.36"
}

func firefoxUA(v int) string {
	s := strconv.Itoa(v)
	return "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:" + s + ".0) Gecko/20100101 Firefox/" + s + ".0"
}

// Default is the profile used when nothing else decides.
var Default = firefox158

// All returns every profile, verified first, newest first.
func All() []*Profile {
	out := append([]*Profile(nil), all...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Verified != out[j].Verified {
			return out[i].Verified
		}
		return out[i].Version > out[j].Version
	})
	return out
}

// Lookup returns a profile by ID.
func Lookup(id string) (*Profile, bool) {
	for _, p := range all {
		if p.ID == id {
			return p, true
		}
	}
	return nil, false
}

var (
	reFirefox = regexp.MustCompile(`Firefox/(\d+)`)
	reChrome  = regexp.MustCompile(`(?:Chrome|Chromium|CriOS)/(\d+)`)
)

// Detect picks the profile matching a client's User-Agent: same browser
// family, the closest version (preferring verified profiles on ties). It
// reports false when the UA is not Firefox or Chromium-based.
func Detect(ua string) (*Profile, bool) {
	var fam Browser
	var ver int
	if m := reFirefox.FindStringSubmatch(ua); m != nil {
		fam, ver = Firefox, atoi(m[1])
	} else if m := reChrome.FindStringSubmatch(ua); m != nil {
		fam, ver = Chrome, atoi(m[1])
	} else {
		return nil, false
	}
	var best *Profile
	bestDist := 1 << 30
	for _, p := range All() {
		if p.Browser != fam {
			continue
		}
		d := p.Version - ver
		if d < 0 {
			d = -d
		}
		if d < bestDist {
			best, bestDist = p, d
		}
	}
	return best, best != nil
}

func atoi(s string) int { n, _ := strconv.Atoi(s); return n }

// Options returns the base tls-client options for the profile. Callers append
// WithProxyUrl and their own transport options.
func (p *Profile) Options() []tls_client.HttpClientOption {
	opts := []tls_client.HttpClientOption{
		tls_client.WithClientProfile(p.client),
		tls_client.WithNotFollowRedirects(), // a proxy must relay 3xx, never chase them
	}
	if p.RandomExtOrder {
		opts = append(opts, tls_client.WithRandomTLSExtensionOrder())
	}
	return opts
}

// WebSocketClient wraps conn in this profile's TLS client for a websocket
// connection. Browsers open fresh websocket connections offering only
// http/1.1 in ALPN, so this is the profile's ClientHello with that change (and
// without ALPS, which only accompanies h2).
func (p *Profile) WebSocketClient(conn net.Conn, serverName string) (*tls.UConn, error) {
	spec, err := p.client.GetClientHelloSpec()
	if err != nil {
		return nil, err
	}
	exts := spec.Extensions[:0]
	for _, ext := range spec.Extensions {
		switch ext.(type) {
		case *tls.ALPNExtension:
			ext = &tls.ALPNExtension{AlpnProtocols: []string{"http/1.1"}}
		case *tls.ApplicationSettingsExtension, *tls.ApplicationSettingsExtensionNew:
			continue
		}
		exts = append(exts, ext)
	}
	spec.Extensions = exts
	if p.RandomExtOrder {
		spec.Extensions = tls.ShuffleChromeTLSExtensions(spec.Extensions)
	}
	uc := tls.UClient(conn, &tls.Config{ServerName: serverName, OmitEmptyPsk: true}, tls.HelloCustom, false, true, true)
	if err := uc.ApplyPreset(&spec); err != nil {
		return nil, err
	}
	return uc, nil
}
