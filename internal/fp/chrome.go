package fp

import (
	"crypto/rand"
	"encoding/hex"

	http2 "github.com/bogdanfinn/fhttp/http2"
	"github.com/bogdanfinn/tls-client/profiles"
	tls "github.com/bogdanfinn/utls"
)

// Chrome 155 on macOS, captured from the real browser on 2026-10-20:
//
//	ja4        t13d1517h2_8daaf6152771_cb7bf5808d99
//	ja3_hash   varies per connection: Chrome shuffles its extension order
//	akamai     52d84b11737d980aef856699f885ca86  (1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p)
//
// Close to tls-client's Chrome_152 preset; differences found against the
// capture: the trust-anchor list (0xca34) is sent in a fixed order, extensions
// are shuffled per connection, and HEADERS carry an exclusive weight-256
// priority.
var chrome155 = &Profile{
	ID:             "chrome_155",
	Name:           "Chrome 155",
	Browser:        Chrome,
	Version:        155,
	Verified:       true,
	UserAgent:      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36",
	JA4:            "t13d1517h2_8daaf6152771_cb7bf5808d99",
	Akamai:         "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
	JA4R:           "t13d1517h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,44cd,ca34,fe0d,ff01_0904,0905,0906,0403,0804,0401,0503,0805,0501,0806,0601",
	Peetprint:      "fc97c1cdfb1409c9a9326c1b726d1dee",
	RandomExtOrder: true,
	client: profiles.NewClientProfile(
		tls.ClientHelloID{Client: "Chrome", Version: "155", SpecFactory: chrome155Hello},
		map[http2.SettingID]uint32{
			http2.SettingHeaderTableSize:   65536,
			http2.SettingEnablePush:        0,
			http2.SettingInitialWindowSize: 6291456,
			http2.SettingMaxHeaderListSize: 262144,
		},
		[]http2.SettingID{
			http2.SettingHeaderTableSize,
			http2.SettingEnablePush,
			http2.SettingInitialWindowSize,
			http2.SettingMaxHeaderListSize,
		},
		[]string{":method", ":authority", ":scheme", ":path"}, // m,a,s,p
		15663105,
		nil,
		&http2.PriorityParam{StreamDep: 0, Exclusive: true, Weight: 255}, // wire 255 => weight 256
		0,     // streams start at 1
		false, // allowHTTP
		nil, nil, 0, nil, false,
	),
	NavHeaders: [][2]string{
		{"sec-ch-ua", `"Google Chrome";v="155", "Chromium";v="155", "Not(A:Brand";v="24"`},
		{"sec-ch-ua-mobile", "?0"},
		{"sec-ch-ua-platform", `"macOS"`},
		{"upgrade-insecure-requests", "1"},
		{"user-agent", ""}, // placeholder: the probe fills in the profile UA here
		{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/jxl,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
		{"sec-fetch-site", "none"},
		{"sec-fetch-mode", "navigate"},
		{"sec-fetch-user", "?1"},
		{"sec-fetch-dest", "document"},
		{"accept-encoding", "gzip, deflate, br, zstd"},
		{"accept-language", "en-US,en;q=0.9"},
		{"priority", "u=0, i"},
	},
}

// chrome155TrustAnchors is the 0xca34 (trust anchor IDs) payload exactly as
// Chrome 155 sent it, identical on every connection.
var chrome155TrustAnchors = mustHex("00b80582df1302010582df1302060582df13020d0582df13020e0582df13020f0582df1302120582df1302130582df13021408839a648c9b2d010708839a648c9b2d010808839a648c9b2d010908839a648c9b2d010a08839a648c9b2d010b08839a648c9b2d010c08839a648c9b2d010d08839a648c9b2d011208839a648c9b2d011304d679090104d679090404d679090504d679090604d679090704d679090804d679090a04d679090b04d679090c04d679090d04d679090f")

func chrome155Hello() (tls.ClientHelloSpec, error) {
	return tls.ClientHelloSpec{
		CipherSuites: []uint16{
			tls.GREASE_PLACEHOLDER,
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		CompressionMethods: []byte{tls.CompressionNone},
		Extensions: []tls.TLSExtension{
			&tls.UtlsGREASEExtension{},
			&tls.SupportedVersionsExtension{Versions: []uint16{tls.GREASE_PLACEHOLDER, tls.VersionTLS13, tls.VersionTLS12}},
			&tls.StatusRequestExtension{},
			&tls.ApplicationSettingsExtensionNew{SupportedProtocols: []string{"h2"}},
			&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
				{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}},
				{Group: tls.X25519MLKEM768},
				{Group: tls.X25519},
			}},
			&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
			&tls.GenericExtension{Id: 0xca34, Data: chrome155TrustAnchors},
			&tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{tls.CertCompressionBrotli}},
			&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
				greaseSignatureScheme(),     // Chrome leads with a fresh GREASE value per connection
				tls.SignatureScheme(0x0904), // ML-DSA-44
				tls.SignatureScheme(0x0905), // ML-DSA-65
				tls.SignatureScheme(0x0906), // ML-DSA-87
				tls.ECDSAWithP256AndSHA256,
				tls.PSSWithSHA256,
				tls.PKCS1WithSHA256,
				tls.ECDSAWithP384AndSHA384,
				tls.PSSWithSHA384,
				tls.PKCS1WithSHA384,
				tls.PSSWithSHA512,
				tls.PKCS1WithSHA512,
			}},
			&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
			tls.BoringGREASEECH(),
			&tls.SupportedPointsExtension{SupportedPoints: []byte{tls.PointFormatUncompressed}},
			&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
				tls.GREASE_PLACEHOLDER,
				tls.X25519MLKEM768,
				tls.X25519,
				tls.CurveP256,
				tls.CurveP384,
			}},
			&tls.SessionTicketExtension{},
			&tls.PSKKeyExchangeModesExtension{Modes: []uint8{tls.PskModeDHE}},
			&tls.ExtendedMasterSecretExtension{},
			&tls.SCTExtension{},
			&tls.SNIExtension{},
			&tls.UtlsGREASEExtension{},
		},
	}, nil
}

// greaseSignatureScheme returns a random RFC 8701 GREASE value (0x?a?a).
func greaseSignatureScheme() tls.SignatureScheme {
	var b [1]byte
	rand.Read(b[:])
	n := uint16(b[0]&0x0f)<<4 | 0x0a
	return tls.SignatureScheme(n<<8 | n)
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
