package fp

import (
	http2 "github.com/bogdanfinn/fhttp/http2"
	"github.com/bogdanfinn/tls-client/profiles"
	tls "github.com/bogdanfinn/utls"
)

// Firefox 158 on macOS, captured from the real browser on 2026-10-20:
//
//	ja4        t13d1517h2_8daaf6152771_3cbfd9057e0d
//	ja3_hash   9d42e90b0225e779f03141ddcd699df2 (Firefox does not shuffle extensions)
//	akamai     6ea73faa8fc5aac76bded7bd238f6433  (1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s)
//
// The ClientHello (15 cipher suites, 17 extensions, X25519MLKEM768 key share) is
// built by hand rather than reusing tls-client's Firefox_148 preset, because 148
// still carries the DHE ciphers and FFDHE groups that Firefox 156+ dropped.
var firefox158 = &Profile{
	ID:        "firefox_158",
	Name:      "Firefox 158",
	Browser:   Firefox,
	Version:   158,
	Verified:  true,
	UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:158.0) Gecko/20100101 Firefox/158.0",
	JA4:       "t13d1517h2_8daaf6152771_3cbfd9057e0d",
	Akamai:    "1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s",
	JA4R:      "t13d1517h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,001c,0022,0023,002b,002d,0033,fe0d,ff01_0403,0503,0603,0804,0805,0806,0401,0501,0601,0203,0201",
	Peetprint: "a4bbbc7e3adf3db97d276fd0adb1efc4",
	AddTE:     true,
	client: profiles.NewClientProfile(
		tls.ClientHelloID{Client: "Firefox", Version: "158", SpecFactory: firefox158Hello},
		map[http2.SettingID]uint32{
			http2.SettingHeaderTableSize:   65536,
			http2.SettingEnablePush:        0,
			http2.SettingInitialWindowSize: 131072,
			http2.SettingMaxFrameSize:      16384,
		},
		[]http2.SettingID{ // SETTINGS order: 1,2,4,5
			http2.SettingHeaderTableSize,
			http2.SettingEnablePush,
			http2.SettingInitialWindowSize,
			http2.SettingMaxFrameSize,
		},
		[]string{":method", ":path", ":authority", ":scheme"}, // m,p,a,s
		12517377, // connection flow (WINDOW_UPDATE increment)
		nil,      // no standalone PRIORITY frames
		&http2.PriorityParam{StreamDep: 0, Exclusive: false, Weight: 41}, // HEADERS priority (wire 41 => weight 42)
		0,                       // streamID: allowHTTP below makes fhttp start at 3, as Firefox does
		true,                    // allowHTTP
		nil, nil, 0, nil, false, // HTTP/3 unused (upstream is TCP via the proxy)
	),
	NavHeaders: [][2]string{
		{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
		{"accept-language", "en-GB,en;q=0.9"},
		{"accept-encoding", "gzip, deflate, br, zstd"},
		{"upgrade-insecure-requests", "1"},
		{"sec-fetch-dest", "document"},
		{"sec-fetch-mode", "navigate"},
		{"sec-fetch-site", "none"},
		{"sec-fetch-user", "?1"},
		{"priority", "u=0, i"},
		{"te", "trailers"},
	},
}

// firefox158Hello returns the Firefox 158 ClientHello. Cipher suites and
// extensions are emitted in the exact wire order recorded in the target's
// ja4_ro / ja4_o, so both the ordered and unordered JA4 variants match.
func firefox158Hello() (tls.ClientHelloSpec, error) {
	return tls.ClientHelloSpec{
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,                        // 1301
			tls.TLS_CHACHA20_POLY1305_SHA256,                  // 1303
			tls.TLS_AES_256_GCM_SHA384,                        // 1302
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,       // c02b
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,         // c02f
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, // cca9
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,   // cca8
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,       // c02c
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,         // c030
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,            // c013
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,            // c014
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,               // 009c
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,               // 009d
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,                  // 002f
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,                  // 0035
		},
		CompressionMethods: []byte{tls.CompressionNone},
		Extensions: []tls.TLSExtension{
			&tls.SNIExtension{},                  // 0  server_name
			&tls.ExtendedMasterSecretExtension{}, // 23 extended_master_secret
			&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient}, // 65281
			&tls.SupportedCurvesExtension{Curves: []tls.CurveID{ // 10 supported_groups
				tls.X25519MLKEM768, // 4588
				tls.X25519,         // 29
				tls.CurveP256,      // 23
				tls.CurveP384,      // 24
				tls.CurveP521,      // 25
			}},
			&tls.SupportedPointsExtension{SupportedPoints: []byte{tls.PointFormatUncompressed}}, // 11
			&tls.SessionTicketExtension{},                                 // 35
			&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}}, // 16
			&tls.StatusRequestExtension{},                                 // 5  status_request (ocsp)
			&tls.DelegatedCredentialsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{ // 34
				tls.ECDSAWithP256AndSHA256, // 1027
				tls.ECDSAWithP384AndSHA384, // 1283
				tls.ECDSAWithP521AndSHA512, // 1539
				tls.ECDSAWithSHA1,          // 515
			}},
			&tls.SCTExtension{}, // 18 signed_certificate_timestamp
			&tls.KeyShareExtension{KeyShares: []tls.KeyShare{ // 51 key_share
				{Group: tls.X25519MLKEM768},
				{Group: tls.X25519},
				{Group: tls.CurveP256},
			}},
			&tls.SupportedVersionsExtension{Versions: []uint16{ // 43
				tls.VersionTLS13,
				tls.VersionTLS12,
			}},
			&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{ // 13
				tls.ECDSAWithP256AndSHA256, // 1027
				tls.ECDSAWithP384AndSHA384, // 1283
				tls.ECDSAWithP521AndSHA512, // 1539
				tls.PSSWithSHA256,          // 2052
				tls.PSSWithSHA384,          // 2053
				tls.PSSWithSHA512,          // 2054
				tls.PKCS1WithSHA256,        // 1025
				tls.PKCS1WithSHA384,        // 1281
				tls.PKCS1WithSHA512,        // 1537
				tls.ECDSAWithSHA1,          // 515
				tls.PKCS1WithSHA1,          // 513
			}},
			&tls.PSKKeyExchangeModesExtension{Modes: []uint8{1}}, // 45 psk_dhe_ke
			&tls.FakeRecordSizeLimitExtension{Limit: 0x4001},     // 28 record_size_limit = 16385
			&tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{ // 27
				tls.CertCompressionZlib,   // 1
				tls.CertCompressionBrotli, // 2
				tls.CertCompressionZstd,   // 3
			}},
			tls.BoringGREASEECH(), // 65037 encrypted_client_hello (GREASE)
		},
	}, nil
}
