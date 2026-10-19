// Package fp defines the exact TLS + HTTP/2 fingerprint that netlogger presents
// to upstream, reproducing Firefox 158 on macOS:
//
//	ja4        t13d1517h2_8daaf6152771_3cbfd9057e0d
//	ja3_hash   9d42e90b0225e779f03141ddcd699df2
//	akamai     6ea73faa8fc5aac76bded7bd238f6433  (1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s)
//
// The ClientHello (15 cipher suites, 17 extensions, X25519MLKEM768 key share) is
// built by hand rather than reusing tls-client's Firefox_148 preset, because 148
// still carries the DHE ciphers and FFDHE groups that Firefox 156+ dropped. The
// HTTP/2 settings are identical to 148 and are reused verbatim.
package fp

import (
	http2 "github.com/bogdanfinn/fhttp/http2"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
	tls "github.com/bogdanfinn/utls"
)

// UserAgent is the matching Firefox 158 UA string. netlogger forces this header
// on every upstream request so the HTTP layer agrees with the TLS layer.
const UserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:158.0) Gecko/20100101 Firefox/158.0"

// clientHelloSpec returns the Firefox 158 ClientHello. Cipher suites and
// extensions are emitted in the exact wire order recorded in the target's
// ja4_ro / ja4_o, so both the ordered and unordered JA4 variants match.
func clientHelloSpec() (tls.ClientHelloSpec, error) {
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
			&tls.SNIExtension{}, // 0  server_name
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
			&tls.SessionTicketExtension{}, // 35
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

// clientProfile bundles the Firefox 158 ClientHello with Firefox's HTTP/2
// settings (identical to tls-client's Firefox_148, which already matches the
// target Akamai fingerprint exactly).
func clientProfile() profiles.ClientProfile {
	helloID := tls.ClientHelloID{
		Client:               "Firefox",
		Version:              "158",
		RandomExtensionOrder: false,
		SpecFactory:          clientHelloSpec,
	}
	return profiles.NewClientProfile(
		helloID,
		map[http2.SettingID]uint32{ // SETTINGS values
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
		[]string{":method", ":path", ":authority", ":scheme"}, // pseudo-header order m,p,a,s
		12517377, // connection flow (WINDOW_UPDATE increment)
		nil,      // no standalone PRIORITY frames
		&http2.PriorityParam{StreamDep: 0, Exclusive: false, Weight: 41}, // HEADERS priority (wire 41 => weight 42)
		0,     // streamID (0 => library default; not part of the Akamai hash)
		true,  // allowHTTP: also serve plaintext http:// targets
		nil, nil, 0, nil, false, // HTTP/3 unused (upstream is TCP via the proxy)
	)
}

// Options returns the base tls-client options for the Firefox 158 fingerprint.
// Callers append WithProxyUrl (upstream) and per-request options as needed.
func Options() []tls_client.HttpClientOption {
	return []tls_client.HttpClientOption{
		tls_client.WithClientProfile(clientProfile()),
		tls_client.WithNotFollowRedirects(), // a proxy must relay 3xx, never chase them
		// tls-client runs the upstream dial + TLS handshake while holding an
		// internal cache lock, bounded only by this request timeout. Keep it
		// short so a stalled upstream can't freeze other HTTPS requests for long.
		tls_client.WithTimeoutSeconds(30),
		// Never let the transport decode content: netlogger relays bodies byte
		// for byte (with Content-Encoding intact) and decodes only for display.
		tls_client.WithTransportOptions(&tls_client.TransportOptions{DisableCompression: true}),
	}
}
