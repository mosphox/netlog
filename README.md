# netlog

A local intercepting proxy for **your own** browser traffic, in the spirit of Burp or
mitmproxy, with one difference: every request netlog makes upstream carries the **TLS and
HTTP/2 fingerprint of a real browser**. By default that is the fingerprint of the browser that
sent the request, so Chrome traffic still looks like Chrome and Firefox traffic like Firefox.

```
browser ──▶ netlog :9393 ──(Chrome 155 / Firefox 158 TLS + HTTP/2)──▶ [upstream proxy] ──▶ site
               │
               └── web UI :9494   proxy history · repeater · intercept · upstreams · fingerprints
```

- **Full capture.** Request line, every header in the order it was sent, query, cookies, and
  complete request and response bodies (compressed bodies are stored as sent and decoded for
  display). WebSockets are relayed and every message is recorded.
- **Real fingerprints, checked against the real browsers.** JA4, the raw JA4, peetprint and the
  Akamai HTTP/2 fingerprint all match captures of the actual browser (see
  [Fingerprints](#fingerprints)).
- **Burp-style tools.** Repeater (edit and resend, with a chosen fingerprint and upstream),
  Intercept (hold, edit, forward or drop), and a list of upstream proxies to switch between.

## Run

Requires Go 1.26+.

```bash
go build -o netlog . && ./netlog
```

Flags: `-web 127.0.0.1:9494` (web UI address), `-data <dir>` (default `./data`),
`-ca-out <path>` (default `~/Desktop/netlog-ca.pem`).

On first start netlog creates a CA in `data/`, exports the public certificate, and listens
for the browser on `127.0.0.1:9393`. Open <http://127.0.0.1:9494>.

## Set up a browser

netlog decrypts HTTPS with its own CA, so the browser you point at it has to trust that CA.
Trust it only in a browser (or profile) you use for this. The private key stays in
`data/ca-key.pem`.

**Firefox.** Settings → Privacy & Security → View Certificates → Authorities → Import, choose
`netlog-ca.pem`, tick "Trust this CA to identify websites". Then Network Settings → Manual proxy:
HTTP proxy `127.0.0.1`, port `9393`, and "Also use this proxy for HTTPS".

**Chrome.** Add the CA to the macOS keychain as trusted (Keychain Access → System → import,
set to Always Trust), then start a separate profile pointed at netlog:

```bash
open -na "Google Chrome" --args --user-data-dir=/tmp/netlog-chrome --proxy-server=127.0.0.1:9393
```

## The web UI

- **Proxy**: live history with a structured filter, status chips, the fingerprint each
  request went out with, and full detail: headers in order, cookies, bodies (pretty JSON),
  WebSocket messages. From any request: **Send to Repeater**, **Replay**, **Copy as curl**.
- **Repeater**: tabs of raw HTTP requests you edit and send. Each tab can pin its own
  fingerprint and upstream; every send is kept so you can step back through responses.
  `⌘/Ctrl + Enter` sends.
- **Intercept**: when on, requests to matching hosts wait before leaving. Edit one and forward
  it, drop it, or forward everything. The browser waits meanwhile (up to 10 minutes, then the
  request goes out unchanged).
- **Upstreams**: the proxies netlog can route through (HTTP, HTTPS, SOCKS5, credentials in the
  URL). Pick the active one, or test each: exit IP, location, network and latency.
- **Fingerprints**: Auto or a fixed profile, the fallback for unknown clients, the expected
  values of every profile, and a live probe that compares a profile with its capture.
- **Settings**: listen port, HTTPS decryption, CA download, browser setup, HAR export.

The top bar shows a 60-second traffic pulse and lets you switch the upstream and the
fingerprint from anywhere.

Filter syntax in Proxy: free text matches the URL, method, status and error. Terms:
`host:` `status:` (`404`, `5xx`, `>=400`) `method:` `type:` (`json`, `html`, `js`, `image`…)
`path:` `fp:` (`chrome`, `firefox_158`) and `is:err` `is:ws` `is:retried` `is:repeater`
`is:replay` `is:edited`. Prefix any term with `-` to exclude it. Keys: `/` filter, `j`/`k` move,
`r` send the selected request to Repeater, `Esc` clear.

## Fingerprints

| profile | status | JA4 | Akamai HTTP/2 |
|---|---|---|---|
| Chrome 155 (macOS) | verified | `t13d1517h2_8daaf6152771_cb7bf5808d99` | `52d84b11737d980aef856699f885ca86` |
| Firefox 158 (macOS) | verified | `t13d1517h2_8daaf6152771_3cbfd9057e0d` | `6ea73faa8fc5aac76bded7bd238f6433` |
| Chrome 152, 146 | tls-client preset | | |
| Firefox 148, 147 | tls-client preset | | |

"Verified" means the profile was compared with a capture of the real browser on
[tls.peet.ws](https://tls.peet.ws) and matches on JA4, the raw JA4 (every cipher, extension and
signature algorithm), the peetprint, the Akamai HTTP/2 fingerprint and the User-Agent. Chrome
shuffles its extension order on every connection, so its JA3 changes per connection, as it does
in the real browser. The Chrome profile also carries the details Chrome 155 added: ML-DSA
signature algorithms, the trust-anchor extension (`0xca34`), and exclusive weight-256 HEADERS
priority.

In **Auto** mode each request gets the profile of the browser that sent it, picked from its
User-Agent (same family, nearest version). Anything that is neither Chrome nor Firefox uses the
fallback profile. **Fixed** sends everything with one profile, and **Rewrite the User-Agent**
makes the headers agree with it.

Re-check the profiles at any time:

```bash
go run ./cmd/fpprobe -check                                # exits 1 on any mismatch
go run ./cmd/fpprobe -check -proxy http://127.0.0.1:12345  # through an upstream
go run ./cmd/fpprobe -profile chrome_155 -raw              # full reflection JSON
```

Adding a browser version: capture it on `https://tls.peet.ws/api/all`, add a profile in
`internal/fp` with the expected values, and run `fpprobe -check`.

## Data

- `data/config.json`: settings, including upstreams (file mode 0600, it may hold proxy credentials)
- `data/ca-cert.pem`, `data/ca-key.pem`: the CA. The key is private.
- `data/logs/YYYY-MM-DD.jsonl`: every transaction in full, one JSON object per line (bodies
  base64). The web UI reads from these.
- `data/netlog.log`: the process log, including any recovered panic.

## Notes and limits

- **Connections like a browser.** Each upstream host gets one connection over HTTP/2 or up to
  six over HTTP/1.1, per fingerprint and upstream. Idle upstream connections are not reused
  after 30 s, since proxies drop idle tunnels.
- **Retries.** A request that fails on a dead connection (EOF, reset, GOAWAY, a protocol
  switch) is sent again on a fresh one: up to 3 tries for GET-like methods, 2 for others.
  Certificate, DNS and timeout errors are not retried.
- **Timeout.** 90 s per upstream request, body included. Responses are buffered in full before
  they reach the browser; for very large downloads turn HTTPS decryption off.
- **WebSockets** open their own connection with the profile's ClientHello and ALPN `http/1.1`,
  as browsers do for a fresh WebSocket connection. Up to 5000 messages / 32 MB per connection
  are recorded; the connection itself is not limited.
- **Loopback targets** (`127.0.0.1`, `localhost`) are always dialed directly, never through
  the upstream.
- **Cleartext `http://`** has no TLS layer to fingerprint and goes through a plain client.
- **Upstream certificates** are verified against the system trust store.
- The browser↔netlog leg is HTTP/1.1. That does not change what netlog presents upstream.

## Development

- `internal/fp`: the profiles (`chrome.go`, `firefox.go`), detection, and the live probe.
- `third_party/tls-client`: a vendored [tls-client](https://github.com/bogdanfinn/tls-client)
  v1.16.0 (4-clause BSD, see `third_party/tls-client/LICENSE`) with two race fixes marked `netlog patch` in
  `roundtripper.go`. Upstream could panic ("dialTLS returned no error…") or write its
  transport map without the lock (a fatal concurrent map write) when a host switched between
  HTTP/1.1 and HTTP/2; both took the whole process down. Re-check them before upgrading.
- `web/`: the UI, plain HTML, CSS and JavaScript modules embedded into the binary. Fonts are
  Geist and Geist Mono (SIL OFL, `web/fonts/OFL.txt`).

## License

MIT, see [LICENSE](LICENSE). This product includes software developed by Bogdan Finn
(tls-client, under its own license in `third_party/tls-client/LICENSE`).
