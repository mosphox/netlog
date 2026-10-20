# netlog

A local logging/debugging proxy for **your own** traffic — like mitmproxy, but with two
specific traits:

1. It logs **every request and response in full** — request line, all headers (in the exact
   order sent), query params, and the complete request/response bodies (no truncation on
   disk). Compressed bodies are relayed byte-for-byte and decompressed only for display.
2. Every request it makes **to the upstream** reproduces the **Firefox 158 (macOS)**
   network fingerprint exactly:

   | | value |
   |---|---|
   | JA4 | `t13d1517h2_8daaf6152771_3cbfd9057e0d` |
   | JA3 hash | `9d42e90b0225e779f03141ddcd699df2` |
   | Akamai H2 | `1:65536;2:0;4:131072;5:16384\|12517377\|0\|m,p,a,s` → `6ea73faa8fc5aac76bded7bd238f6433` |

   This is verified against `tls.peet.ws` / `tls.browserleaks.com` — JA4, JA4_r (raw ordered),
   JA3 hash and the Akamai hash all match the target exactly, including the post-quantum
   `X25519MLKEM768` key share.

```
Firefox ──▶ netlog :9393 ──(Firefox-158 TLS/H2)──▶ upstream :12345 (LocalRack) ──▶ internet
                │
                └── web UI :9494  (config + full request log)
```

## Run

```bash
cd ~/projects/local/netlog
go build -o netlog . && ./netlog
```

Flags: `-web 127.0.0.1:9494` (web UI address), `-data <dir>` (default `./data`),
`-ca-out <path>` (default `~/Desktop/netlog-ca.pem`).

On start it prints the proxy port, upstream, web UI URL, data dir and the CA path, and it
(re)writes the CA certificate to the Desktop.

## One-time Firefox setup

**1. Trust the CA** (required for HTTPS interception):

- Firefox → Settings → Privacy & Security → Certificates → **View Certificates…**
- **Authorities** tab → **Import…** → choose `~/Desktop/netlog-ca.pem`
- Tick **“Trust this CA to identify websites.”** → OK

**2. Point Firefox at the proxy:**

- Settings → Network Settings → **Manual proxy configuration**
- **HTTP Proxy** `127.0.0.1` Port `9393`, and tick **“Also use this proxy for HTTPS”**
  (older Firefox: set the same under *SSL/HTTPS Proxy*)
- Clear “No proxy for”, and (recommended) set `network.proxy.allow_hijacking_localhost` if
  you also want to capture localhost.

Then open <http://127.0.0.1:9494> and browse — requests appear live. Visiting
`https://tls.browserleaks.com/` through it should report the JA4 above.

> The CA cert on the Desktop is the **public** certificate — safe to import. The CA
> **private key** stays in `data/ca-key.pem` and never leaves the machine. Anyone who trusts
> this CA can have their HTTPS intercepted, so keep the key local and remove the CA from
> Firefox when you’re done.

## Web UI (`:9494`)

- **Top bar**: proxy state (listening port and upstream), **Export HAR**, and **Settings**:
  listen port, upstream URL (blank = direct), decrypt HTTPS (MITM), force the Firefox UA,
  the CA download and the fingerprint values. Changes apply immediately.
- **Filter**: free text matches URL, method, status and error. Structured terms:
  `host:` `status:` (`404`, `5xx`, `>=400`) `method:` `type:` (`json`, `html`, `js`, `image`…)
  `path:` and `is:err` `is:ws` `is:retried` `is:replay`. Prefix any term with `-` to exclude.
  The status chips (2xx … Failed, WebSocket) show counts for the current filter and toggle.
- **List**: virtualized, so tens of thousands of rows stay smooth. A duration bar (log
  scale) flags slow requests in amber and failures in red. **Live** keeps the newest row in
  view; scrolling down pauses it. **Clear list** empties the view; logs on disk stay.
- **Detail**: Overview (timing, upstream, attempts, query parameters), Request (headers in
  the order sent, cookies, body), Response (headers, Set-Cookie, body with pretty JSON),
  and Messages for websockets (both directions, live while open). **Replay** re-sends the
  request through netlog; **Copy as curl** and **Copy URL**.
- Keyboard: `/` filter, `j` / `k` move, `Esc` clears the filter or closes the detail.

## Data

- `data/config.json` — persisted settings
- `data/netlog.log` — process log: errors and any recovered panic with its stack
- `data/ca-cert.pem`, `data/ca-key.pem` — the CA (key is private)
- `data/logs/YYYY-MM-DD.jsonl` — every transaction, in full, one JSON object per line
  (bodies base64-encoded). This is the untruncated source of truth; the web UI reads from
  it on demand.

## Notes / limits

- **Upstream** is treated as an HTTP `CONNECT` proxy (e.g. LocalRack on `:12345`);
  `socks5://` and credentials in the URL are also accepted. The Firefox fingerprint is
  applied to the TLS handshake with the **destination**, tunneled through that upstream.
- **Cleartext `http://`** has no TLS layer to fingerprint; it is forwarded through a plain
  proxied client (still logged in full).
- **WebSockets** are relayed and logged: netlog opens its own connection to the origin
  with the Firefox ClientHello (ALPN `http/1.1` only, as Firefox does for a fresh websocket
  connection), replays the browser's handshake in order, and records every message.
  permessage-deflate is decoded for display. Up to 5000 messages / 32 MB per connection are
  kept; the connection itself is never limited.
- **Loopback targets** (`127.0.0.1`, `localhost`) are always dialed directly, never through
  the upstream. Some antibot scripts probe local ports over websockets; those fail exactly as
  they would without the proxy.
- The client↔proxy leg is negotiated as HTTP/1.1 for clean parsing; this does not affect the
  HTTP/2 fingerprint presented upstream. Forwarded request headers are lowercased (as HTTP/2
  and real Firefox require) and the client's `Content-Length` is dropped so the transport
  frames the body — without this, strict servers reject with `400` / `PROTOCOL_ERROR`.
- **Save HAR** exports everything currently in the list. Hit **Clear** first for a focused
  capture of just the next thing you do.
- **Connections, like Firefox:** each upstream host gets its own clients: one connection for
  an HTTP/2 host, up to 6 for an HTTP/1.1 host. A slow host can't stall the others.
  Upstream connections idle for 30 s are not reused (proxies drop idle tunnels).
- **Retries:** a request that fails on a dead connection (EOF, reset, GOAWAY, a protocol
  switch) is sent again on a fresh one: up to 3 tries for GET-like methods, 2 for POST.
  Retried rows carry a "retried" badge. Certificate, DNS and timeout errors are not retried.
- **Timeout:** 90 s per upstream request, body included. Responses are buffered in full
  before they reach the browser, so very large downloads are better done with MITM off.
- **Upstream certificates** are verified against the macOS trust store, like Firefox's own
  roots. Sites on the Russian national CA (e.g. some `sberbank.ru`, `rambler.ru` endpoints)
  fail with `x509: certificate signed by unknown authority`.

## Dev

- `third_party/tls-client` is a vendored tls-client v1.16.0 (`replace` in `go.mod`) with two
  race fixes marked `netlog patch` in `roundtripper.go`. Upstream could panic
  ("dialTLS returned no error…") or write its transport map without the lock (a fatal
  concurrent map write) when a host switched between HTTP/1.1 and HTTP/2. Both crashed the
  whole process. Re-check them before upgrading tls-client.

- `internal/fp/fp.go` — the exact Firefox-158 ClientHello + H2 settings.
- `go run ./cmd/fpprobe` (add `-proxy http://127.0.0.1:12345`) — prints the live JA3/JA4/
  Akamai from `tls.peet.ws` to re-verify the fingerprint.
