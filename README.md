# netlogger

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
Firefox ──▶ netlogger :9393 ──(Firefox-158 TLS/H2)──▶ upstream :12345 (LocalRack) ──▶ internet
                │
                └── web UI :9494  (config + full request log)
```

## Run

```bash
cd ~/Desktop/netlogger
./netlogger
```

Flags: `-web 127.0.0.1:9494` (web UI address), `-data <dir>` (default `./data`),
`-ca-out <path>` (default `~/Desktop/netlogger-ca.pem`).

On start it prints the proxy port, upstream, web UI URL, data dir and the CA path, and it
(re)writes the CA certificate to the Desktop.

## One-time Firefox setup

**1. Trust the CA** (required for HTTPS interception):

- Firefox → Settings → Privacy & Security → Certificates → **View Certificates…**
- **Authorities** tab → **Import…** → choose `~/Desktop/netlogger-ca.pem`
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

- **Top bar** — set the listen port and the upstream URL (blank = connect directly, no
  upstream), toggle **MITM** (off = raw pass-through tunnel, HTTPS not decrypted) and
  **force UA** (rewrite the client User-Agent to the Firefox 158 string). These **apply
  immediately** on change (the listener rebinds if the port changed) — there is no config
  save button. **Save HAR ↓** downloads the current logs through the browser as
  `netlogger-<ts>.har` (HAR 1.2, full headers + bodies; compressed bodies decoded, binary
  base64-encoded). Download the **CA cert**.
- **Left** — live request list (method, status, url, size, ms); filter box; follow toggle;
  Clear.
- **Right** — Overview / Request / Response tabs with full headers and bodies. Bodies show
  size on wire, encoding, decoded size, and **raw ↓ / decoded ↓** download links for the
  complete body.

## Data

- `data/config.json` — persisted settings
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
- **WebSocket / `Upgrade`** requests are not intercepted (logged as `501`); everything else
  is.
- The client↔proxy leg is negotiated as HTTP/1.1 for clean parsing; this does not affect the
  HTTP/2 fingerprint presented upstream. Forwarded request headers are lowercased (as HTTP/2
  and real Firefox require) and the client's `Content-Length` is dropped so the transport
  frames the body — without this, strict servers reject with `400` / `PROTOCOL_ERROR`.
- **Save HAR** exports everything currently in the list. Hit **Clear** first for a focused
  capture of just the next thing you do.
- **Resilience:** the upstream client is a small pool with a 30 s per-request timeout and a
  15 s dial timeout. This is deliberate — tls-client performs the upstream dial + TLS
  handshake while holding an internal cache lock, so without these bounds a single stalled
  upstream could freeze *all* HTTPS. The trade-off is that a legitimately slow upstream
  request is cut at 30 s (fine for browsing; turn MITM off for large downloads).

## Dev

- `internal/fp/fp.go` — the exact Firefox-158 ClientHello + H2 settings.
- `go run ./cmd/fpprobe` (add `-proxy http://127.0.0.1:12345`) — prints the live JA3/JA4/
  Akamai from `tls.peet.ws` to re-verify the fingerprint.
