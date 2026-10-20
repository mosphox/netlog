// Small DOM, formatting and encoding helpers shared by every view.

export const $ = (s, root = document) => root.querySelector(s);

export function el(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  if (typeof attrs === 'string') e.className = attrs;
  else if (attrs) for (const [k, v] of Object.entries(attrs)) {
    if (v == null || v === false) continue;
    if (k === 'class') e.className = v;
    else if (k === 'text') e.textContent = v;
    else if (k === 'html') e.innerHTML = v;
    else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else if (k === 'style' && typeof v === 'object') Object.assign(e.style, v);
    else e.setAttribute(k, v === true ? '' : v);
  }
  for (const k of kids.flat()) if (k != null && k !== false) e.append(k instanceof Node ? k : String(k));
  return e;
}

const P = {
  proxy: '<path d="M3 6h18M3 12h18M3 18h12"/>',
  repeat: '<path d="M17 2l4 4-4 4"/><path d="M3 11V9a3 3 0 0 1 3-3h15"/><path d="M7 22l-4-4 4-4"/><path d="M21 13v2a3 3 0 0 1-3 3H3"/>',
  pause: '<rect x="6" y="4" width="4" height="16" rx="1"/><rect x="14" y="4" width="4" height="16" rx="1"/>',
  route: '<circle cx="6" cy="19" r="3"/><circle cx="18" cy="5" r="3"/><path d="M9 19h6.5a3.5 3.5 0 0 0 0-7h-7a3.5 3.5 0 0 1 0-7H15"/>',
  fp: '<path d="M12 11v4"/><path d="M8.5 7.5a5 5 0 0 1 8.5 3.5v2"/><path d="M6 11a6 6 0 0 1 .5-2.4"/><path d="M7 15.5c.3-1.4.5-3 .5-4.5a4.5 4.5 0 0 1 9 0"/><path d="M11 21c1.5-2.5 2-5.5 2-10"/><path d="M17 15c-.2 2-.7 4-1.5 5.5"/>',
  gear: '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>',
  search: '<circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/>',
  send: '<path d="M22 2L11 13"/><path d="M22 2l-7 20-4-9-9-4z"/>',
  play: '<path d="M6 4l14 8-14 8z"/>',
  copy: '<rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  x: '<path d="M18 6L6 18M6 6l12 12"/>',
  check: '<path d="M20 6L9 17l-5-5"/>',
  trash: '<path d="M3 6h18"/><path d="M8 6V4h8v2"/><path d="M19 6l-1 14H6L5 6"/>',
  edit: '<path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4z"/>',
  bolt: '<path d="M13 2L3 14h9l-1 8 10-12h-9z"/>',
  down: '<path d="M12 3v12"/><path d="M7 10l5 5 5-5"/><path d="M5 21h14"/>',
  sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>',
  moon: '<path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/>',
  chev: '<path d="M6 9l6 6 6-6"/>',
  left: '<path d="M15 18l-6-6 6-6"/>',
  right: '<path d="M9 18l6-6-6-6"/>',
  shield: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/>',
  globe: '<circle cx="12" cy="12" r="10"/><path d="M2 12h20"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>',
  drop: '<circle cx="12" cy="12" r="9"/><path d="M5.6 5.6l12.8 12.8"/>',
};
export function icon(name, cls) {
  const s = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  s.setAttribute('viewBox', '0 0 24 24'); s.setAttribute('fill', 'none'); s.setAttribute('stroke', 'currentColor');
  s.setAttribute('stroke-width', '2'); s.setAttribute('stroke-linecap', 'round'); s.setAttribute('stroke-linejoin', 'round');
  s.setAttribute('aria-hidden', 'true');
  if (cls) s.setAttribute('class', cls);
  s.innerHTML = P[name] || '';
  return s;
}

export const fmtSize = n => n == null ? '' : n < 1024 ? n + ' B' : n < 1048576 ? (n / 1024).toFixed(n < 10240 ? 1 : 0) + ' KB' : (n / 1048576).toFixed(1) + ' MB';
export const fmtMs = ms => ms == null ? '' : ms < 1000 ? ms + ' ms' : (ms / 1000).toFixed(ms < 10000 ? 2 : 1) + ' s';
export const fmtTime = iso => new Date(iso).toTimeString().slice(0, 8);
export function splitUrl(u) { try { const p = new URL(u); return { host: p.host, path: p.pathname + p.search }; } catch { return { host: '', path: u }; } }
export function statusClass(r) { if (r.err) return 'bad'; const s = r.status; if (s === 101) return 'ws'; if (!s) return ''; if (s < 300) return 'ok'; if (s < 400) return 'redir'; if (s < 500) return 'warn'; return 'bad'; }
export function statusLabel(r) { if (r.err) return 'ERR'; if (r.status === 101) return 'WS'; return r.status || '…'; }
export function shortType(ct) {
  if (!ct) return ''; ct = ct.toLowerCase();
  if (ct.includes('json')) return 'json'; if (ct.includes('html')) return 'html'; if (ct.includes('javascript') || ct.includes('ecmascript')) return 'js';
  if (ct.includes('css')) return 'css'; if (ct.startsWith('image/')) return ct.slice(6).replace('svg+xml', 'svg'); if (ct.includes('font')) return 'font';
  if (ct.includes('xml')) return 'xml'; if (ct.startsWith('text/')) return ct.slice(5); if (ct.startsWith('video/') || ct.startsWith('audio/')) return 'media';
  return ct.split('/').pop().slice(0, 8);
}
export const isFailed = r => !!r.err || r.status >= 500;
export const browserOf = id => id ? (id.startsWith('chrome') ? 'chrome' : id.startsWith('firefox') ? 'firefox' : 'none') : 'none';
export function browserBadge(profileId, title) {
  const b = browserOf(profileId);
  return el('span', { class: 'br ' + b, title: title || profileId || 'no fingerprint', text: b === 'firefox' ? 'FF' : b === 'chrome' ? '' : '–' });
}

// ---- bytes <-> base64 / text ----
export function b64ToBytes(b64) { if (!b64) return new Uint8Array(); const s = atob(b64); const a = new Uint8Array(s.length); for (let i = 0; i < s.length; i++) a[i] = s.charCodeAt(i); return a; }
export function bytesToB64(bytes) { let s = ''; for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000)); return btoa(s); }
export const textToB64 = t => bytesToB64(new TextEncoder().encode(t));
export function bytesToText(bytes) { try { return new TextDecoder('utf-8', { fatal: true }).decode(bytes); } catch { return null; } }

// ---- raw HTTP request text <-> structured ----
const BIN = n => `«binary body: ${n} bytes, sent unchanged»`;
export function requestToText(r) {
  const head = [`${r.method} ${r.url} HTTP/1.1`, ...(r.headers || []).map(h => `${h.name}: ${h.value}`)].join('\n');
  const bytes = typeof r.body === 'string' ? b64ToBytes(r.body) : (r.body || new Uint8Array());
  const text = bytesToText(bytes);
  return head + '\n\n' + (bytes.length && text === null ? BIN(bytes.length) : (text || ''));
}
// textToRequest parses the editor text. origBody (base64) is kept when the
// body is the binary placeholder. Throws Error with a readable message.
export function textToRequest(text, origBody) {
  const norm = text.replace(/\r\n/g, '\n');
  const sep = norm.indexOf('\n\n');
  const head = sep < 0 ? norm : norm.slice(0, sep);
  const body = sep < 0 ? '' : norm.slice(sep + 2);
  const lines = head.split('\n');
  const first = lines.shift().trim();
  const m = first.match(/^([A-Za-z]+)\s+(\S+)(?:\s+HTTP\/[\d.]+)?$/);
  if (!m) throw new Error('First line must be: METHOD URL HTTP/1.1');
  const headers = [];
  for (const [i, l] of lines.entries()) {
    if (!l.trim()) continue;
    const c = l.indexOf(':');
    if (c <= 0) throw new Error(`Line ${i + 2} is not a "Name: value" header`);
    headers.push({ name: l.slice(0, c).trim(), value: l.slice(c + 1).trim() });
  }
  let url = m[2];
  if (url.startsWith('/')) {
    const host = headers.find(h => h.name.toLowerCase() === 'host');
    if (!host) throw new Error('Relative URL needs a Host header, or write the full https:// URL');
    url = 'https://' + host.value + url;
  }
  const b = origBody && /^«binary body: \d+ bytes, sent unchanged»$/.test(body.trim()) ? origBody : (body ? textToB64(body) : '');
  return { method: m[1].toUpperCase(), url, headers, body: b };
}

// ---- json highlighting ----
export function highlightJSON(text) {
  const esc = s => s.replace(/&/g, '&amp;').replace(/</g, '&lt;');
  return esc(text).replace(/("(?:\\.|[^"\\])*")(\s*:)?|\b(true|false)\b|\bnull\b|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/g, (m, str, colon, bool) => {
    if (str) return colon ? `<span class="j-k">${str}</span>${colon}` : `<span class="j-s">${str}</span>`;
    if (bool) return `<span class="j-b">${m}</span>`;
    if (m === 'null') return `<span class="j-z">${m}</span>`;
    return `<span class="j-n">${m}</span>`;
  });
}

// ---- toasts, clipboard, misc ----
export function toast(msg, kind) {
  const t = el('div', 'toast' + (kind === 'err' ? ' err' : ''), el('span', 'bar'), el('span', null, msg));
  $('#toasts').append(t);
  setTimeout(() => { t.classList.add('out'); setTimeout(() => t.remove(), 260); }, kind === 'err' ? 4200 : 2400);
}
export function copy(text, msg) { navigator.clipboard.writeText(text).then(() => toast(msg || 'Copied'), () => toast('The browser blocked clipboard access', 'err')); }
export function debounce(fn, ms) { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; }
export async function busy(btn, fn) { btn.classList.add('loading'); btn.disabled = true; try { return await fn(); } finally { btn.classList.remove('loading'); btn.disabled = false; } }
export function store(key, val) { try { if (val === undefined) return JSON.parse(localStorage.getItem('netlog.' + key)); localStorage.setItem('netlog.' + key, JSON.stringify(val)); } catch { return null; } }

export function go(id) { location.hash = '#/' + id; }

// slideInk positions a tab bar's underline under the selected tab.
export function slideInk(tabs) {
  let ink = tabs.querySelector('.ink');
  if (!ink) { ink = el('span', 'ink'); tabs.append(ink); }
  const sel = tabs.querySelector('[aria-selected="true"]');
  if (!sel) { ink.style.width = '0'; return; }
  ink.style.width = sel.offsetWidth + 'px';
  ink.style.transform = `translateX(${sel.offsetLeft}px)`;
}
