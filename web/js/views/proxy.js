// Proxy: the live request history, filter, and full detail of one request.
import { $, el, icon, fmtSize, fmtMs, fmtTime, splitUrl, statusClass, statusLabel, shortType, isFailed, browserBadge,
  highlightJSON, toast, copy, debounce, slideInk, go } from '../util.js';
import { api, profileName } from '../api.js';
import { history, onHistory, loadOlder, clearHistory } from '../history.js';
import { openInRepeater } from './repeater.js';

const ROW = 30;
const CHIPS = [
  ['all', 'All', () => true], ['2xx', '2xx', r => !r.err && r.status >= 200 && r.status < 300], ['3xx', '3xx', r => !r.err && r.status >= 300 && r.status < 400],
  ['4xx', '4xx', r => !r.err && r.status >= 400 && r.status < 500, 'c4'], ['5xx', '5xx', r => !r.err && r.status >= 500, 'c5'],
  ['failed', 'Failed', r => !!r.err, 'cf'], ['ws', 'WebSocket', r => !!r.ws], ['held', 'Intercepted', r => !!r.intercepted],
];

// UI state that survives switching views.
const ui = { filter: '', chip: 'all', live: true, selId: null, tab: 'overview', pretty: true };

function parseFilter(q) {
  return q.trim().split(/\s+/).filter(Boolean).map(tok => {
    let neg = false; if (tok.startsWith('-') && tok.length > 1) { neg = true; tok = tok.slice(1); }
    const i = tok.indexOf(':');
    return i > 0 ? { neg, key: tok.slice(0, i).toLowerCase(), val: tok.slice(i + 1).toLowerCase() } : { neg, key: '', val: tok.toLowerCase() };
  });
}
function statusMatch(s, v) {
  if (/^[1-5]xx$/.test(v)) return Math.floor(s / 100) === +v[0];
  const m = v.match(/^([<>]=?)(\d+)$/);
  if (m) { const n = +m[2]; return { '>': s > n, '>=': s >= n, '<': s < n, '<=': s <= n }[m[1]]; }
  return String(s) === v;
}
function termMatch(r, t) {
  const v = t.val;
  switch (t.key) {
    case 'host': case 'domain': return (r.host || '').toLowerCase().includes(v);
    case 'status': case 'code': return statusMatch(r.status || 0, v);
    case 'method': return (r.method || '').toLowerCase() === v;
    case 'type': case 'ct': return shortType(r.ct) === v || (r.ct || '').toLowerCase().includes(v);
    case 'path': case 'url': return (r.url || '').toLowerCase().includes(v);
    case 'fp': case 'profile': return (r.profile || '').toLowerCase().includes(v);
    case 'is':
      if (['err', 'failed', 'error'].includes(v)) return isFailed(r);
      if (v === 'ws') return !!r.ws;
      if (v === 'retried') return (r.attempts || 0) > 1;
      if (v === 'repeater') return r.source === 'repeater';
      if (v === 'replay') return (r.source || '').startsWith('replay');
      if (v === 'edited') return r.intercepted === 'edited';
      return false;
    default: return (r.url || '').toLowerCase().includes(v) || (r.method || '').toLowerCase() === v || String(r.status) === v || (r.err || '').toLowerCase().includes(v);
  }
}

export default {
  id: 'proxy', title: 'Proxy', icon: 'proxy',
  mount(root) {
    const page = el('div', 'page');
    root.append(page);
    let view = [], detail = null, lastRange = '';

    // ----- filter bar -----
    const filter = el('input', { class: 'input', type: 'search', placeholder: 'Filter  megamarket  status:5xx  -type:image  fp:chrome  is:retried', 'aria-label': 'Filter requests', spellcheck: 'false', autocomplete: 'off', value: ui.filter });
    const chips = el('div', { class: 'chips', role: 'group', 'aria-label': 'Status' });
    const liveBtn = el('button', { class: 'btn sm', title: 'Keep the newest request in view' });
    const clearBtn = el('button', { class: 'btn sm ghost', title: 'Empty the list. Logs on disk are kept.' }, icon('trash'), 'Clear');
    const harBtn = el('button', { class: 'btn sm ghost', title: 'Download every request in the list as a HAR file' }, icon('down'), 'HAR');
    page.append(el('div', 'filterbar', el('div', 'search', icon('search'), filter), chips, liveBtn, harBtn, clearBtn));
    const banner = el('div', { class: 'errbox', style: { margin: '8px 14px' }, hidden: true }, "Can't reach netlog. Retrying.");
    page.append(banner);

    // ----- list -----
    const rows = el('div', { class: 'rows', tabindex: '0', 'aria-label': 'Requests. j and k move the selection.' });
    const vspace = el('div', 'vspace');
    const empty = el('div', 'empty');
    rows.append(vspace, empty);
    const count = el('span');
    const older = el('button', { class: 'link', hidden: true, onclick: () => loadOlder() }, 'Load older');
    const list = el('section', { class: 'list', 'aria-label': 'Requests' },
      el('div', 'grid lhead', el('span', 't', 'Time'), el('span', 'br-h', ''), el('span', 'm', 'Method'), el('span', null, 'Status'), el('span', null, 'URL'), el('span', 'ty', 'Type'), el('span', 'sz r', 'Size'), el('span', 'r', 'Time taken')),
      rows,
      el('div', 'listfoot', count, el('span', { style: { flex: 1 } }), older, el('span', null, el('span', 'kbd', '/'), ' filter  ', el('span', 'kbd', 'j'), el('span', 'kbd', 'k'), ' move')));

    // ----- detail -----
    const back = el('button', { class: 'btn sm back', onclick: () => page.classList.remove('show-detail') }, icon('left'), 'Requests');
    const durl = el('div', 'durl', el('span', { style: { color: 'var(--muted)', fontFamily: 'var(--sans)' } }, 'Select a request to see it in full.'));
    const dfacts = el('div', 'dfacts');
    const tabs = el('div', { class: 'tabs', role: 'tablist' });
    const dbody = el('div', { class: 'dbody', role: 'tabpanel' });
    const det = el('section', { class: 'detail', 'aria-label': 'Request detail' }, el('div', 'dhead', back, durl, dfacts, tabs), dbody);
    page.append(el('div', 'split', list, det));

    // ----- rendering -----
    function apply() {
      const terms = parseFilter(ui.filter);
      const matched = terms.length ? history.rows.filter(r => terms.every(t => termMatch(r, t) !== t.neg)) : history.rows;
      const counts = Object.fromEntries(CHIPS.map(c => [c[0], 0]));
      for (const r of matched) for (const [k, , f] of CHIPS) if (f(r)) counts[k]++;
      const pred = (CHIPS.find(c => c[0] === ui.chip) || CHIPS[0])[2];
      view = matched.filter(pred);
      chips.textContent = '';
      for (const [k, label, , cls] of CHIPS) {
        if (k !== 'all' && k !== ui.chip && !counts[k]) continue;
        chips.append(el('button', { class: 'chip' + (cls ? ' ' + cls : ''), 'aria-pressed': String(k === ui.chip), onclick: () => { ui.chip = ui.chip === k && k !== 'all' ? 'all' : k; apply(); } }, label, el('b', null, counts[k])));
      }
      count.textContent = view.length === history.rows.length ? `${history.rows.length} requests` : `${view.length} of ${history.rows.length} requests`;
      older.hidden = !history.moreOlder;
      render(true);
    }
    function durBar(r) {
      const i = el('i');
      const w = r.duration_ms > 0 ? Math.max(3, Math.min(36, 36 * Math.log10(r.duration_ms + 1) / Math.log10(30001))) : 0;
      i.style.width = w + 'px';
      i.className = isFailed(r) ? 'bad' : r.duration_ms >= 3000 ? 'slow' : 'fast';
      return el('span', 'dur', el('span', null, r.ws && r.status === 101 ? (r.ws_count ? r.ws_count + ' msg' : 'open') : fmtMs(r.duration_ms)), i);
    }
    function rowNode(r, i) {
      const su = splitUrl(r.url);
      const u = el('span', 'u');
      if (r.intercepted) u.append(el('span', 'badge amber', r.intercepted));
      if (r.source === 'repeater') u.append(el('span', 'badge accent', 'repeater'));
      else if ((r.source || '').startsWith('replay')) u.append(el('span', 'badge accent', 'replay'));
      if ((r.attempts || 0) > 1) u.append(el('span', { class: 'badge warn', title: `Took ${r.attempts} attempts: earlier ones failed on a dead connection` }, 'retried'));
      u.append(el('span', 'h', su.host), el('span', 'p', su.path));
      const n = el('div', { class: 'row grid' + (r.id === ui.selId ? ' sel' : '') + (isFailed(r) ? ' failed' : '') + (history.fresh.has(r.id) ? ' fresh' : ''), 'data-id': r.id, role: 'option', title: r.err || r.url, style: { top: i * ROW + 'px' } },
        el('span', 't', fmtTime(r.time)), browserBadge(r.profile, r.profile ? 'Fingerprint: ' + profileName(r.profile) : 'No fingerprint (cleartext or local)'),
        el('span', 'm ' + r.method, r.method), el('span', 's ' + statusClass(r), statusLabel(r)), u,
        el('span', 'ty', shortType(r.ct)), el('span', 'sz r', fmtSize(r.resp_len)), durBar(r));
      return n;
    }
    function render(force) {
      vspace.style.height = view.length * ROW + 'px';
      empty.hidden = view.length > 0;
      if (!view.length) renderEmpty();
      const top = rows.scrollTop, h = rows.clientHeight;
      const from = Math.max(0, Math.floor(top / ROW) - 10), to = Math.min(view.length, Math.ceil((top + h) / ROW) + 10);
      const key = from + ':' + to;
      if (!force && key === lastRange) return;
      lastRange = key;
      const frag = document.createDocumentFragment();
      for (let i = from; i < to; i++) frag.append(rowNode(view[i], i));
      vspace.replaceChildren(frag);
    }
    function renderEmpty() {
      empty.textContent = '';
      if (!history.loaded) { empty.append(el('strong', null, 'Loading requests')); return; }
      if (history.rows.length) {
        empty.append(el('div', 'ico', icon('search')), el('strong', null, 'Nothing matches this filter'),
          el('button', { class: 'btn sm', onclick: () => { filter.value = ui.filter = ''; ui.chip = 'all'; apply(); } }, 'Clear the filter'));
        return;
      }
      empty.append(el('div', 'ico', icon('globe')), el('strong', null, 'No traffic yet'),
        el('p', null, "Point the browser's HTTP and HTTPS proxy at netlog, trust the CA certificate from Settings, then browse. Requests appear here as they happen."),
        el('button', { class: 'btn sm', onclick: () => go('settings') }, icon('gear'), 'Open setup'));
    }
    function setLive(on) {
      ui.live = on; liveBtn.setAttribute('aria-pressed', String(on)); liveBtn.textContent = '';
      liveBtn.append(icon(on ? 'bolt' : 'pause'), on ? 'Live' : 'Paused');
      liveBtn.className = 'btn sm' + (on ? ' primary' : '');
      if (on) { rows.scrollTop = 0; render(true); }
    }

    // ----- detail -----
    async function select(id, keepTab) {
      ui.selId = id; render(true); page.classList.add('show-detail');
      const r = await fetch('/api/logs/' + id);
      if (!r.ok) { toast('That request is no longer in the log', 'err'); return; }
      detail = await r.json();
      if (!keepTab) {
        if (ui.tab === 'messages' && !detail.ws_messages.length) ui.tab = 'overview';
        if (detail.status === 101 && detail.ws_messages.length) ui.tab = 'messages';
      }
      renderDetail();
    }
    function renderDetail(keepScroll) {
      const d = detail, sc = dbody.scrollTop;
      durl.textContent = ''; durl.classList.remove('full');
      durl.append(el('span', 'm ' + d.method, d.method), d.url);
      det.querySelector('.more')?.remove();
      if (d.url.length > 220) {
        const m = el('button', { class: 'link more', onclick: () => { const f = durl.classList.toggle('full'); m.textContent = f ? 'Show less' : 'Show full URL'; } }, 'Show full URL');
        durl.after(m);
      }
      dfacts.textContent = '';
      dfacts.append(el('span', 's ' + statusClass(d), d.err ? 'Failed' : d.status === 101 ? '101 WebSocket' : `${d.status} ${d.resp_proto || ''}`));
      dfacts.append(el('span', null, d.status === 101 ? (d.ws_open ? 'open' : 'closed after ' + fmtMs(d.duration_ms)) : fmtMs(d.duration_ms)));
      if (d.resp_body.size) dfacts.append(el('span', null, fmtSize(d.resp_body.size)));
      if (d.profile) dfacts.append(el('span', { style: { display: 'inline-flex', gap: '6px', alignItems: 'center' } }, browserBadge(d.profile), profileName(d.profile)));
      const acts = el('span', 'actions',
        el('button', { class: 'btn sm primary', onclick: () => { openInRepeater(d); go('repeater'); }, title: 'Open an editable copy in Repeater' }, icon('repeat'), 'Send to Repeater'),
        el('button', { class: 'btn sm', disabled: d.status === 101, onclick: e => replay(e.currentTarget), title: 'Send it again unchanged' }, icon('play'), 'Replay'),
        el('button', { class: 'btn sm icon', title: 'Copy as curl', 'aria-label': 'Copy as curl', onclick: () => copy(curlFor(d), 'Copied curl command') }, icon('copy')));
      dfacts.append(acts);
      const ts = [['overview', 'Overview'], ['request', 'Request'], ['response', 'Response']];
      if (d.ws_messages.length || d.status === 101) ts.push(['messages', `Messages (${d.ws_messages.length})`]);
      tabs.textContent = '';
      for (const [k, label] of ts) tabs.append(el('button', { class: 'tab', role: 'tab', 'aria-selected': String(k === ui.tab), onclick: () => { ui.tab = k; renderDetail(); } }, label));
      requestAnimationFrame(() => slideInk(tabs));
      dbody.textContent = '';
      ({ overview, request: requestTab, response: responseTab, messages: messagesTab })[ui.tab](dbody, d);
      if (keepScroll) dbody.scrollTop = sc;
    }
    function sec(title, aside) { const s = el('section', 'sec'); const h = el('h3', null, title); if (aside) h.append(el('span', 'aside', ...aside)); s.append(h); return s; }
    function kv(pairs, plain) {
      const g = el('div', 'kv' + (plain ? ' plain' : ''));
      if (!pairs.length) g.append(el('div', 'k', 'none'), el('div'));
      for (const [k, v] of pairs) g.append(el('div', 'k', k), el('div', null, v));
      return g;
    }
    function overview(w, d) {
      if (d.err) w.append(el('div', { class: 'errbox', style: { marginBottom: '16px' } }, d.err));
      const pairs = [['Started', new Date(d.time).toLocaleString()], ['Duration', fmtMs(d.duration_ms)],
        ['Fingerprint', d.profile ? profileName(d.profile) + (d.profile_auto ? ', picked from the browser’s User-Agent' : '') : 'none (cleartext http)'],
        ['Upstream', d.upstream || 'direct'], ['Source', d.source || 'proxy'], ['Client', d.client_addr],
        ['Protocol', (d.req_proto || '') + (d.resp_proto ? ' to the browser, ' + d.resp_proto + ' upstream' : '')],
        ['Request body', fmtSize(d.req_body.size)], ['Response body', fmtSize(d.resp_body.size) + (d.resp_body.was_decoded ? ` (${d.resp_body.encoding}, ${fmtSize(d.resp_body.decoded_size)} decoded)` : '')]];
      if (d.intercepted) pairs.push(['Intercept', d.intercepted]);
      if (d.attempts > 1) pairs.push(['Attempts', `${d.attempts}: earlier tries failed on a dead connection and were retried on a fresh one`]);
      const s = sec('Summary'); s.append(kv(pairs, true)); w.append(s);
      try { const q = [...new URL(d.url).searchParams]; if (q.length) { const qs = sec('Query parameters'); qs.append(kv(q)); w.append(qs); } } catch {}
    }
    function cookies(headers) {
      const out = [];
      for (const h of headers || []) if (h.name.toLowerCase() === 'cookie') for (const part of h.value.split(';')) { const i = part.indexOf('='); if (i > 0) out.push([part.slice(0, i).trim(), part.slice(i + 1).trim()]); }
      return out;
    }
    function setCookies(headers) { return (headers || []).filter(h => h.name.toLowerCase() === 'set-cookie').map(h => { const f = h.value.split(';')[0]; const i = f.indexOf('='); return [f.slice(0, i), h.value.slice(i + 1)]; }); }
    function requestTab(w, d) {
      const hs = sec('Headers', [`${(d.req_headers || []).length}, in the order sent`]); hs.append(kv((d.req_headers || []).map(h => [h.name, h.value]))); w.append(hs);
      const c = cookies(d.req_headers); if (c.length) { const cs = sec('Cookies'); cs.append(kv(c)); w.append(cs); }
      w.append(bodySection('Body', d.req_body, d.id, 'req'));
    }
    function responseTab(w, d) {
      if (d.err) { w.append(el('div', 'errbox', 'No response: ' + d.err)); return; }
      const hs = sec('Headers', [String((d.resp_headers || []).length)]); hs.append(kv((d.resp_headers || []).map(h => [h.name, h.value]))); w.append(hs);
      const c = setCookies(d.resp_headers); if (c.length) { const cs = sec('Set-Cookie'); cs.append(kv(c)); w.append(cs); }
      w.append(bodySection('Body', d.resp_body, d.id, 'resp'));
    }
    function bodySection(title, b, id, side) {
      const aside = [];
      if (b.size) {
        aside.push(el('span', null, fmtSize(b.size) + (b.encoding ? ' ' + b.encoding : '') + (b.content_type ? ', ' + b.content_type.split(';')[0] : '')));
        aside.push(el('a', { href: `/api/logs/${id}/body?side=${side}&mode=${b.encoding ? 'decoded' : 'raw'}`, target: '_blank' }, 'Download'));
      }
      let json = null;
      if (b.is_text && b.text && !b.truncated) { try { const t = b.text.trim(); if (t[0] === '{' || t[0] === '[') json = JSON.parse(t); } catch {} }
      if (json !== null) {
        const seg = el('span', 'seg');
        for (const [v, l] of [[true, 'Pretty'], [false, 'Raw']]) seg.append(el('button', { 'aria-pressed': String(ui.pretty === v), onclick: () => { ui.pretty = v; renderDetail(true); } }, l));
        aside.push(seg);
      }
      if (b.is_text && b.text) aside.push(el('button', { class: 'link', onclick: () => copy(b.text, 'Copied body') }, 'Copy'));
      const s = sec(title, aside);
      if (!b.size) { s.append(el('p', { style: { color: 'var(--muted)', margin: 0 } }, 'No body.')); return s; }
      const pre = el('pre', 'code' + (b.is_text ? '' : ' hex'));
      if (json !== null && ui.pretty) pre.innerHTML = highlightJSON(JSON.stringify(json, null, 2));
      else pre.textContent = b.is_text ? b.text : b.hex;
      s.append(pre);
      if (b.truncated) s.append(el('p', null, 'Showing the first 2 MB. Download for the full body.'));
      return s;
    }
    function messagesTab(w, d) {
      const s = sec('Messages', [d.ws_open ? 'Connection open, updating live' : 'Connection closed']);
      if (!d.ws_messages.length) { s.append(el('p', null, d.ws_open ? 'No messages yet.' : 'The connection closed without exchanging messages.')); w.append(s); return; }
      const box = el('div', 'msgs'), t0 = new Date(d.time).getTime();
      const ops = { 1: 'text', 2: 'binary', 8: 'close', 9: 'ping', 10: 'pong', '-1': 'note' };
      for (const m of d.ws_messages) {
        box.append(el('div', 'msg',
          el('span', { class: 'dir ' + (m.from_client ? 'out' : 'in'), title: m.from_client ? 'Browser to server' : 'Server to browser' }, m.from_client ? '↑' : '↓'),
          el('span', 't', '+' + fmtMs(new Date(m.time).getTime() - t0)), el('span', 'ml ty', ops[m.opcode] || 'op ' + m.opcode), el('span', 'mt sz', fmtSize(m.len)),
          el('pre', null, m.text != null ? m.text : m.hex)));
      }
      s.append(box); w.append(s);
    }
    function curlFor(d) {
      const shq = s => "'" + String(s).replace(/'/g, "'\\''") + "'";
      const skip = new Set(['host', 'content-length', 'connection', 'proxy-connection', 'keep-alive', 'te']);
      const parts = ['curl', shq(d.url)];
      if (d.method !== 'GET') parts.push('-X', d.method);
      let compressed = false;
      for (const h of d.req_headers || []) { const n = h.name.toLowerCase(); if (skip.has(n)) continue; if (n === 'accept-encoding') { compressed = true; continue; } parts.push('-H', shq(h.name + ': ' + h.value)); }
      if (compressed) parts.push('--compressed');
      if (d.req_body.size) parts.push('--data-binary', d.req_body.is_text && !d.req_body.truncated ? shq(d.req_body.text) : '@body.bin');
      return parts.join(' ');
    }
    async function replay(btn) {
      btn.classList.add('loading');
      const r = await api.post(`/logs/${ui.selId}/replay`);
      btn.classList.remove('loading');
      if (!r.ok) { toast('Replay failed: ' + r.error, 'err'); return; }
      toast(r.err ? 'Replayed. The upstream failed: ' + r.err : 'Replayed, got ' + r.status, r.err ? 'err' : undefined);
      setTimeout(() => select(r.id), 300);
    }
    function move(delta) {
      if (!view.length) return;
      let i = view.findIndex(r => r.id === ui.selId); i = i < 0 ? 0 : Math.max(0, Math.min(view.length - 1, i + delta));
      select(view[i].id, true);
      const y = i * ROW; if (y < rows.scrollTop) rows.scrollTop = y; else if (y + ROW > rows.scrollTop + rows.clientHeight) rows.scrollTop = y + ROW - rows.clientHeight;
    }

    // ----- events -----
    filter.addEventListener('input', debounce(() => { ui.filter = filter.value; apply(); }, 120));
    rows.addEventListener('scroll', () => { render(false); if (rows.scrollTop > ROW * 2 && ui.live) setLive(false); });
    rows.addEventListener('click', e => { const r = e.target.closest('.row'); if (r) select(+r.dataset.id); });
    liveBtn.onclick = () => setLive(!ui.live);
    clearBtn.onclick = async () => { await clearHistory(); ui.selId = null; detail = null; durl.textContent = 'Select a request to see it in full.'; dfacts.textContent = ''; tabs.textContent = ''; dbody.textContent = ''; toast('List cleared. Logs on disk are kept.'); };
    harBtn.onclick = () => { const a = el('a', { href: '/api/har', download: '' }); document.body.append(a); a.click(); a.remove(); toast('Exporting HAR'); };
    const onKey = e => {
      const typing = e.target.matches('input,textarea,select');
      if (e.key === 'Escape') { if (typing && e.target === filter) { filter.value = ui.filter = ''; apply(); filter.blur(); } else page.classList.remove('show-detail'); return; }
      if (typing || e.metaKey || e.ctrlKey || e.altKey) return;
      if (e.key === '/') { e.preventDefault(); filter.focus(); }
      else if (e.key === 'j' || (e.key === 'ArrowDown' && document.activeElement === rows)) { e.preventDefault(); move(1); }
      else if (e.key === 'k' || (e.key === 'ArrowUp' && document.activeElement === rows)) { e.preventDefault(); move(-1); }
      else if (e.key === 'r' && detail) { openInRepeater(detail); go('repeater'); }
    };
    document.addEventListener('keydown', onKey);
    const onResize = () => render(true);
    window.addEventListener('resize', onResize);
    const off = onHistory(changed => {
      banner.hidden = !history.failing;
      if (!changed) return;
      const before = view.length, top = rows.scrollTop;
      apply();
      if (!ui.live) rows.scrollTop = top + (view.length - before) * ROW;
      if (detail?.ws_open) select(detail.id, true);
    });

    setLive(ui.live);
    apply();
    if (ui.selId) select(ui.selId, true);
    return { unmount() { off(); document.removeEventListener('keydown', onKey); window.removeEventListener('resize', onResize); } };
  },
};
