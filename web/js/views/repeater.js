// Repeater: edit a request by hand and send it, as many times as needed, with
// a chosen fingerprint and upstream. Tabs persist in localStorage.
import { el, icon, fmtSize, fmtMs, statusClass, browserBadge, highlightJSON, toast, copy, store, bytesToB64,
  requestToText, textToRequest, busy, slideInk } from '../util.js';
import { api, state, profileName } from '../api.js';

const ui = { tabs: store('repeater') || [], active: store('repeater.active') || null, respView: 'body' };
let seq = Math.max(0, ...ui.tabs.map(t => t.n || 0));
const results = new Map(); // tab id -> {list: [txn], idx}
let rerender = null;

const sample = () => requestToText({ method: 'GET', url: 'https://tls.peet.ws/api/all', headers: [
  { name: 'Accept', value: 'application/json' }, { name: 'Accept-Language', value: 'en-US,en;q=0.9' }] });

function persist() {
  store('repeater', ui.tabs.map(({ id, n, name, text, origBody, profile, upstream }) => ({ id, n, name, text, origBody, profile, upstream })));
  store('repeater.active', ui.active);
}
function newTab(text, name, origBody) {
  const t = { id: Math.random().toString(36).slice(2, 9), n: ++seq, name: name || `Request ${seq}`, text: text || sample(), origBody: origBody || '', profile: '', upstream: '' };
  ui.tabs.push(t); ui.active = t.id; persist();
  return t;
}

// openInRepeater copies a logged request into a new tab. Bodies are fetched
// raw so binary payloads survive the round trip.
export async function openInRepeater(d) {
  let body = '';
  if (d.req_body?.size) {
    try { body = bytesToB64(new Uint8Array(await (await fetch(`/api/logs/${d.id}/body?side=req&mode=raw`)).arrayBuffer())); } catch {}
  }
  let host = '';
  try { host = new URL(d.url).host; } catch {}
  const headers = (d.req_headers || []).filter(h => !['proxy-connection', 'connection', 'content-length'].includes(h.name.toLowerCase()));
  newTab(requestToText({ method: d.method, url: d.url, headers, body }), `${d.method} ${host}`, body);
  rerender?.();
}

export default {
  id: 'repeater', title: 'Repeater', icon: 'repeat',
  mount(root) {
    if (!ui.tabs.length) newTab();
    if (!ui.tabs.find(t => t.id === ui.active)) ui.active = ui.tabs[0].id;
    const page = el('div', 'page');
    root.append(page);
    const rtabs = el('div', { class: 'rtabs', role: 'tablist', 'aria-label': 'Repeater tabs' });
    const bench = el('div', 'workbench');
    page.append(rtabs, bench);

    function renderTabs() {
      rtabs.textContent = '';
      for (const t of ui.tabs) {
        const tab = el('div', { class: 'rtab', role: 'tab', tabindex: '0', 'aria-selected': String(t.id === ui.active), title: 'Double-click to rename',
          onclick: () => { ui.active = t.id; persist(); render(); },
          ondblclick: e => rename(t, e.currentTarget.querySelector('span')),
          onkeydown: e => { if (e.key === 'Enter') { ui.active = t.id; persist(); render(); } } },
          el('span', null, t.name),
          el('button', { class: 'x', 'aria-label': 'Close ' + t.name, onclick: e => { e.stopPropagation(); close(t.id); } }, icon('x')));
        rtabs.append(tab);
      }
      rtabs.append(el('button', { class: 'btn sm ghost icon', title: 'New tab', 'aria-label': 'New tab', onclick: () => { newTab(); render(); } }, icon('plus')));
    }
    function rename(t, span) {
      const inp = el('input', { class: 'input', value: t.name, style: { height: '24px', width: Math.max(90, span.offsetWidth + 24) + 'px' }, 'aria-label': 'Tab name' });
      const done = ok => { if (ok && inp.value.trim()) { t.name = inp.value.trim(); persist(); } renderTabs(); };
      inp.addEventListener('keydown', e => { e.stopPropagation(); if (e.key === 'Enter') done(true); if (e.key === 'Escape') done(false); });
      inp.addEventListener('blur', () => done(true));
      inp.addEventListener('click', e => e.stopPropagation());
      span.replaceWith(inp); inp.focus(); inp.select();
    }
    function close(id) {
      const i = ui.tabs.findIndex(t => t.id === id);
      ui.tabs.splice(i, 1); results.delete(id);
      if (!ui.tabs.length) newTab();
      if (ui.active === id) ui.active = ui.tabs[Math.max(0, i - 1)].id;
      persist(); render();
    }

    function render() {
      renderTabs();
      const t = ui.tabs.find(x => x.id === ui.active);
      bench.textContent = '';
      // ----- request pane -----
      const ta = el('textarea', { spellcheck: 'false', 'aria-label': 'Raw request', wrap: 'off' });
      ta.value = t.text;
      ta.addEventListener('input', () => { t.text = ta.value; persistSoon(); });
      ta.addEventListener('keydown', e => {
        if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') { e.preventDefault(); send(sendBtn); }
        if (e.key === 'Tab' && !e.shiftKey) { e.preventDefault(); ta.setRangeText('  ', ta.selectionStart, ta.selectionEnd, 'end'); t.text = ta.value; }
      });
      const fpSel = el('select', { class: 'select', 'aria-label': 'Fingerprint', title: 'Fingerprint for this tab' });
      const cfgFp = state.config?.fingerprint === 'auto' ? 'Auto' : profileName(state.config?.fingerprint);
      fpSel.append(el('option', { value: '' }, `Default (${cfgFp})`), el('option', { value: 'auto' }, 'Auto from User-Agent'));
      for (const p of state.profiles) fpSel.append(el('option', { value: p.id }, p.name + (p.verified ? '' : ' (unverified)')));
      fpSel.value = t.profile || '';
      fpSel.onchange = () => { t.profile = fpSel.value; persist(); };
      const upSel = el('select', { class: 'select', 'aria-label': 'Upstream', title: 'Upstream for this tab' });
      const ups = state.config?.upstreams || [];
      const activeUp = ups.find(u => u.id === state.config?.active_upstream);
      upSel.append(el('option', { value: '' }, `Default (${activeUp ? activeUp.name : 'Direct'})`), el('option', { value: 'direct' }, 'Direct'));
      for (const u of ups) upSel.append(el('option', { value: u.id }, u.name));
      upSel.value = t.upstream || '';
      upSel.onchange = () => { t.upstream = upSel.value; persist(); };
      const sendBtn = el('button', { class: 'btn primary', title: 'Send (Ctrl/Cmd + Enter)', onclick: e => send(e.currentTarget) }, icon('send'), 'Send');
      bench.append(el('section', 'pane',
        el('div', 'pane-bar', el('span', 'title', 'Request'), fpSel, upSel, sendBtn),
        el('div', 'editor', ta)));

      // ----- response pane -----
      const res = results.get(t.id);
      const cur = res?.list[res.idx];
      const bar = el('div', 'pane-bar', el('span', 'title', 'Response'));
      if (res?.list.length) {
        bar.append(el('span', 'hist',
          el('button', { class: 'btn sm ghost icon', 'aria-label': 'Previous send', disabled: res.idx === 0, onclick: () => { res.idx--; render(); } }, icon('left')),
          `${res.idx + 1} / ${res.list.length}`,
          el('button', { class: 'btn sm ghost icon', 'aria-label': 'Next send', disabled: res.idx === res.list.length - 1, onclick: () => { res.idx++; render(); } }, icon('right'))));
        const seg = el('span', 'seg');
        for (const [k, l] of [['body', 'Body'], ['headers', 'Headers'], ['raw', 'Raw']]) seg.append(el('button', { 'aria-pressed': String(ui.respView === k), onclick: () => { ui.respView = k; render(); } }, l));
        bar.append(seg);
      }
      const body = el('div', 'resp-body');
      bench.append(el('section', 'pane', bar, body));
      if (!cur) {
        body.append(el('div', 'empty', el('div', 'ico', icon('send')), el('strong', null, 'Nothing sent yet'),
          el('p', null, 'Edit the request on the left and press Send. Each send is kept, so you can step back through responses.'),
          el('p', null, el('span', 'kbd', '⌘'), ' ', el('span', 'kbd', 'Enter'), ' sends from the editor.')));
        return;
      }
      const meta = el('div', { class: 'resp-meta', style: { marginBottom: '12px' } },
        el('span', 's ' + statusClass(cur), cur.err ? 'Failed' : `${cur.status} ${cur.resp_proto || ''}`),
        el('span', null, fmtMs(cur.duration_ms)), el('span', null, fmtSize(cur.resp_body.size)),
        el('span', { style: { display: 'inline-flex', gap: '6px', alignItems: 'center' } }, browserBadge(cur.profile), profileName(cur.profile)),
        el('span', null, 'via ' + (cur.upstream || 'direct')),
        el('span', { style: { color: 'var(--faint)' } }, '#' + cur.id));
      body.append(meta);
      if (cur.err) { body.append(el('div', 'errbox', cur.err)); return; }
      const rb = cur.resp_body;
      if (ui.respView === 'headers') {
        const g = el('div', 'kv');
        for (const h of cur.resp_headers || []) g.append(el('div', 'k', h.name), el('div', null, h.value));
        body.append(g);
      } else if (ui.respView === 'raw') {
        const head = `${cur.resp_proto || 'HTTP/1.1'} ${cur.status}\n` + (cur.resp_headers || []).map(h => `${h.name}: ${h.value}`).join('\n');
        body.append(el('pre', 'code', head + '\n\n' + (rb.is_text ? rb.text : rb.hex)));
      } else {
        let json = null;
        if (rb.is_text && rb.text && !rb.truncated) { try { const s = rb.text.trim(); if (s[0] === '{' || s[0] === '[') json = JSON.parse(s); } catch {} }
        const pre = el('pre', 'code' + (rb.is_text ? '' : ' hex'));
        if (json !== null) pre.innerHTML = highlightJSON(JSON.stringify(json, null, 2)); else pre.textContent = rb.size ? (rb.is_text ? rb.text : rb.hex) : '(empty body)';
        body.append(el('div', { style: { display: 'flex', justifyContent: 'flex-end', marginBottom: '6px' } },
          el('button', { class: 'btn sm ghost', onclick: () => copy(rb.text || '', 'Copied body'), disabled: !rb.is_text }, icon('copy'), 'Copy')), pre);
      }
    }
    let pt; const persistSoon = () => { clearTimeout(pt); pt = setTimeout(persist, 300); };

    async function send(btn) {
      const t = ui.tabs.find(x => x.id === ui.active);
      let req;
      try { req = textToRequest(t.text, t.origBody); } catch (e) { toast(e.message, 'err'); return; }
      const r = await busy(btn, () => api.post('/send', { ...req, profile: t.profile, upstream: t.upstream }));
      if (!r.ok) { toast(r.error, 'err'); return; }
      const res = results.get(t.id) || { list: [], idx: 0 };
      res.list.push(r.txn); res.idx = res.list.length - 1; results.set(t.id, res);
      if (/^Request \d+$/.test(t.name)) { try { t.name = `${req.method} ${new URL(req.url).host}`; persist(); } catch {} }
      render();
    }

    rerender = render;
    render();
    return { unmount() { rerender = null; persist(); } };
  },
};
