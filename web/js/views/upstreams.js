// Upstreams: the list of proxies netlog can route through, which one is
// active, and a live test of each (exit IP, location, latency).
import { el, icon, toast, busy } from '../util.js';
import { api, state, saveConfig, onConfig } from '../api.js';

const results = new Map(); // upstream id ('' = direct) -> test result
const flag = cc => cc && cc.length === 2 ? String.fromCodePoint(...[...cc.toUpperCase()].map(c => 0x1f1a5 + c.charCodeAt(0))) : '';
const mask = u => u.replace(/\/\/([^:@/]*):[^@/]*@/, '//$1:•••@');

export default {
  id: 'upstreams', title: 'Upstreams', icon: 'route',
  mount(root) {
    const page = el('div', 'page scroll');
    const wrap = el('div', 'pad narrow');
    page.append(wrap); root.append(page);
    let editing = null; // upstream id being edited

    async function save(patch, msg) {
      const r = await saveConfig(patch);
      if (!r.ok) { toast(r.error, 'err'); return false; }
      if (msg) toast(msg);
      return true;
    }
    async function test(id, url, btn) {
      const r = await busy(btn, () => api.post('/upstreams/test', { url }));
      results.set(id, r);
      render();
    }

    function resultLine(id) {
      const r = results.get(id);
      if (!r) return null;
      if (!r.ok) return el('div', 'res', el('span', 'badge bad', 'failed'), el('span', { style: { color: 'var(--bad)' } }, r.error || 'status ' + r.status));
      return el('div', 'res', el('span', 'badge ok', icon('check'), 'reachable'),
        el('span', null, 'exit ', el('b', null, r.ip)), el('span', null, flag(r.country), ' ', [r.city, r.country].filter(Boolean).join(', ')),
        r.org ? el('span', null, r.org) : null, el('span', null, el('b', null, r.ms + ' ms')));
    }

    function item(u) {
      const cfg = state.config;
      const id = u ? u.id : '';
      const active = (cfg.active_upstream || '') === id;
      const activate = async () => { if (!active) await save({ active_upstream: id }, u ? 'Routing through ' + u.name : 'Now connecting directly'); };
      if (u && editing === u.id) return form(u);
      const card = el('div', { class: 'card hover uitem' + (active ? ' active' : ''), role: 'radio', 'aria-checked': String(active), tabindex: '0',
        onclick: e => { if (!e.target.closest('button')) activate(); }, onkeydown: e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); activate(); } } },
        el('span', 'radio'),
        el('div', null,
          el('div', 'name', u ? u.name : 'Direct', active ? el('span', 'badge accent', 'active') : null),
          el('div', 'url', u ? mask(u.url) : 'No upstream: netlog connects to sites itself'),
          resultLine(id)),
        el('div', 'acts',
          el('button', { class: 'btn sm', onclick: e => test(id, u ? u.url : '', e.currentTarget) }, icon('bolt'), 'Test'),
          u ? el('button', { class: 'btn sm ghost icon', title: 'Edit', 'aria-label': 'Edit ' + u.name, onclick: () => { editing = u.id; render(); } }, icon('edit')) : null,
          u ? el('button', { class: 'btn sm ghost icon', title: 'Delete', 'aria-label': 'Delete ' + u.name, onclick: async e => {
            const b = e.currentTarget;
            if (!b.dataset.armed) { // first click arms, second deletes
              b.dataset.armed = '1'; b.className = 'btn sm danger'; b.textContent = 'Delete?';
              setTimeout(() => { if (b.isConnected) { delete b.dataset.armed; b.className = 'btn sm ghost icon'; b.replaceChildren(icon('trash')); } }, 3000);
              return;
            }
            await save({ upstreams: cfg.upstreams.filter(x => x.id !== u.id), active_upstream: active ? '' : cfg.active_upstream }, 'Deleted ' + u.name);
            results.delete(u.id);
          } }, icon('trash')) : null));
      return card;
    }

    function form(u) {
      const name = el('input', { class: 'input', placeholder: 'LocalRack', value: u?.name || '', 'aria-label': 'Name' });
      const url = el('input', { class: 'input mono', placeholder: 'http://127.0.0.1:12345  or  socks5://user:pass@host:1080', value: u?.url || '', spellcheck: 'false', 'aria-label': 'Proxy URL' });
      const ok = el('button', { class: 'btn primary', type: 'submit' }, icon(u ? 'check' : 'plus'), u ? 'Save' : 'Add upstream');
      const f = el('form', { class: 'card uform', onsubmit: async e => {
        e.preventDefault();
        if (!url.value.trim()) { toast('Enter the proxy URL', 'err'); url.focus(); return; }
        const cfg = state.config;
        const entry = { id: u?.id || '', name: name.value.trim(), url: url.value.trim() };
        const list = u ? cfg.upstreams.map(x => x.id === u.id ? entry : x) : [...cfg.upstreams, entry];
        if (await save({ upstreams: list }, u ? 'Saved ' + (entry.name || 'upstream') : 'Added ' + (entry.name || 'upstream'))) { editing = null; render(); }
      } },
        el('label', 'field', 'Name', name), el('label', 'field', 'Proxy URL', url),
        el('div', { style: { display: 'flex', gap: '6px' } }, u ? el('button', { class: 'btn ghost', type: 'button', onclick: () => { editing = null; render(); } }, 'Cancel') : null, ok));
      return f;
    }

    function render() {
      const cfg = state.config;
      wrap.textContent = '';
      if (!cfg) { wrap.append(el('div', 'empty', el('strong', null, 'Loading'))); return; }
      wrap.append(el('div', { style: { display: 'flex', alignItems: 'flex-start', gap: '12px' } },
        el('div', { style: { flex: 1 } }, el('h2', 'sect-title', 'Upstream proxies'),
          el('p', 'sect-sub', 'Pick where requests leave from. The active one applies to new requests right away; Repeater tabs can pick their own. HTTP, HTTPS and SOCKS5 proxies work, with credentials in the URL.')),
        el('button', { class: 'btn', onclick: async e => { const b = e.currentTarget; await busy(b, () => Promise.all([['', ''], ...cfg.upstreams.map(u => [u.id, u.url])].map(async ([id, url]) => results.set(id, await api.post('/upstreams/test', { url }))))); render(); } }, icon('bolt'), 'Test all')));
      const list = el('div', { class: 'ulist', role: 'radiogroup', 'aria-label': 'Upstreams' }, item(null), ...cfg.upstreams.map(item));
      wrap.append(list, el('h3', { style: { margin: '26px 0 4px', fontSize: '14px' } }, 'Add an upstream'), form(null));
    }
    const off = onConfig(() => { if (!document.activeElement?.closest('form')) render(); });
    render();
    return { unmount: off };
  },
};
