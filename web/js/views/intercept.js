// Intercept: pause requests before they leave, edit them, forward or drop.
import { el, icon, fmtTime, splitUrl, toast, requestToText, textToRequest, busy, debounce } from '../util.js';
import { api, state, saveConfig, subscribe } from '../api.js';

const ui = { selId: null, drafts: new Map() }; // held id -> edited text

export default {
  id: 'intercept', title: 'Intercept', icon: 'pause',
  mount(root) {
    const page = el('div', 'page');
    root.append(page);
    let held = [], enabled = false, timer = null, origBodies = new Map();

    const sw = el('input', { type: 'checkbox', role: 'switch', 'aria-label': 'Intercept requests' });
    const swLabel = el('span', { style: { fontWeight: 600 } });
    const filter = el('input', { class: 'input mono', placeholder: 'only these hosts, e.g. megamarket api.  -yandex excludes', spellcheck: 'false', style: { flex: '1 1 260px' } });
    const fwdAll = el('button', { class: 'btn sm amber', onclick: e => busy(e.currentTarget, async () => { await api.post('/intercept/forward-all'); ui.drafts.clear(); await refresh(); toast('Forwarded every held request'); }) }, icon('play'), 'Forward all');
    const top = el('div', 'filterbar', el('label', { class: 'switch amber' }, sw, el('span', 'track'), swLabel), filter, fwdAll);
    const banner = el('div', 'held-banner', el('span', 'dot'), el('span'));
    const queue = el('div', { class: 'queue scroll', role: 'listbox', 'aria-label': 'Held requests' });
    const edit = el('section', 'pane');
    const body = el('div', { class: 'workbench', style: { gridTemplateColumns: 'minmax(260px,32%) 1fr' } }, queue, edit);
    page.append(top, banner, body);

    sw.onchange = async () => {
      const r = await saveConfig({ intercept: { enabled: sw.checked, filter: filter.value.trim() } });
      if (!r.ok) { toast(r.error, 'err'); sw.checked = !sw.checked; return; }
      toast(sw.checked ? 'Intercept is on. Matching requests will wait here.' : 'Intercept is off. Held requests were forwarded.');
      refresh();
    };
    filter.addEventListener('input', debounce(async () => {
      const r = await saveConfig({ intercept: { enabled: sw.checked, filter: filter.value.trim() } });
      if (!r.ok) toast(r.error, 'err');
    }, 500));

    async function refresh() {
      let d;
      try { d = await api.get('/intercept'); } catch { return; }
      enabled = d.enabled;
      if (document.activeElement !== filter) filter.value = d.filter || '';
      sw.checked = enabled;
      swLabel.textContent = enabled ? 'Intercepting' : 'Intercept off';
      const ids = held.map(h => h.id).join();
      held = d.held;
      for (const h of held) origBodies.set(h.id, h.body || '');
      if (ids !== held.map(h => h.id).join()) render();
      banner.hidden = !held.length;
      fwdAll.disabled = !held.length;
      banner.lastChild.textContent = held.length === 1 ? 'A request is waiting for you. The browser is paused until you forward or drop it.' : `${held.length} requests are waiting. The browser is paused until you decide.`;
    }

    function render() {
      queue.textContent = '';
      if (!held.find(h => h.id === ui.selId)) ui.selId = held[0]?.id ?? null;
      for (const h of held) {
        const su = splitUrl(h.url);
        queue.append(el('div', { class: 'qitem' + (h.id === ui.selId ? ' sel' : ''), role: 'option', tabindex: '0', 'aria-selected': String(h.id === ui.selId),
          onclick: () => { ui.selId = h.id; render(); }, onkeydown: e => { if (e.key === 'Enter') { ui.selId = h.id; render(); } } },
          el('span', 'm ' + h.method, h.method), el('span', 'u', el('span', 'h', su.host), el('span', 'p', su.path)),
          el('span', 't', 'held since ' + fmtTime(h.time))));
      }
      if (!held.length) queue.append(el('div', 'empty', el('div', 'ico', icon('pause')), el('strong', null, enabled ? 'Waiting for requests' : 'Intercept is off'),
        el('p', null, enabled ? 'Requests to matching hosts stop here before they leave. Edit one and forward it, or drop it.' : 'Turn it on to pause matching requests before they go upstream, then edit, forward or drop each one.')));
      renderEditor();
    }

    function renderEditor() {
      edit.textContent = '';
      const h = held.find(x => x.id === ui.selId);
      if (!h) { edit.append(el('div', 'empty', el('div', 'ico', icon('edit')), el('strong', null, 'Nothing selected'), el('p', null, 'Held requests open here for editing.'))); return; }
      const ta = el('textarea', { spellcheck: 'false', wrap: 'off', 'aria-label': 'Held request' });
      ta.value = ui.drafts.get(h.id) ?? requestToText({ method: h.method, url: h.url, headers: h.headers, body: h.body || '' });
      ta.addEventListener('input', () => ui.drafts.set(h.id, ta.value));
      ta.addEventListener('keydown', e => { if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') { e.preventDefault(); forward(fwd); } });
      const fwd = el('button', { class: 'btn primary', title: 'Forward (Ctrl/Cmd + Enter)', onclick: e => forward(e.currentTarget) }, icon('send'), 'Forward');
      const drop = el('button', { class: 'btn danger', onclick: e => decide(e.currentTarget, { action: 'drop' }, 'Dropped') }, icon('drop'), 'Drop');
      const reset = el('button', { class: 'btn ghost sm', onclick: () => { ui.drafts.delete(h.id); renderEditor(); } }, 'Undo edits');
      edit.append(el('div', 'pane-bar', el('span', 'title', ui.drafts.has(h.id) ? 'Edited request' : 'Held request'), reset, drop, fwd), el('div', 'editor', ta));
      async function forward(btn) {
        const text = ui.drafts.get(h.id);
        if (text == null) return decide(btn, { action: 'forward' }, 'Forwarded');
        let req; try { req = textToRequest(text, origBodies.get(h.id)); } catch (e) { toast(e.message, 'err'); return; }
        return decide(btn, { action: 'forward', edit: req }, 'Forwarded with your edits');
      }
      async function decide(btn, payload, msg) {
        const r = await busy(btn, () => api.post('/intercept/' + h.id, payload));
        if (!r.ok) { toast(r.error, 'err'); }
        else toast(msg);
        ui.drafts.delete(h.id);
        await refresh(); render();
      }
    }

    const off = subscribe(() => { if (state.status && state.status.intercept_held !== held.length) refresh(); });
    refresh().then(render);
    timer = setInterval(refresh, 700);
    return { unmount() { clearInterval(timer); off(); } };
  },
};
