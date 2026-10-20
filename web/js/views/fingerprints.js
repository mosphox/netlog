// Fingerprints: choose auto (follow each browser) or a fixed profile, see
// every profile's expected values, and probe one live.
import { el, icon, toast, busy, browserBadge } from '../util.js';
import { api, state, saveConfig, onConfig } from '../api.js';

const probes = new Map(); // profile id -> probe result or error

export default {
  id: 'fingerprints', title: 'Fingerprints', short: 'Prints', icon: 'fp',
  mount(root) {
    const page = el('div', 'page scroll');
    const wrap = el('div', 'pad narrow');
    page.append(wrap); root.append(page);

    async function set(patch, msg) { const r = await saveConfig(patch); if (!r.ok) toast(r.error, 'err'); else toast(msg); }

    function render() {
      const cfg = state.config, profiles = state.profiles;
      wrap.textContent = '';
      if (!cfg || !profiles.length) { wrap.append(el('div', 'empty', el('strong', null, 'Loading'))); return; }
      const auto = cfg.fingerprint === 'auto';
      wrap.append(el('h2', 'sect-title', 'Fingerprint'),
        el('p', 'sect-sub', 'What netlog looks like to the sites it talks to: the TLS ClientHello, the HTTP/2 settings and header order, and the User-Agent of a real browser.'));
      const fixedSel = el('select', { class: 'select', 'aria-label': 'Fixed profile', onclick: e => e.stopPropagation(), onchange: e => set({ fingerprint: e.target.value }, 'Every request now presents ' + profiles.find(p => p.id === e.target.value).name) });
      for (const p of profiles) fixedSel.append(el('option', { value: p.id }, p.name));
      fixedSel.value = auto ? cfg.fallback_fingerprint : cfg.fingerprint;
      const fbSel = el('select', { class: 'select', 'aria-label': 'Fallback profile', onclick: e => e.stopPropagation(), onchange: e => set({ fallback_fingerprint: e.target.value }, 'Fallback is now ' + profiles.find(p => p.id === e.target.value).name) });
      for (const p of profiles) fbSel.append(el('option', { value: p.id }, p.name));
      fbSel.value = cfg.fallback_fingerprint;
      wrap.append(el('div', 'fpmode',
        el('button', { class: 'modecard', 'aria-pressed': String(auto), onclick: () => !auto && set({ fingerprint: 'auto' }, 'Fingerprint follows each browser') },
          el('strong', null, 'Auto'), el('span', null, 'Each request goes out as the browser that sent it: Chrome traffic as Chrome, Firefox as Firefox, nearest version. Anything else uses the fallback.'),
          el('div', { style: { marginTop: '12px', display: 'flex', gap: '8px', alignItems: 'center' } }, el('span', { style: { color: 'var(--muted)', fontSize: '12px' } }, 'Fallback'), fbSel)),
        el('button', { class: 'modecard', 'aria-pressed': String(!auto), onclick: () => auto && set({ fingerprint: fixedSel.value }, 'Every request now presents ' + profiles.find(p => p.id === fixedSel.value).name) },
          el('strong', null, 'Fixed'), el('span', null, 'Every request presents the same browser, whatever sent it. Useful to test how a site treats one browser.'),
          el('div', { style: { marginTop: '12px' } }, fixedSel))));
      const forceUA = el('input', { type: 'checkbox', role: 'switch', checked: cfg.force_ua, onchange: e => set({ force_ua: e.target.checked }, e.target.checked ? 'User-Agent now matches the fingerprint' : 'The browser’s own User-Agent is kept') });
      wrap.append(el('div', { class: 'card', style: { padding: '14px 16px', marginBottom: '22px', display: 'flex', gap: '14px', alignItems: 'center' } },
        el('label', 'switch', forceUA, el('span', 'track')),
        el('div', null, el('strong', null, 'Rewrite the User-Agent'), el('p', 'help', 'Replace the browser’s User-Agent with the profile’s, so headers agree with the TLS fingerprint. Leave it off in Auto mode with a matching browser.'))));

      wrap.append(el('h3', { style: { margin: '0 0 10px', fontSize: '14px' } }, 'Profiles'));
      const list = el('div', 'fptable');
      for (const p of profiles) list.append(row(p, cfg));
      wrap.append(list);
    }

    function row(p, cfg) {
      const inUse = cfg.fingerprint === p.id || (cfg.fingerprint === 'auto' && cfg.fallback_fingerprint === p.id);
      const vals = el('div', 'vals',
        el('span', null, 'JA4'), el('span', 'mono', p.ja4 || 'not captured'),
        el('span', null, 'HTTP/2'), el('span', 'mono', p.akamai || 'not captured'),
        el('span', null, 'UA'), el('span', 'mono', p.user_agent));
      const card = el('div', 'card fprow',
        browserBadge(p.id),
        el('div', 'name', p.name,
          p.verified ? el('span', { class: 'badge ok', title: 'Matched against the real browser, field by field' }, icon('shield'), 'verified') : el('span', { class: 'badge', title: 'A tls-client preset, not compared with a real browser' }, 'unverified'),
          p.random_ext_order ? el('span', { class: 'badge', title: 'Extension order is shuffled per connection, as Chrome does' }, 'shuffles extensions') : null,
          inUse ? el('span', 'badge accent', cfg.fingerprint === 'auto' ? 'fallback' : 'in use') : null),
        el('div', 'acts', el('button', { class: 'btn sm', title: 'Send a request with this profile to tls.peet.ws through the active upstream and compare', onclick: e => probe(p, e.currentTarget) }, icon('bolt'), 'Probe live')),
        vals);
      const res = probes.get(p.id);
      if (res) card.append(probeView(res));
      return card;
    }
    function probeView(r) {
      if (r.error) return el('div', 'checks', el('div', 'errbox', r.error));
      const box = el('div', 'checks');
      if (!r.checks?.length) {
        box.append(el('div', 'check', icon('globe'), el('span', null, 'Seen as'), el('span', 'mono', `JA4 ${r.ja4} · HTTP/2 ${r.akamai_hash}`)));
        return box;
      }
      for (const c of r.checks) box.append(el('div', 'check ' + (c.ok ? 'ok' : 'bad'), icon(c.ok ? 'check' : 'x'), el('span', null, c.name), el('span', 'mono', c.ok ? c.got : `got ${c.got || '(nothing)'}, want ${c.want}`)));
      box.append(el('div', { style: { color: 'var(--muted)', fontSize: '12px', marginTop: '4px' } }, (r.match ? 'Identical to the real browser' : 'Differs from the real browser') + `, seen from ${r.ip || 'unknown IP'} by ${r.service?.replace('https://', '').split('/')[0]}`));
      return box;
    }
    async function probe(p, btn) {
      const r = await busy(btn, () => api.post(`/fingerprints/${p.id}/probe`));
      probes.set(p.id, r.ok ? r.result : { error: r.error });
      if (r.ok && r.result.checks?.length) toast(r.result.match ? `${p.name} matches the real browser` : `${p.name} differs from the capture`, r.result.match ? undefined : 'err');
      render();
    }

    const off = onConfig(render);
    render();
    return { unmount: off };
  },
};
