import { $, el, icon, toast, go } from './util.js';
import { state, subscribe, refreshStatus, refreshConfig, loadProfiles, saveConfig, profileName } from './api.js';
import { pollHistory, timeline } from './history.js';
import proxyView from './views/proxy.js';
import repeaterView from './views/repeater.js';
import interceptView from './views/intercept.js';
import upstreamsView from './views/upstreams.js';
import fingerprintsView from './views/fingerprints.js';
import settingsView from './views/settings.js';

const views = [proxyView, repeaterView, interceptView, upstreamsView, fingerprintsView, settingsView];
let current = null, currentView = null;

// ---------- navigation ----------
const nav = $('#nav');
for (const v of views) {
  const a = el('a', { href: '#/' + v.id, 'data-view': v.id, title: v.title }, icon(v.icon), el('span', null, v.short || v.title));
  nav.append(a);
}
function moveNavPill() {
  const a = nav.querySelector('[aria-current="page"]'), pill = $('#navpill');
  if (!a) return;
  pill.style.transform = `translateY(${a.offsetTop}px)`;
}
function route() {
  const id = (location.hash.match(/^#\/(\w+)/) || [])[1] || 'proxy';
  const v = views.find(x => x.id === id) || views[0];
  if (currentView === v) return;
  current?.unmount?.();
  currentView = v;
  for (const a of nav.querySelectorAll('a')) a.removeAttribute('aria-current');
  nav.querySelector(`[data-view="${v.id}"]`).setAttribute('aria-current', 'page');
  $('#title').textContent = v.title;
  document.title = v.title + ' · netlog';
  const root = $('#view'); root.textContent = '';
  current = v.mount(root) || null;
  moveNavPill();
}
window.addEventListener('hashchange', route);

// ---------- theme ----------
function themeNow() { return document.documentElement.dataset.theme || (matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark'); }
function paintThemeBtn() { const b = $('#theme'); b.textContent = ''; b.append(icon(themeNow() === 'dark' ? 'sun' : 'moon')); }
$('#theme').onclick = () => { const t = themeNow() === 'dark' ? 'light' : 'dark'; document.documentElement.dataset.theme = t; try { localStorage.setItem('netlog.theme', t); } catch {} paintThemeBtn(); drawPulse(); };
paintThemeBtn();

// ---------- top-bar route pills ----------
function pill(host, label, value, title, buildMenu) {
  host.textContent = '';
  const btn = el('button', { 'aria-haspopup': 'menu', 'aria-expanded': 'false', title },
    el('span', 'lbl', label), el('span', 'val', value), icon('chev', 'chev'));
  host.append(btn);
  btn.onclick = e => {
    e.stopPropagation();
    const open = host.hasAttribute('data-open');
    closeMenus();
    if (open) return;
    host.setAttribute('data-open', ''); btn.setAttribute('aria-expanded', 'true');
    const m = el('div', { class: 'menu', role: 'menu' });
    buildMenu(m);
    host.append(m);
    m.querySelector('[aria-checked="true"], button.item')?.focus();
  };
}
function closeMenus() { for (const h of document.querySelectorAll('.pill[data-open]')) { h.removeAttribute('data-open'); h.querySelector('button').setAttribute('aria-expanded', 'false'); h.querySelector('.menu')?.remove(); } }
document.addEventListener('click', e => { if (!e.target.closest('.menu')) closeMenus(); });
document.addEventListener('keydown', e => { if (e.key === 'Escape') closeMenus(); });
function item(label, sub, checked, onPick) {
  return el('button', { class: 'item', role: 'menuitemradio', 'aria-checked': String(!!checked), onclick: async () => { closeMenus(); await onPick(); } },
    el('span', null, label, sub ? el('span', 'sub', sub) : null), icon('check', 'tick'));
}
async function pick(patch, msg) {
  const r = await saveConfig(patch);
  if (r.ok) toast(msg); else toast(r.error, 'err');
}
function renderPills() {
  const c = state.config; if (!c) return;
  const up = c.upstreams.find(u => u.id === c.active_upstream);
  pill($('#uppill'), 'via', up ? up.name : 'Direct', 'Upstream proxy for new requests', m => {
    m.append(el('h4', null, 'Upstream'));
    m.append(item('Direct', 'no upstream proxy', !up, () => pick({ active_upstream: '' }, 'Now connecting directly')));
    for (const u of c.upstreams) m.append(item(u.name, u.url.replace(/\/\/[^@/]*@/, '//•••@'), up?.id === u.id, () => pick({ active_upstream: u.id }, 'Routing through ' + u.name)));
    m.append(el('hr'), el('button', { class: 'item', onclick: () => { closeMenus(); go('upstreams'); } }, el('span', null, 'Manage upstreams')));
  });
  const fpVal = c.fingerprint === 'auto' ? 'Auto' : profileName(c.fingerprint);
  pill($('#fppill'), 'as', fpVal, 'Fingerprint presented upstream', m => {
    m.append(el('h4', null, 'Fingerprint'));
    m.append(item('Auto', 'match the browser that sent each request', c.fingerprint === 'auto', () => pick({ fingerprint: 'auto' }, 'Fingerprint follows each browser')));
    for (const p of state.profiles) m.append(item(p.name + (p.verified ? '' : ' (unverified)'), p.ja4 || p.user_agent.slice(0, 48), c.fingerprint === p.id, () => pick({ fingerprint: p.id }, 'Every request now presents ' + p.name)));
    m.append(el('hr'), el('button', { class: 'item', onclick: () => { closeMenus(); go('fingerprints'); } }, el('span', null, 'Compare fingerprints')));
  });
}

// ---------- pulse ----------
const canvas = $('#pulse');
function drawPulse() {
  const ctx = canvas.getContext('2d'), W = canvas.width, H = canvas.height, n = 60;
  const data = timeline(n), max = Math.max(4, ...data.map(d => d[0]));
  const cs = getComputedStyle(document.documentElement);
  const a1 = cs.getPropertyValue('--accent').trim(), a2 = cs.getPropertyValue('--accent-2').trim(), bad = cs.getPropertyValue('--bad').trim(), line = cs.getPropertyValue('--line').trim();
  ctx.clearRect(0, 0, W, H);
  ctx.fillStyle = line; ctx.fillRect(0, H - 1, W, 1);
  const g = ctx.createLinearGradient(0, H, 0, 0); g.addColorStop(0, a1); g.addColorStop(1, a2);
  const bw = W / n;
  data.forEach(([t, f], i) => {
    if (!t) return;
    const h = Math.max(3, (t / max) * (H - 4));
    ctx.globalAlpha = 0.35 + 0.65 * (i / n);
    ctx.fillStyle = g; ctx.beginPath(); ctx.roundRect(i * bw + 1, H - h, bw - 2, h, 2); ctx.fill();
    if (f) { const fh = Math.max(3, (f / max) * (H - 4)); ctx.fillStyle = bad; ctx.beginPath(); ctx.roundRect(i * bw + 1, H - fh, bw - 2, fh, 2); ctx.fill(); }
  });
  ctx.globalAlpha = 1;
  const last5 = data.slice(-5).reduce((s, d) => s + d[0], 0) / 5;
  $('#rate').innerHTML = `<b>${last5 < 10 ? last5.toFixed(1) : Math.round(last5)}</b> req/s`;
}

// ---------- status ----------
function renderStatus() {
  const s = state.status;
  $('#dot').className = 'status-dot' + (state.online && s?.listening ? '' : ' off');
  $('#dot').title = !state.online ? 'netlog is not reachable' : `Proxy listening on 127.0.0.1:${s?.proxy_port}`;
  const held = s?.intercept_held || 0;
  const a = nav.querySelector('[data-view="intercept"]');
  a.querySelector('.count')?.remove();
  if (held) a.append(el('span', 'count', String(held)));
  renderPills();
}
subscribe(renderStatus);

async function boot() {
  await Promise.all([refreshStatus(), refreshConfig().catch(() => {}), loadProfiles().catch(() => {})]);
  route();
  await pollHistory();
  setInterval(pollHistory, 1000);
  setInterval(drawPulse, 1000);
  setInterval(refreshStatus, 2000);
  setInterval(() => refreshConfig().catch(() => {}), 10000);
  drawPulse();
  window.addEventListener('resize', moveNavPill);
}
boot();
