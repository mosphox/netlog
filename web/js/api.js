// API client and shared app state.

async function req(method, path, body) {
  const r = await fetch('/api' + path, {
    method,
    headers: body ? { 'content-type': 'application/json' } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!r.ok && r.headers.get('content-type')?.includes('json') !== true) throw new Error(`${r.status} ${await r.text()}`);
  return r.json();
}
export const api = {
  get: p => req('GET', p),
  post: (p, b) => req('POST', p, b || {}),
};

// state is a tiny observable store: views read it and subscribe to changes.
const subs = new Set();
export const state = {
  status: null,   // /api/status
  config: null,   // /api/config
  profiles: [],   // /api/fingerprints
  online: true,
};
export function subscribe(fn) { subs.add(fn); return () => subs.delete(fn); }
// onConfig calls fn only when the config or profile list actually changed.
export function onConfig(fn) {
  let last = '';
  return subscribe(s => {
    const sig = JSON.stringify([s.config, s.profiles.length, s.status?.data_dir, s.status?.ca_path]);
    if (sig !== last) { last = sig; fn(s); }
  });
}
export function emit() { for (const f of subs) f(state); }

export async function refreshStatus() {
  try {
    state.status = await api.get('/status');
    state.online = true;
  } catch { state.online = false; }
  emit();
}
export async function refreshConfig() {
  state.config = await api.get('/config');
  emit();
}
export async function loadProfiles() {
  const r = await api.get('/fingerprints');
  state.profiles = r.profiles;
  emit();
}
// saveConfig merges a patch into the config and applies it. It returns the
// server's answer ({ok, error, config}).
export async function saveConfig(patch) {
  const r = await api.post('/config', patch);
  if (r.config) state.config = r.config;
  await refreshStatus();
  return r;
}
export const profileName = id => state.profiles.find(p => p.id === id)?.name || id;
