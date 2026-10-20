// history polls the request log and keeps it in memory, newest first. The
// proxy view renders it; the top bar's pulse reads its timeline.
import { api } from './api.js';

export const history = {
  rows: [],
  byId: new Map(),
  maxId: 0,
  oldestId: 0,
  moreOlder: false,
  loaded: false,
  failing: false,
  fresh: new Set(), // ids that arrived in the last poll, for the flash animation
};
const subs = new Set();
export const onHistory = fn => { subs.add(fn); return () => subs.delete(fn); };
const emit = changed => { for (const f of subs) f(changed); };

const PAGE = 5000;
let failures = 0;

export async function pollHistory() {
  try {
    const d = await api.get(`/logs?after=${history.maxId}&limit=${PAGE}`);
    failures = 0; history.failing = false;
    const fresh = [];
    for (const e of d.entries) {
      const prev = history.byId.get(e.id);
      if (prev) { Object.assign(prev, e); continue; }
      history.byId.set(e.id, e); fresh.push(e);
      if (e.id > history.maxId) history.maxId = e.id;
    }
    fresh.sort((a, b) => b.id - a.id);
    history.fresh = new Set(history.loaded ? fresh.map(e => e.id) : []);
    if (fresh.length) history.rows = fresh.concat(history.rows);
    if (!history.loaded) {
      history.loaded = true;
      history.oldestId = history.rows.length ? history.rows[history.rows.length - 1].id : 0;
      history.moreOlder = d.entries.length >= PAGE;
    }
    emit(fresh.length > 0);
  } catch {
    if (++failures >= 2 && !history.failing) { history.failing = true; emit(false); }
  }
}

export async function loadOlder() {
  const d = await api.get(`/logs?before=${history.oldestId}&limit=${PAGE}`);
  for (const e of d.entries) if (!history.byId.has(e.id)) { history.byId.set(e.id, e); history.rows.push(e); }
  if (d.entries.length) history.oldestId = d.entries[d.entries.length - 1].id;
  history.moreOlder = d.entries.length >= PAGE;
  emit(true);
}

export async function clearHistory() {
  await api.post('/clear');
  history.rows = []; history.byId.clear(); history.oldestId = 0; history.moreOlder = false; history.fresh = new Set();
  emit(true);
}

// timeline returns per-second [total, failed] counts for the last n seconds.
export function timeline(n) {
  const now = Math.floor(Date.now() / 1000);
  const out = Array.from({ length: n }, () => [0, 0]);
  for (const r of history.rows) {
    const t = Math.floor(new Date(r.time).getTime() / 1000);
    const i = n - 1 - (now - t);
    if (i < 0) break; // rows are newest first
    if (i >= n) continue;
    out[i][0]++;
    if (r.err || r.status >= 500) out[i][1]++;
  }
  return out;
}
