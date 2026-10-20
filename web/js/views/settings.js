// Settings: listener, HTTPS decryption, the CA certificate and browser setup.
import { el, icon, toast } from '../util.js';
import { state, saveConfig, onConfig } from '../api.js';

export default {
  id: 'settings', title: 'Settings', icon: 'gear',
  mount(root) {
    const page = el('div', 'page scroll');
    const wrap = el('div', 'pad narrow');
    page.append(wrap); root.append(page);

    function render() {
      const cfg = state.config, st = state.status;
      if (!cfg || !st) return;
      if (wrap.contains(document.activeElement) && document.activeElement.matches('input')) return; // don't fight typing
      wrap.textContent = '';
      wrap.append(el('h2', 'sect-title', 'Settings'), el('p', 'sect-sub', 'Changes apply immediately.'));

      const port = el('input', { class: 'input mono', type: 'number', min: 1, max: 65535, value: cfg.listen_port, style: { width: '120px' }, 'aria-label': 'Listen port' });
      port.addEventListener('change', async () => {
        const r = await saveConfig({ listen_port: parseInt(port.value, 10) });
        if (r.ok) toast(`Proxy listening on 127.0.0.1:${r.proxy_port}`); else { toast(r.error, 'err'); port.value = state.config.listen_port; }
      });
      const mitm = el('input', { type: 'checkbox', role: 'switch', checked: cfg.mitm_enabled, onchange: async e => {
        const r = await saveConfig({ mitm_enabled: e.target.checked });
        toast(r.ok ? (e.target.checked ? 'HTTPS is decrypted and logged' : 'HTTPS passes through untouched and unlogged') : r.error, r.ok ? undefined : 'err');
      } });
      wrap.append(el('div', 'settings-grid',
        el('div', 'card',
          el('h3', null, 'Proxy listener'),
          el('div', 'field-row',
            el('span', null, 'Port'), el('div', null, port, el('p', 'help', 'Listens on 127.0.0.1 only.')),
            el('span', null, 'Decrypt HTTPS'), el('div', null, el('label', 'switch', mitm, el('span', 'track')), el('p', 'help', 'Off tunnels HTTPS without reading it: nothing is logged and the fingerprint is the browser’s own.')))),
        el('div', 'card',
          el('h3', null, 'CA certificate'),
          el('p', { class: 'help', style: { marginBottom: '12px' } }, 'netlog decrypts HTTPS with its own certificate authority. Trust it in the browser you point at netlog, and only there. The private key never leaves ', el('span', 'mono', st.data_dir), '.'),
          el('a', { class: 'btn primary', href: '/ca.pem', download: 'netlog-ca.pem', style: { textDecoration: 'none' } }, icon('down'), 'Download netlog-ca.pem'),
          el('p', 'help', 'Also written to ', el('span', 'mono', st.ca_path), '.')),
        el('div', 'card',
          el('h3', null, 'Set up a browser'),
          el('div', { class: 'field-row', style: { alignItems: 'start' } },
            el('strong', null, 'Firefox'),
            el('div', null, el('p', { class: 'help', style: { margin: 0 } }, 'Settings, Privacy & Security, View Certificates, Authorities, Import the CA and tick "Trust this CA to identify websites". Then Network Settings, Manual proxy: HTTP proxy 127.0.0.1 port ' + cfg.listen_port + ', and "Also use this proxy for HTTPS".')),
            el('strong', null, 'Chrome'),
            el('div', null, el('p', { class: 'help', style: { margin: 0 } }, 'Add the CA to the macOS keychain as trusted (Keychain Access, System, Always Trust). Start a separate profile pointed at netlog:'),
              el('pre', { class: 'code', style: { marginTop: '8px' } }, `open -na "Google Chrome" --args --user-data-dir=/tmp/netlog-chrome --proxy-server=127.0.0.1:${cfg.listen_port}`)))),
        el('div', 'card',
          el('h3', null, 'Data'),
          el('div', 'field-row',
            el('span', null, 'Folder'), el('span', 'mono', st.data_dir),
            el('span', null, 'Logged requests'), el('span', null, String(st.count)),
            el('span', null, 'Export'), el('div', null, el('a', { class: 'btn sm', href: '/api/har', download: '', style: { textDecoration: 'none' } }, icon('down'), 'Download HAR'))))));
    }
    const off = onConfig(render);
    render();
    return { unmount: off };
  },
};
