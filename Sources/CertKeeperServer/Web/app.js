'use strict';
// CertKeeper web interface. Everything is built with DOM calls and textContent — never innerHTML —
// because names, labels and log details can come from the hosts CertKeeper talks to.

const KINDS = [
  ['nginx', 'nginx'], ['apache', 'Apache httpd'], ['proxmox', 'Proxmox VE'], ['truenas', 'TrueNAS'],
  ['unifiOS', 'UniFi OS'], ['opnsense', 'OPNsense'], ['pihole', 'Pi-hole'], ['containerApp', 'App (cert files)'],
  ['device_api', 'Device (HTTPS API)'], ['custom', 'Custom script'],
];
const KIND_NAME = Object.fromEntries(KINDS);
const FILE_KINDS = new Set(['nginx', 'apache', 'containerApp', 'pihole', 'custom']);
const KEY_TYPES = ['ECDSA P-256', 'ECDSA P-384', 'RSA 2048', 'RSA 4096'];
const EXPORT_FORMATS = [
  ['pemSeparate', 'PEM — separate files', 'cert.pem, chain.pem, fullchain.pem and privkey.pem: nginx, Apache, most Linux tools.'],
  ['pemCombined', 'PEM — single file', 'One file with the private key and full chain: HAProxy, Pi-hole, lighttpd.'],
  ['pkcs12', 'PKCS#12 (.p12 / .pfx)', 'One password-protected file with the full chain and key: Windows/IIS, macOS Keychain, Java, Jellyfin.'],
  ['pkcs7', 'PKCS#7 (.p7b) + key', 'The full chain in a .p7b (PKCS#7 can’t hold keys) plus the key as a separate PEM file: Windows, Java.'],
  ['der', 'DER (.cer) + key', 'Each certificate as binary .cer (leaf, then intermediates) plus the key as binary PKCS#8: Windows, appliances, Android.'],
];
const REPO = 'https://github.com/MJWaters1985/CertKeeper';
const COFFEE = 'https://buymeacoffee.com/mjwaters1985';

const S = { session: null, state: null, timer: null, menuOpen: false };

// ---------- DOM helpers ----------

function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k === 'text') el.textContent = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k === 'value') el.value = v;
    else if (k === 'checked') el.checked = !!v;
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const c of children.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); return el; }

function toast(message, error) {
  const t = document.getElementById('toast');
  t.textContent = message;
  t.className = 'show' + (error ? ' error' : '');
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => { t.className = ''; }, error ? 6000 : 3000);
}

function fmtDate(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}

function fmtDay(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleDateString(undefined, { dateStyle: 'medium' });
}

function ago(iso) {
  if (!iso) return 'never';
  const s = (Date.now() - new Date(iso).getTime()) / 1000;
  if (s < 45) return 'just now';
  const units = [['year', 31536000], ['month', 2592000], ['week', 604800], ['day', 86400], ['hour', 3600], ['minute', 60]];
  for (const [u, n] of units) {
    if (s >= n) { const v = Math.round(s / n); return `${v} ${u}${v === 1 ? '' : 's'} ago`; }
  }
  return 'just now';
}

function hostLabel(id) { return S.state.hosts.find(x => x.host.id === id)?.host.name || 'Unknown host'; }
function certLabel(id) { return S.state.certificates.find(x => x.certificate.id === id)?.certificate.name || 'Unknown certificate'; }
function certDTO(id) { return S.state.certificates.find(x => x.certificate.id === id); }
function hostDTO(id) { return S.state.hosts.find(x => x.host.id === id); }

// ---------- API ----------

async function api(method, path, body) {
  const opts = { method, credentials: 'same-origin', headers: { 'X-CertKeeper': '1' } };
  if (body !== undefined) { opts.headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(body); }
  let res;
  try { res = await fetch(path, opts); } catch (e) { throw new Error('CertKeeper isn’t answering. Is it running?'); }
  let data = null;
  const text = await res.text();
  if (text) { try { data = JSON.parse(text); } catch (e) { data = null; } }
  if (res.status === 401 && path !== '/api/login' && path !== '/api/setup') {
    S.session = { signedIn: false };
    render();
    throw new Error('Signed out');
  }
  if (!res.ok) throw new Error(data?.error?.message || `Request failed (${res.status})`);
  return data;
}

/// Runs an action, shows its error, then refreshes the state.
async function act(fn, success) {
  try {
    const r = await fn();
    if (success) toast(success);
    await refresh();
    return r;
  } catch (e) {
    if (e.message !== 'Signed out') toast(e.message, true);
    return undefined;
  }
}

async function refresh() {
  try {
    S.state = await api('GET', '/api/state');
  } catch (e) {
    if (e.message !== 'Signed out') toast(e.message, true);
    schedule(15000);
    return;
  }
  renderApp(false);
  const busy = S.state.maintenanceRunning || S.state.certificates.some(c => c.busy) || S.state.hosts.some(x => x.busy) ||
    S.state.deployments.some(d => d.busy);
  schedule(busy ? 2000 : 15000);
}

function schedule(ms) {
  clearTimeout(S.timer);
  S.timer = setTimeout(refresh, ms);
}

// ---------- Status badges ----------

function certBadge(dto, compact) {
  const s = dto.status, monitored = dto.certificate.external === true;
  const d = s.days;
  switch (s.kind) {
    case 'notIssued': return h('span', { class: 'badge grey', text: monitored ? 'Not checked yet' : 'Not issued' });
    case 'valid': return h('span', { class: 'badge green', text: compact ? `${d}d` : (monitored ? `Monitored · ${d} days` : `Valid · ${d} days`) });
    case 'renewDue': return h('span', { class: 'badge orange', text: compact ? `${d}d` : (monitored ? `Expiring · ${d} days` : `Renewal due · ${d} days`) });
    case 'expired': return h('span', { class: 'badge red', text: 'Expired' });
    case 'domainsChanged': return h('span', { class: 'badge orange', text: 'Names changed' });
  }
  return h('span', { class: 'badge grey', text: s.kind });
}

function deploymentBadge(dto) {
  const s = dto.state, d = s.days;
  const map = {
    disabled: ['grey', 'Disabled'], attention: ['red', 'Needs attention'], error: ['red', 'Error'],
    awaitingIssuance: ['blue', 'Awaiting issuance'], outOfDate: ['orange', 'Out of date'], incompleteChain: ['orange', 'Incomplete chain'],
    current: ['green', 'Current'], notCheckedYet: ['grey', 'Not checked yet'], watching: ['purple', `Watching · ${d} days`],
    expiringSoon: ['orange', `Expiring · ${d} days`], expired: ['red', 'Expired'],
  };
  const [color, text] = map[s.kind] || ['grey', s.kind];
  return h('span', { class: `badge ${color}`, text, title: s.detail || null });
}

function busySpinner(on, label) { return on ? h('span', { class: 'spinner', title: label || 'Working…' }) : null; }

// ---------- Rendering ----------

function route() {
  const parts = (location.hash || '#/overview').slice(2).split('/');
  return { page: parts[0] || 'overview', id: parts[1] };
}

function render() {
  const root = clear(document.getElementById('app'));
  if (!S.session) return;
  if (!S.session.signedIn) { root.append(renderAuth()); return; }
  if (!S.state) { root.append(h('p', { class: 'loading', text: 'Loading…' })); refresh(); return; }
  renderApp(true);
}

/// Redraws the sidebar always and the page unless it holds a form being edited (Settings).
function renderApp(navigated) {
  if (!S.session?.signedIn || !S.state) return;
  const root = document.getElementById('app');
  let layout = root.querySelector('.layout');
  if (!layout) {
    clear(root);
    layout = h('div', { class: 'layout' }, h('nav', { class: 'sidebar' }), h('main', { class: 'main' }, h('div', { class: 'page' })));
    root.append(layout);
    navigated = true;
  }
  const r = route();
  const sidebar = layout.querySelector('.sidebar');
  sidebar.replaceWith(renderSidebar(r));
  if (r.page === 'settings' && !navigated) return;
  const page = layout.querySelector('.page');
  const fresh = h('div', { class: 'page' }, renderPage(r));
  page.replaceWith(fresh);
  if (navigated) layout.querySelector('.main').scrollTop = 0;
}

function renderSidebar(r) {
  const st = S.state;
  const nav = (hash, label, extra, active) =>
    h('a', { class: 'nav-item' + (active ? ' active' : ''), href: hash, onclick: () => { S.menuOpen = false; } },
      h('span', { class: 'label', text: label }), extra);
  return h('nav', { class: 'sidebar' + (S.menuOpen ? '' : ' collapsed') },
    h('div', { class: 'brand' }, h('img', { src: 'icon.svg', alt: '' }), 'CertKeeper',
      h('button', { class: 'menu-button', text: S.menuOpen ? 'Close' : 'Menu', onclick: () => { S.menuOpen = !S.menuOpen; renderApp(false); } })),
    h('div', { class: 'nav' },
      nav('#/overview', 'Overview', null, r.page === 'overview'),
      nav('#/activity', 'Activity', null, r.page === 'activity'),
      h('div', { class: 'nav-section' }, 'Certificates',
        h('button', { class: 'link', title: 'New certificate', text: '+', onclick: () => certModal() })),
      st.certificates.length ? null : h('div', { class: 'nav-item muted small', text: 'None yet' }),
      st.certificates.map(c => nav(`#/certificate/${c.certificate.id}`, c.certificate.name,
        [busySpinner(c.busy), certBadge(c, true)], r.page === 'certificate' && r.id === c.certificate.id)),
      h('div', { class: 'nav-section' }, 'Hosts',
        h('button', { class: 'link', title: 'New host', text: '+', onclick: () => hostModal() })),
      st.hosts.length ? null : h('div', { class: 'nav-item muted small', text: 'None yet' }),
      st.hosts.map(x => nav(`#/host/${x.host.id}`, x.host.name,
        [busySpinner(x.busy), h('span', { class: `dot ${x.health.level}`, title: x.health.summary })], r.page === 'host' && r.id === x.host.id)),
      h('div', { class: 'nav-section' }, 'CertKeeper'),
      nav('#/settings', 'Settings', null, r.page === 'settings')));
}

function renderPage(r) {
  switch (r.page) {
    case 'certificate': return certificateDTOExists(r.id) ? renderCertificate(r.id) : renderMissing();
    case 'host': return hostDTO(r.id) ? renderHost(r.id) : renderMissing();
    case 'activity': return renderActivity();
    case 'settings': return renderSettings();
    default: return renderOverview();
  }
}

function certificateDTOExists(id) { return !!certDTO(id); }

function renderMissing() {
  return [h('div', { class: 'page-header' }, h('h1', { text: 'Not found' })),
    h('p', { class: 'muted' }, 'It may have been deleted. ', h('a', { href: '#/overview', text: 'Back to the overview' }))];
}

// ---------- Overview ----------

function setupWarnings() {
  const st = S.state, out = [];
  if (st.loadError) out.push(h('div', { class: 'banner err' }, h('span', { class: 'grow', text: st.loadError })));
  if (!st.hasCloudflareToken || !st.settings.acceptedTermsOfService || !st.settings.acmeEmail) {
    out.push(h('div', { class: 'banner warn' },
      h('span', { class: 'grow', text: 'Add your Cloudflare API token and Let’s Encrypt account details before issuing certificates.' }),
      h('a', { class: 'button', href: '#/settings', text: 'Open Settings' })));
  }
  return out;
}

function renderOverview() {
  const st = S.state;
  const managed = st.certificates.filter(c => c.certificate.external !== true);
  const needRenewal = managed.filter(c => ['renewDue', 'expired', 'domainsChanged', 'notIssued'].includes(c.status.kind)).length;
  const outOfDate = st.deployments.filter(d => d.state.kind === 'outOfDate').length;
  const card = (n, t) => h('div', { class: 'card' }, h('div', { class: 't', text: t }), h('div', { class: 'n', text: String(n) }));
  const sorted = [...st.certificates].sort((a, b) =>
    (a.certificate.current?.notAfter || '9999').localeCompare(b.certificate.current?.notAfter || '9999'));
  return [
    h('div', { class: 'page-header' }, h('h1', { text: 'Overview' }),
      busySpinner(st.maintenanceRunning, 'Rotation pass running'),
      h('button', { class: 'primary', disabled: st.maintenanceRunning, title: 'Renew what’s due and redeploy anything out of date',
        text: st.maintenanceRunning ? 'Rotation pass running…' : 'Run rotation pass',
        onclick: () => act(() => api('POST', '/api/maintenance'), 'Rotation pass started') })),
    setupWarnings(),
    h('div', { class: 'cards' },
      card(st.certificates.length, 'Certificates'), card(needRenewal, 'Need issuing or renewal'),
      card(st.deployments.length, 'Deployments'), card(outOfDate, 'Out of date'), card(st.hosts.length, 'Hosts')),
    h('h2', {}, 'Expiry timeline', h('span', { class: 'spacer' }),
      h('span', { class: 'muted small', text: st.lastMaintenance ? `Last rotation pass ${ago(st.lastMaintenance)}` : '' })),
    sorted.length === 0
      ? h('div', { class: 'panel empty' }, 'No certificates yet. ',
          h('button', { class: 'link', text: 'Create one', onclick: () => certModal() }), ' or add a host and discover what it serves.')
      : h('div', { class: 'panel table-scroll' }, h('table', {},
          h('thead', {}, h('tr', {}, [['Certificate'], ['Names', 'wide-only'], ['Expires', 'wide-only'], ['Valid for'], ['Status', 'wide-only'], ['Deployed']]
            .map(([t, cls]) => h('th', { text: t, class: cls })))),
          h('tbody', {}, sorted.map(c => {
            const cert = c.certificate, deps = st.deployments.filter(d => d.deployment.certificateID === cert.id && d.state.kind !== 'disabled');
            // The web interface counts as one more place it's deployed.
            const total = deps.length + (c.webInterface ? 1 : 0);
            const ok = deps.filter(d => ['current', 'watching'].includes(d.state.kind)).length + (c.webInterface?.serving ? 1 : 0);
            const days = cert.current ? Math.floor((new Date(cert.current.notAfter) - Date.now()) / 86400000) : null;
            return h('tr', {},
              h('td', {}, h('a', { href: `#/certificate/${cert.id}`, text: cert.name })),
              h('td', { class: 'wrap wide-only', text: cert.domains.join(', ') }),
              h('td', { class: 'nowrap wide-only', text: fmtDay(cert.current?.notAfter) }),
              h('td', {}, days === null ? '—' : h('span', { class: 'badge ' + (days < 0 ? 'red' : days <= c.renewalWindow ? 'orange' : 'green'),
                text: days < 0 ? 'Expired' : `${days} days` })),
              h('td', { class: 'wide-only' }, cert.external ? h('span', { class: 'badge purple', text: 'Monitored' }) : h('span', { class: 'badge blue', text: 'Managed' })),
              h('td', { class: 'nowrap', text: total ? `${ok}/${total} current` : '—' }));
          })))),
  ];
}

// ---------- Certificate ----------

function renderCertificate(id) {
  const c = certDTO(id), cert = c.certificate, monitored = cert.external === true;
  const deps = S.state.deployments.filter(d => d.deployment.certificateID === id);
  const cur = cert.current;
  const issued = !!cur && !monitored;
  return [
    h('div', { class: 'page-header' }, h('h1', { text: cert.name }), busySpinner(c.busy), certBadge(c),
      monitored ? null : h('button', { class: 'primary', disabled: c.busy,
        text: c.status.kind === 'notIssued' ? 'Issue' : 'Renew now', title: 'Request a new certificate from Let’s Encrypt now',
        onclick: () => act(() => api('POST', `/api/certificates/${id}/issue`), 'Issuing…') }),
      monitored ? h('button', { disabled: c.busy, text: 'Check now', title: 'Read the certificate in use now',
        onclick: () => act(async () => { for (const d of deps) await api('POST', `/api/deployments/${d.deployment.id}/check`); }, 'Checking…') }) : null,
      issued && c.hasKey ? h('button', { text: 'Export…', title: 'Download the certificate and key in common formats', onclick: () => exportModal(cert) }) : null,
      h('button', { text: 'Edit', title: 'Change names, key type and renewal', onclick: () => certModal(cert) }),
      h('button', { class: 'danger', text: 'Delete', title: 'Delete this certificate, its deployments and its private key',
        onclick: () => confirmModal(`Delete ${cert.name}?`, 'Its deployments and private key are deleted too. Files already installed on hosts stay where they are.',
          'Delete', async () => { await act(() => api('DELETE', `/api/certificates/${id}`), 'Deleted'); location.hash = '#/overview'; }) })),
    cert.lastError ? h('div', { class: 'banner err' }, h('span', { class: 'grow', text: cert.lastError })) : null,
    h('div', { class: 'panel rows' },
      row('Status', certBadge(c)),
      row('Expires', cur ? `${fmtDate(cur.notAfter)} (${Math.floor((new Date(cur.notAfter) - Date.now()) / 86400000)} days)` : '—'),
      row('Issued by', cur?.issuer || '—'),
      row('Names on the certificate', cur ? cur.dnsNames.join(', ') : '—'),
      row('SHA-256', cur ? h('span', { class: 'mono', text: cur.sha256 }) : '—'),
      monitored ? null : row('Last issued', cert.lastIssued ? `${fmtDate(cert.lastIssued)} (${ago(cert.lastIssued)})` : 'never')),
    h('h2', {}, 'Definition'),
    h('div', { class: 'panel rows' },
      row('Names', cert.domains.join(', ')),
      row('Mode', monitored ? 'Monitor only: another system renews it; CertKeeper watches its expiry' : 'Managed: CertKeeper issues, renews and deploys it'),
      monitored ? null : row('Key type', cert.keyAlgorithm),
      monitored ? null : row('Renew automatically', cert.autoRenew ? 'Yes' : 'No'),
      row(monitored ? 'Warn when fewer than' : 'Renew when fewer than',
        `${c.renewalWindow} days remain${cert.renewDaysBeforeExpiry == null ? ' (default)' : ''}`)),
    h('h2', {}, 'Deployments', h('span', { class: 'spacer' }),
      h('button', { text: '+ Add deployment', title: 'Install this certificate on another host',
        onclick: () => deploymentModal(null, { certificateID: id }) })),
    h('div', { class: 'panel' }, (deps.length || c.webInterface) ? [c.webInterface ? webInterfaceItem(c.webInterface) : null, deps.map(d => deploymentItem(d, 'host'))] :
      h('div', { class: 'empty', text: monitored ? 'Nothing to watch yet.' : 'Not deployed anywhere yet. Add a deployment, or discover a host and adopt what it serves.' })),
  ];
}

/// This CertKeeper's own web interface, listed with the deployments of the certificate it serves.
function webInterfaceItem(w) {
  const source = w.chosen ? 'CertKeeper installs and renews it here (Settings › Web interface HTTPS)'
    : w.mode === 'platform' ? 'Provided by the install settings (CERTKEEPER_TLS_CERT)' : 'In use by the web interface';
  return h('div', { class: 'item' },
    h('div', { class: 'body' },
      h('div', { class: 'title', text: 'This CertKeeper · Web interface' }),
      h('div', { class: 'mono muted', text: location.origin }),
      h('div', { class: 'muted small', text: w.serving ? `Serving a certificate expiring ${fmtDay(w.notAfter)}` : 'Switching to the current certificate within a minute' }),
      h('div', { class: 'muted small', text: source })),
    h('div', { class: 'actions' },
      h('span', { class: `badge ${w.serving ? 'green' : 'blue'}`, text: w.serving ? 'Current' : 'Switching' }),
      h('a', { class: 'button', href: '#/settings', text: 'Settings', title: 'Choose the certificate for the web interface' })));
}

function row(k, v) { return h('div', { class: 'row' }, h('div', { class: 'k', text: k }), h('div', { class: 'v' }, v)); }

function deploymentItem(dto, show) {
  const d = dto.deployment, cert = certDTO(d.certificateID)?.certificate, monitored = cert?.external === true;
  const title = show === 'host'
    ? h('a', { href: `#/host/${d.hostID}`, text: hostLabel(d.hostID) })
    : h('a', { href: `#/certificate/${d.certificateID}`, text: certLabel(d.certificateID) });
  const where = d.certPath || d.verifyEndpoint || (d.options?.truenas_apps ? `apps: ${d.options.truenas_apps}` : '');
  const served = d.deployedNotAfter
    ? `Serving a certificate expiring ${fmtDay(d.deployedNotAfter)} · checked ${ago(d.lastChecked)}`
    : (d.lastChecked ? `Checked ${ago(d.lastChecked)}` : 'Not checked yet');
  return h('div', { class: 'item' },
    h('div', { class: 'body' },
      h('div', { class: 'title' }, title, ` · ${KIND_NAME[d.kind] || d.kind}`),
      where ? h('div', { class: 'mono muted', text: where }) : null,
      h('div', { class: 'muted small', text: served }),
      dto.state.detail ? h('div', { class: 'small error-text', text: dto.state.detail }) : null),
    h('div', { class: 'actions' }, busySpinner(dto.busy), deploymentBadge(dto),
      monitored ? null : h('button', { disabled: dto.busy || !d.enabled, text: 'Deploy', title: 'Install the current certificate now',
        onclick: () => act(() => api('POST', `/api/deployments/${d.id}/deploy`), 'Deploying…') }),
      h('button', { disabled: dto.busy, text: 'Check', title: 'Check what the service is serving',
        onclick: () => act(() => api('POST', `/api/deployments/${d.id}/check`), 'Checking…') }),
      h('button', { text: 'Edit', title: 'Edit this deployment', onclick: () => deploymentModal(dto) }),
      h('button', { class: 'danger', text: 'Remove', title: 'Stop managing this deployment (installed files stay)',
        onclick: () => confirmModal('Remove this deployment?', 'CertKeeper stops installing the certificate here. Files already installed stay.',
          'Remove', () => act(() => api('DELETE', `/api/deployments/${d.id}`), 'Removed')) })));
}

// ---------- Host ----------

function renderHost(id) {
  const x = hostDTO(id), host = x.host, device = host.connection === 'device_api';
  const deps = S.state.deployments.filter(d => d.deployment.hostID === id);
  const auth = device ? (x.hasPassword ? 'API token saved' : 'No API token saved')
    : [host.identityFile ? `Key ${host.identityFile}` : 'CertKeeper’s SSH key (or ~/.ssh)', host.passwordLogin ? ', then password' : ''].join('');
  return [
    h('div', { class: 'page-header' }, h('span', { class: `dot ${x.health.level}`, title: x.health.summary }),
      h('h1', { text: host.name }), busySpinner(x.busy),
      h('button', { disabled: x.busy, text: 'Test connection', title: 'Connect and report the system',
        onclick: async () => { const r = await act(() => api('POST', `/api/hosts/${id}/test`)); if (r) messageModal('Connection test', r.message); } }),
      h('button', { disabled: x.busy, text: 'Edit', title: 'Edit the connection settings', onclick: () => hostModal(host, x) }),
      h('button', { class: 'danger', disabled: x.busy, text: 'Delete', title: 'Delete this host, its deployments and its stored password',
        onclick: () => confirmModal(`Delete ${host.name}?`, 'Its deployments and stored password are deleted too. Nothing on the host changes.',
          'Delete', async () => { await act(() => api('DELETE', `/api/hosts/${id}`), 'Deleted'); location.hash = '#/overview'; }) })),
    h('div', { class: 'panel rows' },
      row(device ? 'Device API' : 'SSH', device ? `https://${host.address}:${host.port}` : `${host.username ? host.username + '@' : ''}${host.address}:${host.port}`),
      row('Authentication', auth),
      device ? row('Pinned certificate', host.apiPinnedSHA256 ? h('span', { class: 'mono', text: host.apiPinnedSHA256 }) : 'None (only certificates CertKeeper trusts)') :
        row('Privilege', host.useSudo ? 'sudo (password if required)' : 'As the login user'),
      row('System', host.notes || '—'),
      row('Last contact', host.lastSeen ? ago(host.lastSeen) : 'never'),
      row('Health', x.health.summary)),
    h('h2', {}, 'Discovered certificates', h('span', { class: 'spacer' }),
      h('button', { disabled: x.busy, text: x.busy ? 'Working…' : 'Discover', title: 'Find the certificates this host serves',
        onclick: () => act(() => api('POST', `/api/hosts/${id}/discover`), 'Discovering…') })),
    h('div', { class: 'panel' }, host.lastDiscovery.length
      ? host.lastDiscovery.map((ep, i) => discoveredItem(host, ep, x.endpoints[i]))
      : h('div', { class: 'empty', text: 'Discover to find the certificates this host serves.' })),
    h('h2', {}, 'Managed deployments', h('span', { class: 'spacer' }),
      h('button', { text: '+ Add deployment', title: 'Install a certificate on this host', onclick: () => deploymentModal(null, { hostID: id }) })),
    h('div', { class: 'panel' }, deps.length ? deps.map(d => deploymentItem(d, 'certificate')) :
      h('div', { class: 'empty', text: 'Nothing managed on this host yet.' })),
  ];
}

function discoveredItem(host, ep, info) {
  const s = ep.summary;
  const facts = s ? [s.dnsNames.join(', '), `expires ${fmtDay(s.notAfter)}`, s.issuer].filter(Boolean).join(' · ') : 'No certificate read';
  let control;
  if (info?.managed) {
    control = h('span', { class: 'badge green', text: '✓ Managed' });
  } else {
    const automatic = info?.automatic ? `Automatic (use ${certLabel(info.automatic)})` : 'Automatic (new certificate)';
    const select = h('select', { 'aria-label': 'Adopt as' },
      h('option', { value: 'automatic', text: automatic }),
      h('option', { value: 'new', text: 'New certificate for these names' }),
      (info?.candidates || []).map(c => h('option', { value: `existing:${c.id}`, text: `Use ${c.name} (${c.coverage})` })),
      h('option', { value: 'monitor', text: 'Monitor only (another system renews it)' }));
    control = h('div', { class: 'inline' }, select,
      h('button', { text: 'Adopt', title: 'Start managing this certificate',
        onclick: () => {
          const [target, certificateID] = select.value.split(':');
          act(() => api('POST', `/api/hosts/${host.id}/adopt`, { endpointID: info.id, target, certificateID }), 'Adopted');
        } }));
  }
  return h('div', { class: 'item' },
    h('div', { class: 'body' },
      h('div', { class: 'title', text: `${KIND_NAME[ep.kind] || ep.kind} — ${ep.label}` }),
      ep.certPath ? h('div', { class: 'mono muted', text: ep.certPath }) : null,
      h('div', { class: 'muted small', text: facts }),
      ep.note ? h('div', { class: 'small', text: ep.note }) : null),
    h('div', { class: 'actions' }, control));
}

// ---------- Activity ----------

function renderActivity() {
  const log = S.state.log;
  const color = { info: 'blue', success: 'green', warning: 'orange', error: 'red' };
  return [
    h('div', { class: 'page-header' }, h('h1', { text: 'Activity' }),
      h('button', { class: 'danger', disabled: !log.length, text: 'Clear', title: 'Delete every log entry',
        onclick: () => confirmModal('Clear the activity log?', 'Every entry is deleted.', 'Clear',
          () => act(() => api('DELETE', '/api/log'), 'Cleared')) })),
    h('div', { class: 'panel log' }, log.length ? log.map(e => h('div', { class: 'item' },
      h('div', { class: 'log-level' }, h('span', { class: `badge ${color[e.level] || 'grey'}`, text: e.level })),
      h('div', { class: 'body' }, h('div', { text: e.message }), e.detail ? h('pre', { text: e.detail }) : null),
      h('div', { class: 'muted small', text: fmtDate(e.date) }))) : h('div', { class: 'empty', text: 'Nothing yet.' })),
    log.length >= 300 ? h('p', { class: 'muted small', text: 'Showing the latest 300 entries.' }) : null,
  ];
}

// ---------- Settings ----------

function renderSettings() {
  const st = S.state, set = { ...st.settings }, srv = st.server;
  const email = h('input', { type: 'email', value: set.acmeEmail, placeholder: 'you@example.com' });
  const staging = h('input', { type: 'checkbox', checked: set.useStaging });
  const tos = h('input', { type: 'checkbox', checked: set.acceptedTermsOfService });
  const renewDays = h('input', { type: 'number', min: 1, max: 60, value: set.renewDaysBeforeExpiry });
  const interval = h('input', { type: 'number', min: 1, max: 168, value: set.checkIntervalHours });
  const autoDeploy = h('input', { type: 'checkbox', checked: set.autoDeploy });
  const dnsTimeout = h('input', { type: 'number', min: 30, max: 3600, value: set.dnsPropagationTimeout });
  const retention = h('input', { type: 'number', min: 1, max: 365, value: set.logRetentionDays ?? 90 });
  const saveSettings = () => act(() => api('PUT', '/api/settings', {
    ...set, acmeEmail: email.value.trim(), useStaging: staging.checked, acceptedTermsOfService: tos.checked,
    renewDaysBeforeExpiry: +renewDays.value, checkIntervalHours: +interval.value, autoDeploy: autoDeploy.checked,
    dnsPropagationTimeout: +dnsTimeout.value, logRetentionDays: +retention.value,
  }), 'Settings saved');

  const token = h('input', { type: 'password', autocomplete: 'off', placeholder: st.hasCloudflareToken ? '•••••••• (saved)' : 'Cloudflare API token' });
  const verifyOut = h('div', { class: 'small' });

  const tls = srv.tls;
  const certChoices = st.certificates.filter(c => c.certificate.external !== true);
  const serverCert = h('select', { disabled: srv.tlsPlatformProvided },
    h('option', { value: '', text: 'Self-signed (made by CertKeeper)' }),
    certChoices.map(c => h('option', { value: c.certificate.id, text: c.certificate.name, selected: srv.serverCertificateID === c.certificate.id })));

  const current = h('input', { type: 'password', autocomplete: 'current-password' });
  const next = h('input', { type: 'password', autocomplete: 'new-password' });
  const importInput = h('input', { type: 'file', accept: '.json,application/json' });
  const exportPassword = h('input', { type: 'password', autocomplete: 'new-password', placeholder: 'Leave empty to leave secrets out' });

  return [
    h('div', { class: 'page-header' }, h('h1', { text: 'Settings' })),

    h('h2', {}, 'Let’s Encrypt'),
    h('div', { class: 'panel section-pad' },
      field('Account email', email, 'Let’s Encrypt sends expiry warnings here.'),
      check(staging, 'Use the staging environment', 'For testing: staging certificates aren’t trusted by browsers but don’t count against rate limits.'),
      check(tos, h('span', {}, 'I accept the ', h('a', { href: 'https://letsencrypt.org/repository/', target: '_blank', rel: 'noopener', text: 'Let’s Encrypt Subscriber Agreement' }))),
      h('div', { class: 'form-grid' },
        field('Renew when fewer than (days)', renewDays, 'Default for certificates without their own setting.'),
        field('Rotation pass every (hours)', interval),
        field('DNS propagation timeout (seconds)', dnsTimeout, 'How long to wait for the challenge record in public DNS.'),
        field('Keep activity for (days)', retention)),
      check(autoDeploy, 'Deploy renewed certificates automatically'),
      h('div', { class: 'form-actions' }, h('button', { class: 'primary', text: 'Save', onclick: saveSettings }))),

    h('h2', {}, 'Cloudflare'),
    h('div', { class: 'panel section-pad' },
      field('API token', token, 'A token with Zone › DNS › Edit for the zones you issue certificates in. It’s stored encrypted.'),
      verifyOut,
      h('div', { class: 'form-actions' },
        st.hasCloudflareToken ? h('button', { class: 'danger', text: 'Remove', onclick: () =>
          confirmModal('Remove the Cloudflare token?', 'Issuing and renewing stop until a new token is saved.', 'Remove',
            () => act(() => api('DELETE', '/api/cloudflare'), 'Token removed')) }) : null,
        h('button', { text: 'Verify', title: 'Check the token with Cloudflare and list its zones', onclick: async () => {
          clear(verifyOut).append(h('span', { class: 'muted', text: 'Checking…' }));
          try {
            const r = await api('POST', '/api/cloudflare/verify', { token: token.value });
            clear(verifyOut).append(h('span', { class: r.ok ? '' : 'error-text', text: r.message + (r.zones.length ? ` · zones: ${r.zones.join(', ')}` : '') }));
          } catch (e) { clear(verifyOut).append(h('span', { class: 'error-text', text: e.message })); }
        } }),
        h('button', { class: 'primary', text: 'Save token', onclick: async () => {
          if (await act(() => api('PUT', '/api/cloudflare', { token: token.value }), 'Token saved')) { token.value = ''; rerenderSettings(); }
        } }))),

    h('h2', {}, 'Web interface HTTPS'),
    h('div', { class: 'panel section-pad' },
      tls ? h('div', { class: 'rows' },
        row('Serving', `${tls.subject} · expires ${fmtDay(tls.notAfter)}`),
        row('Source', { platform: 'The certificate from the install settings', managed: 'A certificate CertKeeper manages', self_signed: 'Self-signed (browsers will warn)' }[tls.mode] || tls.mode),
        row('SHA-256', h('span', { class: 'mono', text: tls.sha256 }))) : null,
      srv.tlsPlatformProvided
        ? h('p', { class: 'muted small', text: 'The certificate comes from the install settings (CERTKEEPER_TLS_CERT); change it there.' })
        : [field('Certificate for this interface', serverCert,
            'Issue a certificate for CertKeeper’s own name, then pick it here. It’s renewed with the others and applies without a restart.'),
          h('div', { class: 'form-actions' }, h('button', { class: 'primary', text: 'Use this certificate', onclick: () =>
            act(() => api('PUT', '/api/server-certificate', { certificateID: serverCert.value || null }), 'Saved — reload the page if the browser asks')
              .then(rerenderSettings) }))]),

    h('h2', {}, 'SSH key'),
    h('div', { class: 'panel section-pad' },
      srv.sshPublicKey
        ? [h('p', { class: 'small muted', text: 'Hosts that should trust CertKeeper list this public key in ~/.ssh/authorized_keys for the user CertKeeper logs in as.' }),
          h('textarea', { readonly: true, rows: 3, text: srv.sshPublicKey }),
          h('div', { class: 'form-actions' }, h('button', { text: 'Copy', onclick: () => navigator.clipboard.writeText(srv.sshPublicKey).then(() => toast('Copied')) }))]
        : h('p', { class: 'muted small', text: 'CertKeeper uses the SSH keys in its home folder.' })),

    h('h2', {}, 'Configuration'),
    h('div', { class: 'panel section-pad' },
      field('Export', exportPassword, 'With a password, the file also holds the Cloudflare token, ACME key, private keys and host passwords, encrypted with it.'),
      h('div', { class: 'form-actions' }, h('button', { text: 'Export configuration…', onclick: async () => {
        const f = await act(() => api('POST', '/api/config/export', { password: exportPassword.value || null }));
        if (f) { download(f); exportPassword.value = ''; }
      } })),
      field('Import', importInput, 'Replaces the current hosts, certificates and deployments (a backup is saved first).'),
      h('div', { class: 'form-actions' }, h('button', { text: 'Import…', onclick: () => importFlow(importInput) }))),

    h('h2', {}, 'Account'),
    h('div', { class: 'panel section-pad' },
      h('p', { class: 'muted small', text: `Signed in as ${srv.username || ''}.` }),
      h('div', { class: 'form-grid' }, field('Current password', current), field('New password', next, 'At least 10 characters.')),
      h('div', { class: 'form-actions' },
        h('button', { text: 'Sign out', onclick: async () => { await api('POST', '/api/logout').catch(() => {}); S.session = { signedIn: false }; S.state = null; render(); } }),
        h('button', { class: 'primary', text: 'Change password', onclick: async () => {
          if (await act(() => api('POST', '/api/password', { current: current.value, new: next.value }), 'Password changed')) { current.value = ''; next.value = ''; }
        } }))),

    h('h2', {}, 'About'),
    h('div', { class: 'panel section-pad about' }, h('img', { src: 'icon.svg', alt: '' }),
      h('div', {},
        h('div', {}, h('b', { text: `CertKeeper ${st.version}` })),
        h('div', { class: 'muted small', text: 'Issues Let’s Encrypt certificates through Cloudflare DNS and keeps them current on your servers and devices. Free software under the Apache License 2.0. Copyright © 2026 Mike Waters.' }),
        h('div', { class: 'small' }, h('a', { href: REPO, target: '_blank', rel: 'noopener', text: 'Source code' }), ' · ',
          h('a', { href: `${REPO}/issues`, target: '_blank', rel: 'noopener', text: 'Report a problem' })),
        h('p', { class: 'muted small', text: 'CertKeeper is a free, one-person project. If it saves you time, you can support it:' }),
        h('a', { class: 'coffee', href: COFFEE, target: '_blank', rel: 'noopener', text: '☕ Buy me a coffee' }),
        h('p', { class: 'muted small', text: `Data in ${srv.configDirectory} · secrets key from ${srv.secretsKeySource}` }))),
  ];
}

function rerenderSettings() { if (route().page === 'settings') renderApp(true); }

function field(label, input, help) {
  return h('div', { class: 'field' }, h('label', {}, label), input, help ? h('div', { class: 'help', text: help }) : null);
}

function check(input, label, help) {
  return h('label', { class: 'check' }, input, h('span', {}, label, help ? h('div', { class: 'help muted small', text: help }) : null));
}

function download(file) {
  const bytes = Uint8Array.from(atob(file.data), ch => ch.charCodeAt(0));
  const url = URL.createObjectURL(new Blob([bytes], { type: 'application/octet-stream' }));
  const a = h('a', { href: url, download: file.name });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10000);
}

function readFileBase64(file) {
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => resolve(String(r.result).split(',')[1] || '');
    r.onerror = () => reject(new Error('That file couldn’t be read'));
    r.readAsDataURL(file);
  });
}

async function importFlow(input) {
  const file = input.files?.[0];
  if (!file) { toast('Choose a configuration file first', true); return; }
  let data;
  try { data = await readFileBase64(file); } catch (e) { toast(e.message, true); return; }
  const password = h('input', { type: 'password', autocomplete: 'off', placeholder: 'The export password, or leave empty to skip secrets' });
  const out = h('div', { class: 'small' });
  const close = modal('Import configuration', [
    field('Password', password, 'Needed only if the file was exported with secrets.'),
    out,
    h('div', { class: 'form-actions' },
      h('button', { text: 'Cancel', onclick: () => close() }),
      h('button', { class: 'primary', text: 'Continue', onclick: async () => {
        try {
          const s = await api('POST', '/api/config/import', { file: data, password: password.value || null });
          const cur = S.state;
          clear(out).append(h('p', { text: `The file (exported ${fmtDate(s.exportedAt)}) has ${s.hosts} hosts, ${s.certificates} certificates and ${s.deployments} deployments` +
            (s.secretsInFile ? `, and ${s.secretsImported} of ${s.secretsInFile} secrets will be imported.` : ', without secrets.') +
            ` It replaces the current ${cur.hosts.length} hosts, ${cur.certificates.length} certificates and ${cur.deployments.length} deployments. A backup is saved first.` }),
            h('div', { class: 'form-actions' }, h('button', { class: 'primary danger', text: 'Replace configuration', onclick: async () => {
              const done = await act(() => api('POST', '/api/config/import', { file: data, password: password.value || null, confirm: true }), 'Configuration imported');
              if (done) { close(); messageModal('Configuration imported', done.message || 'Done.'); input.value = ''; }
            } })));
        } catch (e) { clear(out).append(h('p', { class: 'error-text', text: e.message })); }
      } })),
  ]);
}

// ---------- Modals ----------

function modal(title, content) {
  const root = document.getElementById('modal-root');
  const backdrop = h('div', { class: 'modal-backdrop' }, h('div', { class: 'modal', role: 'dialog', 'aria-modal': 'true' }, h('h3', { text: title }), content));
  const close = () => { backdrop.remove(); document.removeEventListener('keydown', onKey); };
  const onKey = e => { if (e.key === 'Escape') close(); };
  backdrop.addEventListener('mousedown', e => { if (e.target === backdrop) close(); });
  document.addEventListener('keydown', onKey);
  root.append(backdrop);
  backdrop.querySelector('input, select, textarea')?.focus();
  return close;
}

function confirmModal(title, text, verb, onConfirm) {
  const close = modal(title, [h('p', { text }), h('div', { class: 'form-actions' },
    h('button', { text: 'Cancel', onclick: () => close() }),
    h('button', { class: 'primary', text: verb, onclick: async () => { close(); await onConfirm(); } }))]);
}

function messageModal(title, text) {
  const close = modal(title, [h('pre', { class: 'mono', style: null, text }), h('div', { class: 'form-actions' },
    h('button', { class: 'primary', text: 'OK', onclick: () => close() }))]);
}

function certModal(cert) {
  const name = h('input', { type: 'text', value: cert?.name || '', placeholder: 'Defaults to the first name' });
  const domains = h('textarea', { rows: 3, text: (cert?.domains || []).join('\n'), placeholder: 'nas.example.com\n*.lab.example.com' });
  const key = h('select', {}, KEY_TYPES.map(k => h('option', { value: k, text: k, selected: (cert?.keyAlgorithm || 'ECDSA P-256') === k })));
  const auto = h('input', { type: 'checkbox', checked: cert ? cert.autoRenew : true });
  const days = h('input', { type: 'number', min: 1, max: 60, value: cert?.renewDaysBeforeExpiry ?? '', placeholder: `Default (${S.state.settings.renewDaysBeforeExpiry})` });
  const monitor = h('input', { type: 'checkbox', checked: cert?.external === true });
  const close = modal(cert ? `Edit ${cert.name}` : 'New certificate', [
    field('Names', domains, 'One per line (or comma separated). Wildcards use DNS-01 via Cloudflare.'),
    field('Display name', name),
    h('div', { class: 'form-grid' }, field('Key type', key), field('Renew when fewer than (days)', days)),
    check(auto, 'Renew automatically'),
    check(monitor, 'Monitor only', 'Another system renews this certificate; CertKeeper only watches its expiry.'),
    h('div', { class: 'form-actions' },
      h('button', { text: 'Cancel', onclick: () => close() }),
      h('button', { class: 'primary', text: cert ? 'Save' : 'Create', onclick: async () => {
        const body = { name: name.value, domains: domains.value.split(/[\s,]+/).filter(Boolean), keyAlgorithm: key.value,
          autoRenew: auto.checked, renewDaysBeforeExpiry: days.value ? +days.value : null, monitorOnly: monitor.checked };
        const r = await act(() => cert ? api('PUT', `/api/certificates/${cert.id}`, body) : api('POST', '/api/certificates', body), cert ? 'Saved' : 'Created');
        if (r) { close(); if (!cert && r.id) location.hash = `#/certificate/${r.id}`; }
      } })),
  ]);
}

function hostModal(host, dto) {
  const isNew = !host;
  const conn = h('select', {}, h('option', { value: 'ssh', text: 'SSH', selected: !host || host.connection === 'ssh' }),
    h('option', { value: 'device_api', text: 'Device API (HTTPS)', selected: host?.connection === 'device_api' }));
  const name = h('input', { type: 'text', value: host?.name || '' });
  const address = h('input', { type: 'text', value: host?.address || '', placeholder: 'pve1.example.com' });
  const port = h('input', { type: 'number', min: 1, max: 65535, value: host?.port || 22 });
  const user = h('input', { type: 'text', value: host?.username ?? 'root' });
  const identity = h('input', { type: 'text', value: host?.identityFile || '', placeholder: 'Leave empty for CertKeeper’s own key' });
  const saved = dto?.hasPassword;
  const password = h('input', { type: 'password', autocomplete: 'off', placeholder: saved ? '•••••••• (saved)' : 'Optional' });
  const removePassword = h('input', { type: 'checkbox' });
  const pwLogin = h('input', { type: 'checkbox', checked: host ? host.passwordLogin : false });
  const sudo = h('input', { type: 'checkbox', checked: host ? host.useSudo : false });
  const token = h('input', { type: 'password', autocomplete: 'off', placeholder: saved ? '•••••••• (saved)' : 'ckd_… from the device’s web settings' });
  const pin = h('input', { type: 'text', value: host?.apiPinnedSHA256 || '', placeholder: 'SHA-256 of the device’s self-signed certificate' });
  const notes = h('input', { type: 'text', value: host?.notes || '' });
  const sshPart = h('div', {},
    h('div', { class: 'form-grid' }, field('Username', user), field('Identity file', identity)),
    field('Password', password, 'For password login and for sudo. Stored encrypted.'),
    saved ? check(removePassword, 'Remove the saved password') : null,
    check(pwLogin, 'Log in with the password when keys don’t work'),
    check(sudo, 'Use sudo', 'Run install steps as root through sudo.'),
    S.state.server.sshPublicKey ? h('p', { class: 'muted small', text: 'To use CertKeeper’s key, add its public key (Settings › SSH key) to the user’s authorized_keys.' }) : null);
  const devicePart = h('div', {},
    field('API token', token, 'From the device’s web settings. Stored encrypted.'),
    h('div', { class: 'field' }, h('label', { text: 'Pinned certificate' }), h('div', { class: 'inline' }, pin,
      h('button', { text: 'Fetch', title: 'Read the fingerprint the device presents now', onclick: async () => {
        try { const r = await api('POST', '/api/fingerprint', { address: address.value.trim(), port: +port.value }); pin.value = r.sha256; toast('Compare it with the one in the device’s settings'); }
        catch (e) { toast(e.message, true); }
      } })), h('div', { class: 'help', text: 'Until a trusted certificate is installed the device serves a self-signed one. Pin it only after checking it matches the fingerprint the device shows.' })));
  const sync = () => {
    const device = conn.value === 'device_api';
    sshPart.classList.toggle('hidden', device);
    devicePart.classList.toggle('hidden', !device);
    if (device && port.value === '22') port.value = '443';
    if (!device && port.value === '443') port.value = '22';
  };
  conn.addEventListener('change', sync);
  const close = modal(isNew ? 'New host' : `Edit ${host.name}`, [
    field('Connection', conn),
    h('div', { class: 'form-grid' }, field('Name', name), field('Address', address)),
    field('Port', port),
    sshPart, devicePart,
    field('Notes', notes),
    h('div', { class: 'form-actions' },
      h('button', { text: 'Cancel', onclick: () => close() }),
      h('button', { class: 'primary', text: isNew ? 'Add host' : 'Save', onclick: async () => {
        const body = { name: name.value, address: address.value, port: +port.value, connection: conn.value, username: user.value,
          identityFile: identity.value, useSudo: sudo.checked, passwordLogin: pwLogin.checked, notes: notes.value, apiPinnedSHA256: pin.value,
          password: removePassword.checked ? '' : ((conn.value === 'device_api' ? token.value : password.value) || null) };
        const r = await act(() => isNew ? api('POST', '/api/hosts', body) : api('PUT', `/api/hosts/${host.id}`, body), isNew ? 'Host added' : 'Saved');
        if (r) { close(); if (isNew && r.id) location.hash = `#/host/${r.id}`; }
      } })),
  ]);
  sync();
}

function deploymentModal(dto, defaults) {
  const d = dto?.deployment;
  const existing = { ...(d?.options || {}) };
  const opt = k => existing[k] ?? ({ truenas_ui: 'true', cert_format: 'pem', pihole_set_domain: 'true' }[k] || '');
  const certSel = h('select', {}, S.state.certificates.map(c => h('option', { value: c.certificate.id, text: c.certificate.name,
    selected: (d?.certificateID || defaults?.certificateID) === c.certificate.id })));
  const hostSel = h('select', {}, S.state.hosts.map(x => h('option', { value: x.host.id, text: x.host.name,
    selected: (d?.hostID || defaults?.hostID) === x.host.id })));
  const kind = h('select', {}, KINDS.map(([k, n]) => h('option', { value: k, text: n, selected: (d?.kind || 'nginx') === k })));
  const certPath = h('input', { type: 'text', value: d?.certPath || '', placeholder: '/etc/ssl/certs/site.pem' });
  const keyPath = h('input', { type: 'text', value: d?.keyPath || '', placeholder: '/etc/ssl/private/site.key' });
  const chainPath = h('input', { type: 'text', value: d?.chainPath || '', placeholder: 'Empty: the full chain goes in the certificate file' });
  const verify = h('input', { type: 'text', value: d?.verifyEndpoint || '', placeholder: 'host.example.com:443 (optional)' });
  const enabled = h('input', { type: 'checkbox', checked: d ? d.enabled : true });
  const pfx = h('input', { type: 'password', autocomplete: 'off', placeholder: dto?.hasPfxPassword ? '•••••••• (saved)' : 'Optional' });
  const customize = h('input', { type: 'checkbox', checked: !!d?.scriptOverride });
  const script = h('textarea', { rows: 8, text: d?.scriptOverride || '', placeholder: '# Runs on the host with $FULLCHAIN and $KEY set\nsystemctl reload myservice' });

  // Options per part; only the parts that apply to the chosen kind are saved.
  const text = (k, ph) => h('input', { type: 'text', value: opt(k), placeholder: ph || '' });
  const box = k => h('input', { type: 'checkbox', checked: opt(k) === 'true' });
  const format = h('select', {}, h('option', { value: 'pem', text: 'PEM (separate certificate and key)', selected: opt('cert_format') === 'pem' }),
    h('option', { value: 'pkcs12', text: 'PKCS#12 (.pfx / .p12)', selected: opt('cert_format') === 'pkcs12' }));
  const o = {
    pihole: { pihole_set_domain: box('pihole_set_domain'), restart_target: text('restart_target', 'Leave empty for a native install') },
    truenas: { truenas_ui: box('truenas_ui'), truenas_apps: text('truenas_apps', 'nextcloud, minio') },
    containerApp: { cert_format: format, restart_target: text('restart_target', 'systemd:unit.service, TrueNAS app, container or Compose project'),
      reload_command: text('reload_command', 'Overrides the restart, e.g. docker exec proxy nginx -s reload') },
    unifiOS: { unifi_dir: text('unifi_dir', 'Leave empty to auto-detect') },
    nginx: { nginx_conf: text('nginx_conf', 'Empty for the system nginx'), nginx_prefix: text('nginx_prefix', 'Optional') },
    owner: { file_owner: text('file_owner', 'user:group, e.g. 568:568 for TrueNAS apps') },
  };
  const certField = field('Certificate file', certPath);
  const keyField = field('Private key file', keyPath);
  const chainField = field('Chain file (optional)', chainPath);
  const pfxField = field('PKCS#12 password', pfx);
  const parts = {
    files: h('div', {}, certField, keyField, chainField),
    pihole: h('div', {}, check(o.pihole.pihole_set_domain, 'Set Pi-hole’s web domain to the certificate’s first name'),
      field('Docker container', o.pihole.restart_target)),
    truenas: h('div', {}, check(o.truenas.truenas_ui, 'Use for the TrueNAS web UI'), field('Catalog apps', o.truenas.truenas_apps)),
    containerApp: h('div', {}, field('File format', format), pfxField, field('Restart', o.containerApp.restart_target),
      field('Reload command (optional)', o.containerApp.reload_command)),
    unifiOS: h('div', {}, field('unifi-core folder', o.unifiOS.unifi_dir)),
    nginx: h('div', { class: 'form-grid' }, field('nginx config (-c)', o.nginx.nginx_conf), field('nginx prefix (-p)', o.nginx.nginx_prefix)),
    owner: h('div', {}, field('File owner (optional)', o.owner.file_owner)),
  };
  const activeParts = k => [k in o ? k : null, FILE_KINDS.has(k) ? 'owner' : null].filter(Boolean);
  const sync = () => {
    const k = kind.value;
    parts.files.classList.toggle('hidden', !FILE_KINDS.has(k));
    certField.querySelector('label').textContent = k === 'pihole' ? 'TLS file' : 'Certificate file';
    keyField.classList.toggle('hidden', k === 'pihole');
    chainField.classList.toggle('hidden', k === 'pihole');
    for (const name of ['pihole', 'truenas', 'containerApp', 'unifiOS', 'nginx', 'owner']) parts[name].classList.toggle('hidden', !activeParts(k).includes(name));
    pfxField.classList.toggle('hidden', format.value !== 'pkcs12');
    if (k === 'custom') customize.checked = true;
    script.classList.toggle('hidden', !customize.checked);
    if (k === 'pihole' && !certPath.value) certPath.value = '/etc/pihole/tls.pem';
  };
  kind.addEventListener('change', sync);
  format.addEventListener('change', sync);
  customize.addEventListener('change', sync);

  const close = modal(d ? 'Edit deployment' : 'New deployment', [
    h('div', { class: 'form-grid' }, field('Certificate', certSel), field('Host', hostSel)),
    field('Target', kind, 'The kind of service, which decides how the certificate is installed.'),
    parts.files, parts.pihole, parts.truenas, parts.containerApp, parts.unifiOS, parts.nginx, parts.owner,
    field('Verify TLS endpoint', verify, 'Where to check the served certificate. Empty: read it on the host.'),
    check(enabled, 'Enabled', 'Disabled deployments are never checked or deployed.'),
    check(customize, 'Customize install script', 'Replace the built-in install steps for this deployment with your own script.'),
    script,
    h('div', { class: 'form-actions' },
      h('button', { text: 'Cancel', onclick: () => close() }),
      h('button', { class: 'primary', text: d ? 'Save' : 'Add', onclick: async () => {
        const k = kind.value;
        // Keep options the form doesn't show (discovery's verify_port, generic, …); drop other kinds' ones.
        const shown = new Set(Object.values(o).flatMap(Object.keys));
        const options = Object.fromEntries(Object.entries(existing).filter(([key]) => !shown.has(key)));
        for (const part of activeParts(k)) {
          for (const [key, el] of Object.entries(o[part])) options[key] = el.type === 'checkbox' ? String(el.checked) : el.value;
        }
        const files = FILE_KINDS.has(k), separate = files && k !== 'pihole';
        const body = { certificateID: certSel.value, hostID: hostSel.value, kind: k,
          certPath: files ? certPath.value : '', keyPath: separate ? keyPath.value : '', chainPath: separate ? chainPath.value : '',
          verifyEndpoint: verify.value, enabled: enabled.checked, options, scriptOverride: customize.checked ? script.value : null,
          pfxPassword: k === 'containerApp' && options.cert_format === 'pkcs12' ? (pfx.value || null) : '' };
        const r = await act(() => d ? api('PUT', `/api/deployments/${d.id}`, body) : api('POST', '/api/deployments', body), d ? 'Saved' : 'Added');
        if (r) close();
      } })),
  ]);
  sync();
}

function exportModal(cert) {
  const format = h('select', {}, EXPORT_FORMATS.map(([v, t]) => h('option', { value: v, text: t })));
  const summary = h('p', { class: 'muted small' });
  const password = h('input', { type: 'password', autocomplete: 'new-password' });
  const legacy = h('input', { type: 'checkbox' });
  const p12 = h('div', {}, field('Password', password, 'Required for PKCS#12.'),
    check(legacy, 'Legacy encryption (3DES, SHA-1)', 'For older systems, such as Windows Server 2016 and earlier, that can’t read AES-encrypted files.'));
  const sync = () => {
    summary.textContent = EXPORT_FORMATS.find(f => f[0] === format.value)[2];
    p12.classList.toggle('hidden', format.value !== 'pkcs12');
  };
  format.addEventListener('change', sync);
  const close = modal(`Export ${cert.name}`, [
    field('Format', format), summary, p12,
    h('p', { class: 'small', text: 'The download includes the private key. Keep it safe.' }),
    h('div', { class: 'form-actions' },
      h('button', { text: 'Cancel', onclick: () => close() }),
      h('button', { class: 'primary', text: 'Download', onclick: async () => {
        try {
          const files = await api('POST', `/api/certificates/${cert.id}/export`, { format: format.value, password: password.value || null, legacy: legacy.checked });
          files.forEach((f, i) => setTimeout(() => download(f), i * 300));
          close();
        } catch (e) { toast(e.message, true); }
      } })),
  ]);
  sync();
}

// ---------- Sign-in ----------

function renderAuth() {
  const setup = S.session.needsSetup;
  const code = h('input', { type: 'text', autocomplete: 'off', placeholder: 'XXXX-XXXX-XXXX' });
  const user = h('input', { type: 'text', autocomplete: 'username', value: setup ? 'admin' : '' });
  const pass = h('input', { type: 'password', autocomplete: setup ? 'new-password' : 'current-password' });
  const out = h('p', { class: 'error-text small' });
  const submit = async e => {
    e.preventDefault();
    out.textContent = '';
    try {
      S.session = setup
        ? await api('POST', '/api/setup', { code: code.value, username: user.value, password: pass.value })
        : await api('POST', '/api/login', { username: user.value, password: pass.value });
      S.state = null;
      render();
    } catch (err) { out.textContent = err.message; }
  };
  return h('div', { class: 'auth' }, h('form', { class: 'panel', onsubmit: submit },
    h('h1', {}, h('img', { src: 'icon.svg', alt: '' }), setup ? 'Set up CertKeeper' : 'Sign in to CertKeeper'),
    setup ? h('p', { class: 'muted small', text: 'Enter the one-time setup code from CertKeeper’s log (the app’s Logs in TrueNAS), then choose your username and password.' }) : null,
    setup ? field('Setup code', code) : null,
    field('Username', user),
    field('Password', pass, setup ? 'At least 10 characters.' : null),
    out,
    h('div', { class: 'form-actions' }, h('button', { class: 'primary', type: 'submit', text: setup ? 'Create account' : 'Sign in' }))));
}

// ---------- Start ----------

window.addEventListener('hashchange', () => { if (S.state) { renderApp(true); refresh(); } });
(async () => {
  try {
    S.session = await api('GET', '/api/session');
  } catch (e) {
    S.session = { signedIn: false, needsSetup: false };
    toast(e.message, true);
  }
  render();
})();
