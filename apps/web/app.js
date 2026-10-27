/* Veyl console — plain ES2020, no build step, no dependencies.
 *
 * Everything here talks to the same-origin API under /api. The console is a
 * client, not an authority: every permission check it performs is cosmetic, and
 * the server re-checks each one. If this file were replaced with something
 * hostile, the API would still refuse.
 *
 * All server-provided strings are escaped before they reach innerHTML. Banners,
 * TLS subjects, and evidence detail are attacker-influenced data in a security
 * tool, so they are treated as untrusted.
 */
'use strict';

const API = '/api';
const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
const SEVERITY_COLOR = {
  CRITICAL: 'var(--critical)',
  HIGH: 'var(--high)',
  MEDIUM: 'var(--medium)',
  LOW: 'var(--low)',
  INFO: 'var(--info)',
};

const state = {
  token: sessionStorage.getItem('veyl.token') || null,
  me: null,
  filters: { severity: '', status: '', search: '' },
};

/* ------------------------------------------------------------------ utils */

const $ = (sel, root = document) => root.querySelector(sel);

function esc(value) {
  if (value === null || value === undefined) return '';
  return String(value).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

function num(n) {
  return (n === null || n === undefined ? 0 : n).toLocaleString();
}

function plural(count, singular) {
  const n = count || 0;
  return n.toLocaleString() + ' ' + singular + (n === 1 ? '' : 's');
}

function pct(part, total) {
  if (!total) return 0;
  return Math.round((part / total) * 100);
}

function widthClass(percent) {
  const step = Math.max(0, Math.min(100, Math.round(percent / 5) * 5));
  return 'w-' + step;
}

function fmtDate(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toLocaleString(undefined, {
    year: 'numeric', month: 'short', day: '2-digit',
    hour: '2-digit', minute: '2-digit',
  });
}

function relTime(iso) {
  if (!iso) return '—';
  const d = new Date(iso).getTime();
  if (Number.isNaN(d)) return '—';
  const diff = Math.round((Date.now() - d) / 1000);
  if (diff < 60) return 'just now';
  if (diff < 3600) return Math.round(diff / 60) + 'm ago';
  if (diff < 86400) return Math.round(diff / 3600) + 'h ago';
  return Math.round(diff / 86400) + 'd ago';
}

function sevChip(sev) {
  if (!sev) return '<span class="chip chip-neutral">—</span>';
  return '<span class="chip chip-' + esc(sev) + '">' + esc(sev) + '</span>';
}

function statusChip(status) {
  const cls = ['OPEN'].includes(status) ? 'chip-warn'
    : ['RESOLVED', 'COMPLETED'].includes(status) ? 'chip-ok'
    : 'chip-neutral';
  return '<span class="chip ' + cls + '">' + esc(String(status || '').replace(/_/g, ' ')) + '</span>';
}

let toastTimer = null;
function toast(message, kind) {
  const el = $('#toast');
  el.textContent = message;
  el.className = 'toast show' + (kind ? ' ' + kind : '');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { el.className = 'toast'; }, 4200);
}

function emptyState(message) {
  return '<div class="empty">' + esc(message) + '</div>';
}

/* -------------------------------------------------------------- transport */

async function api(path, opts = {}) {
  const method = opts.method || 'GET';
  const headers = {};
  if (opts.body !== undefined) headers['Content-Type'] = 'application/json';
  if (state.token) headers.Authorization = 'Bearer ' + state.token;

  const res = await fetch(API + path, {
    method,
    headers,
    body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
  });

  if (res.status === 401 && state.token) {
    signOut('Your session expired. Sign in again.');
    throw new Error('session expired');
  }

  const type = res.headers.get('content-type') || '';
  const data = type.includes('application/json') ? await res.json() : await res.text();

  if (!res.ok) {
    const detail = data && data.detail;
    let message;
    if (typeof detail === 'string') message = detail;
    else if (detail && typeof detail.message === 'string') message = detail.message;
    else if (detail) message = JSON.stringify(detail);
    else message = res.status + ' ' + res.statusText;
    const err = new Error(message);
    err.status = res.status;
    err.payload = data;
    throw err;
  }
  return data;
}

/* --------------------------------------------------------------- sign in */

function showLoginError(message) {
  const el = $('#login-error');
  el.textContent = message;
  el.hidden = false;
}

function clearLoginError() {
  $('#login-error').hidden = true;
}

async function submitLogin(event) {
  event.preventDefault();
  clearLoginError();

  const email = $('#login-email').value.trim();
  const password = $('#login-password').value;
  const totp = $('#login-totp').value.trim();
  const button = $('#login-submit');
  button.disabled = true;
  button.textContent = 'Signing in…';

  const body = { email, password };
  if (totp) body.totp_code = totp;

  try {
    const pair = await api('/auth/login', { method: 'POST', body });
    state.token = pair.access_token;
    sessionStorage.setItem('veyl.token', pair.access_token);
    $('#login-password').value = '';
    $('#login-totp').value = '';
    await boot();
  } catch (err) {
    const detail = err.payload && err.payload.detail;
    if (err.status === 401 && detail && Array.isArray(detail.methods)) {
      $('#totp-field').hidden = false;
      $('#login-totp').focus();
      showLoginError(
        'Password accepted. This account has a second factor (' +
        detail.methods.join(', ') + '). Enter the code to finish signing in.'
      );
    } else {
      showLoginError(err.message);
    }
  } finally {
    button.disabled = false;
    button.textContent = 'Sign in';
  }
}

function signOut(message) {
  state.token = null;
  state.me = null;
  sessionStorage.removeItem('veyl.token');
  $('#toast').className = 'toast';
  $('#app').classList.add('hidden');
  $('#login').classList.remove('hidden');
  $('#totp-field').hidden = true;
  if (message) showLoginError(message);
}

/* TOTP helper for the local demo. The demo prints a base32 secret; this
 * computes the current code from it so an evaluator does not need an
 * authenticator app to sign in as the demo administrator. It is arithmetic on
 * a value the user already has, and it never leaves the page. */
function base32Decode(input) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const clean = String(input).toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = '';
  for (const ch of clean) {
    const idx = alphabet.indexOf(ch);
    if (idx < 0) continue;
    bits += idx.toString(2).padStart(5, '0');
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }
  return new Uint8Array(bytes);
}

async function totpNow(secret) {
  const key = base32Decode(secret);
  if (!key.length) throw new Error('that does not look like a base32 secret');
  const counter = Math.floor(Date.now() / 30000);
  const buffer = new ArrayBuffer(8);
  const view = new DataView(buffer);
  view.setUint32(0, Math.floor(counter / 0x100000000));
  view.setUint32(4, counter >>> 0);
  const cryptoKey = await crypto.subtle.importKey(
    'raw', key, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']
  );
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', cryptoKey, buffer));
  const offset = mac[mac.length - 1] & 0x0f;
  const binary = ((mac[offset] & 0x7f) << 24)
    | (mac[offset + 1] << 16)
    | (mac[offset + 2] << 8)
    | mac[offset + 3];
  return String(binary % 1000000).padStart(6, '0');
}

/* ------------------------------------------------------------------ boot */

async function boot() {
  if (!state.token) {
    $('#login').classList.remove('hidden');
    $('#app').classList.add('hidden');
    return;
  }
  let me;
  try {
    me = await api('/auth/me');
  } catch (err) {
    if (err.message === 'session expired') return;
    signOut('Could not load your profile: ' + err.message);
    return;
  }
  state.me = me;
  $('#login').classList.add('hidden');
  $('#app').classList.remove('hidden');

  const org = (me.organizations || []).find((o) => o.id === me.active_organization_id)
    || (me.organizations || [])[0];
  $('#org-chip').innerHTML = org
    ? '<strong>' + esc(org.name) + '</strong>' + esc(org.slug)
    : '<strong>No organization</strong>';
  $('#who').innerHTML =
    '<strong>' + esc(me.full_name) + '</strong>' +
    esc(me.email) + ' · ' + esc(me.role || '');

  if (!location.hash) location.hash = '#/dashboard';
  await route();
}

function can(capability) {
  return Boolean(state.me && (state.me.capabilities || []).includes(capability));
}

/* ---------------------------------------------------------------- router */

function parseHash() {
  const raw = location.hash.replace(/^#\/?/, '');
  const parts = raw.split('/').filter(Boolean);
  return { view: parts[0] || 'dashboard', id: parts[1] || null };
}

function setActiveNav(view) {
  document.querySelectorAll('#nav a').forEach((a) => {
    a.classList.toggle('active', a.dataset.view === view);
  });
}

const VIEW_META = {
  dashboard: ['Dashboard', 'Exposure posture at a glance'],
  findings: ['Findings', 'Evidence-backed issues, ranked by risk'],
  assets: ['Assets', 'What Veyl has observed, and what it does not know'],
  scope: ['Scope registry', 'Only authorized targets are ever scanned'],
  changes: ['Exposure changes', 'What changed between scans, and why it matters'],
  paths: ['Attack paths', 'Potential chains, stated as potential'],
  scans: ['Scans', 'Every assessment run, including refused targets'],
  reports: ['Reports', 'Generated artifacts you can hand to someone'],
  audit: ['Audit log', 'Who did what, in order, tamper-evident'],
};

async function route() {
  const { view, id } = parseHash();
  if (!VIEW_META[view]) {
    location.hash = '#/dashboard';
    return;
  }
  setActiveNav(view);
  $('#view-title').textContent = VIEW_META[view][0];
  $('#view-sub').textContent = VIEW_META[view][1];
  const container = $('#view');
  container.innerHTML = '<div class="empty">Loading…</div>';

  try {
    const renderer = {
      dashboard: renderDashboard,
      findings: id ? renderFindingDetail : renderFindings,
      assets: id ? renderAssetDetail : renderAssets,
      scope: renderScope,
      changes: renderChanges,
      paths: renderPaths,
      scans: renderScans,
      reports: renderReports,
      audit: renderAudit,
    }[view];
    const out = await renderer(id);
    container.innerHTML = out.html;
    if (out.after) out.after();
  } catch (err) {
    container.innerHTML = '<div class="card"><h2>Could not load this view</h2><p class="muted">'
      + esc(err.message) + '</p></div>';
  }
}

/* ------------------------------------------------------------- dashboard */

async function renderDashboard() {
  const data = await api('/dashboard');
  const sev = data.findings_by_severity || {};
  const openTotal = data.open_finding_count || 0;

  const stats = [
    ['Assets', num(data.asset_count), num(data.reachable_asset_count) + ' reachable'],
    ['Internet-exposed', num(data.internet_exposed_asset_count), 'declared by the organization'],
    ['Open findings', num(openTotal), (sev.CRITICAL || 0) + ' critical · ' + (sev.HIGH || 0) + ' high'],
    ['Risk-increasing changes', num(data.risk_increasing_changes_30d), 'last 30 days'],
    ['Active attack paths', num(data.active_attack_path_count), 'all stated as potential'],
    ['Scope entries', num(data.scope_entry_count), num(data.authorized_scope_entry_count) + ' authorized now'],
  ];

  const statCards = stats.map(([label, value, note]) =>
    '<div class="stat"><div class="stat-label">' + esc(label) + '</div>'
    + '<div class="stat-value">' + esc(value) + '</div>'
    + '<div class="stat-note">' + esc(note) + '</div></div>'
  ).join('');

  const sevBars = SEVERITIES.map((s) => {
    const count = sev[s] || 0;
    const share = pct(count, openTotal);
    return '<div class="row sev-row">'
      + '<span class="chip chip-' + s + '">' + s + '</span>'
      + '<div class="bar"><div class="bar-fill ' + widthClass(share) + '"></div></div>'
      + '<span class="mono">' + num(count) + '</span>'
      + '</div>';
  }).join('');

  const top = (data.top_findings || []).map((f) =>
    '<tr class="clickable" data-finding="' + esc(f.id) + '">'
    + '<td>' + sevChip(f.severity) + '</td>'
    + '<td><strong>' + esc(f.title) + '</strong><div class="faint mono">' + esc(f.rule_id) + '</div></td>'
    + '<td>' + esc(f.asset_hostname || f.asset_key || '—') + '</td>'
    + '<td class="risk">' + f.risk_score.toFixed(1) + '</td>'
    + '<td>' + statusChip(f.status) + '</td>'
    + '</tr>'
  ).join('');

  const lastScan = data.last_scan;
  const scanCard = lastScan
    ? '<div class="card"><h2>Last scan</h2>'
      + '<div class="row"><strong>' + esc(lastScan.label || lastScan.id.slice(0, 8)) + '</strong>'
      + statusChip(lastScan.status) + '</div>'
      + '<dl class="kv">'
      + '<dt>Finished</dt><dd>' + esc(fmtDate(lastScan.finished_at)) + '</dd>'
      + '<dt>Targets</dt><dd>' + num(lastScan.targets_scanned) + ' of ' + num(lastScan.targets_requested)
      + (lastScan.targets_blocked ? ' · <span class="chip chip-warn">' + num(lastScan.targets_blocked) + ' refused</span>' : '') + '</dd>'
      + '<dt>Found</dt><dd>' + plural(lastScan.assets_found, 'asset') + ', '
      + plural(lastScan.services_found, 'service') + ' identified by name</dd>'
      + '<dt>Results</dt><dd>' + num(lastScan.findings_created) + ' findings, ' + num(lastScan.changes_detected) + ' changes</dd>'
      + '</dl></div>'
    : '<div class="card"><h2>Last scan</h2>' + emptyState('No scan has run yet.') + '</div>';

  return {
    html:
      '<div class="grid grid-3">' + statCards + '</div>'
      + '<div class="section"><div class="grid grid-2">'
      + '<div class="card"><h2>Open findings by severity</h2>'
      + (openTotal ? sevBars : emptyState('No open findings.')) + '</div>'
      + scanCard
      + '</div></div>'
      + '<div class="section"><div class="section-head"><h2>Highest risk findings</h2>'
      + '<a href="#/findings">View all</a></div>'
      + '<div class="table-wrap">'
      + (top
        ? '<table><thead><tr><th>Severity</th><th>Finding</th><th>Asset</th><th>Risk</th><th>Status</th></tr></thead><tbody>' + top + '</tbody></table>'
        : emptyState('Nothing open. That is either good news or a sign no scan has run.'))
      + '</div></div>',
    after: () => bindFindingRows('#view'),
  };
}

/* -------------------------------------------------------------- findings */

function bindFindingRows(root) {
  document.querySelectorAll(root + ' tr[data-finding]').forEach((row) => {
    row.addEventListener('click', () => { location.hash = '#/findings/' + row.dataset.finding; });
  });
}

async function renderFindings() {
  const params = new URLSearchParams({ limit: '100' });
  if (state.filters.severity) params.set('severity', state.filters.severity);
  // "Active only" is the default view, and it must say so: the API defaults to
  // active findings, so an "Any" label here would be a lie about resolved ones.
  if (state.filters.status === '*') params.set('active_only', 'false');
  else if (state.filters.status) params.set('status_filter', state.filters.status);
  if (state.filters.search) params.set('search', state.filters.search);

  const page = await api('/findings?' + params.toString());
  const rows = (page.items || []).map((f) =>
    '<tr class="clickable" data-finding="' + esc(f.id) + '">'
    + '<td>' + sevChip(f.severity) + '</td>'
    + '<td><strong>' + esc(f.title) + '</strong><div class="faint mono">' + esc(f.rule_id) + '</div></td>'
    + '<td>' + esc(f.asset_hostname || f.asset_key || '—') + '</td>'
    + '<td class="risk' + (f.risk_score >= 70 ? ' risk-high' : '') + '">' + f.risk_score.toFixed(1) + '</td>'
    + '<td>' + statusChip(f.status) + '</td>'
    + '<td class="mono">' + num(f.evidence_count) + '</td>'
    + '<td class="faint nowrap">' + esc(relTime(f.last_seen_at)) + '</td>'
    + '</tr>'
  ).join('');

  const options = (values, current, labels = {}) => values.map((v) =>
    '<option value="' + esc(v) + '"' + (v === current ? ' selected' : '') + '>'
    + esc(labels[v] || (v ? v.replace(/_/g, ' ') : 'Any')) + '</option>'
  ).join('');

  return {
    html:
      '<div class="toolbar">'
      + '<select id="f-severity">' + options(['', ...SEVERITIES], state.filters.severity, { '': 'Any severity' }) + '</select>'
      + '<select id="f-status">' + options(
        ['', '*', 'OPEN', 'ACKNOWLEDGED', 'IN_PROGRESS', 'RESOLVED', 'FALSE_POSITIVE'],
        state.filters.status,
        { '': 'Active only', '*': 'All statuses' },
      ) + '</select>'
      + '<input id="f-search" type="search" placeholder="Search title or asset" value="' + esc(state.filters.search) + '">'
      + '<span class="faint">' + num(page.total) + ' matching</span>'
      + '</div>'
      + '<div class="table-wrap">'
      + (rows
        ? '<table><thead><tr><th>Severity</th><th>Finding</th><th>Asset</th><th>Risk</th><th>Status</th><th>Evidence</th><th>Last seen</th></tr></thead><tbody>' + rows + '</tbody></table>'
        : emptyState('No findings match these filters.'))
      + '</div>',
    after: () => {
      bindFindingRows('#view');
      $('#f-severity').addEventListener('change', (e) => {
        state.filters.severity = e.target.value; route();
      });
      $('#f-status').addEventListener('change', (e) => {
        state.filters.status = e.target.value; route();
      });
      let timer = null;
      $('#f-search').addEventListener('input', (e) => {
        clearTimeout(timer);
        const value = e.target.value;
        timer = setTimeout(() => { state.filters.search = value; route(); }, 350);
      });
      // The view is rebuilt after a search, which would otherwise drop the caret
      // out of the box the user is typing in.
      if (state.filters.search) {
        const box = $('#f-search');
        box.focus();
        box.setSelectionRange(box.value.length, box.value.length);
      }
    },
  };
}

async function renderFindingDetail(id) {
  const f = await api('/findings/' + encodeURIComponent(id));

  const evidence = (f.evidence || []).map((e) =>
    '<div class="evidence">'
    + '<div class="evidence-head"><strong>' + esc(e.kind) + '</strong>'
    + '<span class="faint mono">' + esc(e.provenance) + ' · ' + esc(e.confidence) + '</span></div>'
    + '<div>' + esc(e.summary) + '</div>'
    + '<div class="faint mono">observed ' + esc(fmtDate(e.observed_at))
    + ' · matcher ' + esc(e.matcher) + ' · sha256 ' + esc(String(e.checksum).slice(0, 16)) + '…</div>'
    + '<pre>' + esc(JSON.stringify(e.detail, null, 2)) + '</pre>'
    + '</div>'
  ).join('');

  const history = (f.history || []).map((h) =>
    '<div class="row"><span class="faint mono">' + esc(fmtDate(h.created_at)) + '</span>'
    + '<span>' + esc(h.event_type) + '</span>'
    + '<span class="muted">' + esc(h.actor_label) + '</span>'
    + (h.from_value || h.to_value
      ? '<span class="mono">' + esc(h.from_value || '—') + ' → ' + esc(h.to_value || '—') + '</span>' : '')
    + '</div>'
  ).join('');

  const references = (f.references || []).map((r) =>
    '<li><a href="' + esc(r.url || '#') + '" target="_blank" rel="noreferrer noopener">'
    + esc(r.title || r.url || 'reference') + '</a></li>'
  ).join('');

  const vulnRefs = (f.vulnerability_refs || []).length
    ? '<div class="section"><div class="card"><h2>Vulnerability references</h2><pre>'
      + esc(JSON.stringify(f.vulnerability_refs, null, 2)) + '</pre></div></div>'
    : '';

  const STATUS_ACTIONS = [
    ['ACKNOWLEDGED', 'Acknowledge'],
    ['IN_PROGRESS', 'Start work'],
    ['RESOLVED', 'Resolve'],
    ['FALSE_POSITIVE', 'Mark false positive'],
    ['OPEN', 'Reopen'],
  ];

  const statusButtons = can('finding:write')
    ? STATUS_ACTIONS
      .filter(([value]) => value !== f.status)
      .map(([value, label]) => '<button class="btn btn-sm" data-status="' + value + '">' + label + '</button>')
      .join('')
    : '<span class="faint">Your role cannot change finding status.</span>';

  const remediation = f.remediation;
  const remediationForm = can('remediation:write')
    ? '<div class="card"><h2>Remediation</h2>'
      + '<div class="row"><select id="r-owner">'
      + ['ENGINEERING', 'SECURITY_TEAM', 'INFRASTRUCTURE', 'PLATFORM', 'DATA', 'UNASSIGNED']
        .map((o) => '<option value="' + o + '"' + (remediation && remediation.owner === o ? ' selected' : '') + '>' + o + '</option>').join('')
      + '</select>'
      + '<select id="r-priority">'
      + ['LOW', 'MEDIUM', 'HIGH', 'URGENT']
        .map((p) => '<option value="' + p + '"' + (remediation && remediation.priority === p ? ' selected' : '') + '>' + p + '</option>').join('')
      + '</select></div>'
      + '<textarea id="r-notes" placeholder="What is being done about this?">'
      + esc(remediation ? remediation.notes || '' : '') + '</textarea>'
      + '<div class="row"><button class="btn btn-sm" id="r-save">Save remediation</button>'
      + (remediation ? '<span class="faint">Owner: ' + esc(remediation.owner || 'unassigned') + '</span>' : '')
      + '</div></div>'
    : '<div class="card"><h2>Remediation</h2>'
      + (remediation
        ? '<dl class="kv"><dt>Owner</dt><dd>' + esc(remediation.owner || '—') + '</dd>'
          + '<dt>Priority</dt><dd>' + esc(remediation.priority || '—') + '</dd>'
          + '<dt>Notes</dt><dd>' + esc(remediation.notes || '—') + '</dd></dl>'
        : '<p class="muted">Not yet assigned. Your role cannot edit this.</p>')
      + '</div>';

  return {
    html:
      '<div class="detail-head">'
      + sevChip(f.severity)
      + '<h2 class="detail-title">' + esc(f.title) + '</h2>'
      + statusChip(f.status)
      + '</div>'
      + '<p class="muted mono">' + esc(f.rule_id) + ' · ' + esc(f.rule_category) + ' · asset '
      + esc(f.asset_hostname || f.asset_key || f.asset_id) + '</p>'
      + '<div class="detail section">'
      + '<div class="stack">'
      + '<div class="card"><h2>Why this ranks where it does</h2>'
      + '<div class="row"><span class="stat-value">' + f.risk_score.toFixed(1) + '</span>'
      + '<span class="faint">risk score · criticality boost +' + f.criticality_boost.toFixed(1) + '</span></div>'
      + '<p>' + esc(f.risk_explanation) + '</p>'
      + '<pre>' + esc(JSON.stringify(f.risk_factors, null, 2)) + '</pre></div>'

      + '<div class="card"><h2>How Veyl decided this</h2>'
      + '<p>' + esc(f.detection_explanation) + '</p></div>'

      + '<div class="card"><h2>Description</h2><p>' + esc(f.description) + '</p>'
      + '<h2>Impact</h2><p>' + esc(f.impact) + '</p>'
      + '<h2>Remediation guidance</h2><p>' + esc(f.remediation_summary) + '</p>'
      + (references ? '<h2>References</h2><ul>' + references + '</ul>' : '')
      + '</div>'

      + '<div class="card"><h2>Evidence (' + num((f.evidence || []).length) + ')</h2>'
      + '<p class="note">Every claim above traces to one of these records. Each is '
      + 'checksummed at capture time; a finding with no evidence cannot be created.</p>'
      + (evidence || emptyState('No evidence attached — this would be a bug.'))
      + '</div>'

      + (history ? '<div class="card"><h2>History</h2><div class="stack">' + history + '</div></div>' : '')
      + vulnRefs
      + '</div>'

      + '<div class="stack">'
      + '<div class="card"><h2>Actions</h2>'
      + '<div class="row">' + statusButtons + '</div>'
      + '<div class="row section"><a class="btn btn-sm" href="#/findings">Back to findings</a>'
      + '<a class="btn btn-sm" href="#/assets/' + esc(f.asset_id) + '">Open asset</a></div></div>'
      + remediationForm
      + '<div class="card"><h2>Facts</h2><dl class="kv">'
      + '<dt>First seen</dt><dd>' + esc(fmtDate(f.first_seen_at)) + '</dd>'
      + '<dt>Last seen</dt><dd>' + esc(fmtDate(f.last_seen_at)) + '</dd>'
      + '<dt>Reopened</dt><dd>' + num(f.reopen_count) + '×</dd>'
      + '<dt>Confidence</dt><dd>' + esc(f.confidence) + '</dd>'
      + '<dt>Dedup key</dt><dd class="mono">' + esc(f.dedup_key) + '</dd>'
      + '</dl></div>'
      + '</div></div>',
    after: () => {
      document.querySelectorAll('[data-status]').forEach((btn) => {
        btn.addEventListener('click', async () => {
          btn.disabled = true;
          try {
            await api('/findings/' + encodeURIComponent(id) + '/status', {
              method: 'PATCH', body: { status: btn.dataset.status },
            });
            toast('Status changed to ' + btn.dataset.status.replace(/_/g, ' ').toLowerCase(), 'ok');
            route();
          } catch (err) {
            toast(err.message, 'error');
            btn.disabled = false;
          }
        });
      });
      const save = $('#r-save');
      if (save) {
        save.addEventListener('click', async () => {
          save.disabled = true;
          try {
            await api('/findings/' + encodeURIComponent(id) + '/remediation', {
              method: 'PUT',
              body: {
                owner: $('#r-owner').value,
                priority: $('#r-priority').value,
                notes: $('#r-notes').value || null,
              },
            });
            toast('Remediation saved', 'ok');
            route();
          } catch (err) {
            toast(err.message, 'error');
            save.disabled = false;
          }
        });
      }
    },
  };
}

/* ---------------------------------------------------------------- assets */

async function renderAssets() {
  const page = await api('/assets?limit=100');
  const rows = (page.items || []).map((a) =>
    '<tr class="clickable" data-asset="' + esc(a.id) + '">'
    + '<td><strong>' + esc(a.hostname || a.asset_key) + '</strong>'
    + (a.ip_address && a.ip_address !== (a.hostname || a.asset_key)
      ? '<div class="faint mono">' + esc(a.ip_address) + '</div>' : '') + '</td>'
    + '<td>' + esc(a.environment) + '</td>'
    + '<td>' + esc(a.business_criticality) + '</td>'
    + '<td>' + (a.reachable ? '<span class="chip chip-ok">reachable</span>' : '<span class="chip chip-neutral">no answer</span>') + '</td>'
    + '<td>' + (a.internet_exposed ? '<span class="chip chip-warn">declared exposed</span>' : '<span class="faint">—</span>') + '</td>'
    + '<td>' + num(a.open_finding_count) + '</td>'
    + '<td>' + sevChip(a.highest_severity) + '</td>'
    + '<td class="faint nowrap">' + esc(relTime(a.last_seen)) + '</td>'
    + '</tr>'
  ).join('');

  return {
    html: '<div class="table-wrap">'
      + (rows
        ? '<table><thead><tr><th>Asset</th><th>Environment</th><th>Criticality</th><th>Observed</th>'
          + '<th>Internet</th><th>Open findings</th><th>Highest</th><th>Last seen</th></tr></thead><tbody>'
          + rows + '</tbody></table>'
        : emptyState('No assets yet. Run a scan against an authorized scope entry.'))
      + '</div>',
    after: () => {
      document.querySelectorAll('#view tr[data-asset]').forEach((row) => {
        row.addEventListener('click', () => { location.hash = '#/assets/' + row.dataset.asset; });
      });
    },
  };
}

async function renderAssetDetail(id) {
  const a = await api('/assets/' + encodeURIComponent(id));

  const services = (a.services || []).map((s) =>
    '<tr><td class="mono">' + num(s.port) + '/' + esc(s.protocol) + '</td>'
    + '<td><strong>' + esc(s.service_name || 'unknown') + '</strong>'
    + (s.product ? '<div class="faint">' + esc(s.product) + (s.version ? ' ' + esc(s.version) : '') + '</div>' : '') + '</td>'
    + '<td>' + esc(s.fingerprint_confidence) + '</td>'
    + '<td>' + [s.is_encrypted ? 'encrypted' : null, s.is_administrative ? 'admin' : null, s.is_database ? 'database' : null]
      .filter(Boolean).map((t) => '<span class="chip chip-neutral">' + t + '</span>').join(' ') + '</td>'
    + '<td class="mono faint">' + esc((s.banner || '').slice(0, 60) || '—') + '</td></tr>'
  ).join('');

  const serviceEvidence = (a.services || []).filter((s) => (s.fingerprint_evidence || []).length)
    .map((s) => '<div class="evidence"><div class="evidence-head"><strong>'
      + num(s.port) + '/' + esc(s.protocol) + ' → ' + esc(s.service_name || 'unknown') + '</strong>'
      + '<span class="faint">' + esc(s.fingerprint_confidence) + '</span></div>'
      + s.fingerprint_evidence.map((e) =>
        '<div class="faint">' + esc(e.method || 'observation') + ': ' + esc(e.detail || '') + '</div>').join('')
      + '</div>').join('');

  const certs = (a.certificates || []).map((c) =>
    '<div class="evidence"><div class="evidence-head"><strong>' + esc(c.subject || 'certificate') + '</strong>'
    + (c.is_expired ? '<span class="chip chip-CRITICAL">expired</span>'
      : c.is_self_signed ? '<span class="chip chip-MEDIUM">self-signed</span>' : '') + '</div>'
    + '<div class="faint">issuer ' + esc(c.issuer || '—') + ' · expires ' + esc(fmtDate(c.not_after))
    + (c.days_until_expiry !== null && c.days_until_expiry !== undefined ? ' (' + c.days_until_expiry + ' days)' : '')
    + ' · ' + esc(c.signature_algorithm || '—') + ' ' + (c.key_size || '') + '</div>'
    + ((c.hostnames || []).length ? '<div class="mono faint">' + esc(c.hostnames.join(', ')) + '</div>' : '')
    + '</div>').join('');

  return {
    html:
      '<div class="detail-head"><h2 class="detail-title">' + esc(a.hostname || a.asset_key) + '</h2>'
      + (a.reachable ? '<span class="chip chip-ok">reachable</span>' : '<span class="chip chip-neutral">no answer</span>')
      + (a.internet_exposed ? '<span class="chip chip-warn">declared internet-exposed</span>' : '')
      + '</div>'
      + '<p class="muted mono">' + esc(a.ip_address || '') + ' · ' + esc(a.asset_type) + ' · ' + esc(a.environment)
      + ' · discovered via ' + esc(a.discovery_source) + '</p>'
      + '<div class="detail section">'
      + '<div class="stack">'
      + '<div class="card"><h2>Services (' + num((a.services || []).length) + ')</h2>'
      + ((a.services || []).length
        ? '<table><thead><tr><th>Port</th><th>Service</th><th>Fingerprint</th><th>Flags</th><th>Banner</th></tr></thead><tbody>'
          + services + '</tbody></table>'
        : emptyState('No open services observed.'))
      + '</div>'
      + ((a.services || []).some((s) => (s.fingerprint_evidence || []).length)
        ? '<div class="card"><h2>Fingerprint evidence</h2>' + serviceEvidence + '</div>' : '')
      + ((a.certificates || []).length
        ? '<div class="card"><h2>Certificates</h2>' + certs + '</div>' : '')
      + '</div>'

      + '<div class="stack">'
      + '<div class="card"><h2>Business context</h2>'
      + '<p class="note">Source: <strong>' + esc(a.context_source) + '</strong>. '
      + (a.context_source === 'USER_PROVIDED'
        ? 'A human asserted this.'
        : a.context_source === 'OBSERVED' ? 'Veyl observed this directly.'
        : 'Inferred, not confirmed — treat accordingly.') + '</p>'
      + '<dl class="kv">'
      + '<dt>Criticality</dt><dd>' + esc(a.business_criticality) + '</dd>'
      + '<dt>Data class</dt><dd>' + esc(a.data_classification) + '</dd>'
      + '<dt>Function</dt><dd>' + esc(a.business_function) + '</dd>'
      + '<dt>Owner</dt><dd>' + esc(a.owner) + '</dd>'
      + '<dt>Open findings</dt><dd>' + num(a.open_finding_count) + '</dd>'
      + '<dt>Authorization</dt><dd>' + esc(a.authorization_status) + '</dd>'
      + '<dt>First seen</dt><dd>' + esc(fmtDate(a.first_seen)) + '</dd>'
      + '<dt>Last seen</dt><dd>' + esc(fmtDate(a.last_seen)) + '</dd>'
      + '</dl>'
      + (can('finding:write')
        ? '<div class="row section"><button class="btn btn-sm" id="rescore">Recompute risk scores</button></div>'
        : '')
      + '</div>'
      + '<div class="card"><h2>Navigate</h2><div class="row">'
      + '<a class="btn btn-sm" href="#/assets">All assets</a>'
      + '<a class="btn btn-sm" href="#/findings">Findings</a></div></div>'
      + '</div></div>',
    after: () => {
      const rescore = $('#rescore');
      if (rescore) {
        rescore.addEventListener('click', async () => {
          rescore.disabled = true;
          try {
            const result = await api('/assets/' + encodeURIComponent(id) + '/rescore', { method: 'POST' });
            toast('Rescored ' + num(result.findings_rescored) + ' finding(s)', 'ok');
            route();
          } catch (err) {
            toast(err.message, 'error');
            rescore.disabled = false;
          }
        });
      }
    },
  };
}

/* ----------------------------------------------------------------- scope */

async function renderScope() {
  const page = await api('/scope?limit=200');
  const rows = (page.items || []).map((s) =>
    '<tr>'
    + '<td><strong class="mono">' + esc(s.domain) + '</strong>'
    + (s.cidr ? '<div class="faint mono">' + esc(s.cidr) + '</div>' : '') + '</td>'
    + '<td>' + esc(s.environment) + '</td>'
    + '<td>' + esc(s.asset_owner) + '</td>'
    + '<td>' + (s.is_authorized_now
      ? '<span class="chip chip-ok">authorized</span>'
      : '<span class="chip chip-warn">' + esc(s.authorization_status) + '</span>') + '</td>'
    + '<td>' + (s.allow_port_override ? '<span class="chip chip-neutral">override allowed</span>' : '<span class="faint">default ports</span>') + '</td>'
    + '<td class="faint">' + esc(s.authorized_by || '—') + '</td>'
    + '<td class="faint nowrap">' + esc(s.expires_at ? fmtDate(s.expires_at) : 'no expiry') + '</td>'
    + '</tr>'
  ).join('');

  const form = can('scope:write')
    ? '<div class="card section"><h2>Add a target</h2>'
      + '<p class="note">Veyl will only ever scan a host that appears here, is marked '
      + 'AUTHORIZED, and has not expired. A target outside this list is refused with a reason, '
      + 'and the refusal is recorded on the scan.</p>'
      + '<div class="row section">'
      + '<input id="s-domain" placeholder="api.example.com">'
      + '<select id="s-env"><option>PRODUCTION</option><option>STAGING</option><option>DEVELOPMENT</option><option>UNKNOWN</option></select>'
      + '<select id="s-owner"><option>UNASSIGNED</option><option>ENGINEERING</option><option>SECURITY_TEAM</option><option>INFRASTRUCTURE</option><option>PLATFORM</option><option>DATA</option></select>'
      + '<select id="s-auth"><option>AUTHORIZED</option><option>PENDING</option></select>'
      + '</div>'
      + '<div class="row"><input id="s-by" placeholder="Authorized by (person, ticket, contract)">'
      + '<label class="faint"><input id="s-override" type="checkbox"> allow port override</label>'
      + '<button class="btn btn-sm" id="s-add">Add to scope</button></div>'
      + '</div>'
    : '';

  return {
    html: '<div class="table-wrap">'
      + (rows
        ? '<table><thead><tr><th>Target</th><th>Environment</th><th>Owner</th><th>Authorization</th>'
          + '<th>Ports</th><th>Authorized by</th><th>Expires</th></tr></thead><tbody>' + rows + '</tbody></table>'
        : emptyState('No scope entries. Nothing can be scanned until one is added.'))
      + '</div>' + form,
    after: () => {
      const add = $('#s-add');
      if (!add) return;
      add.addEventListener('click', async () => {
        const domain = $('#s-domain').value.trim();
        if (!domain) { toast('Enter a hostname first', 'error'); return; }
        add.disabled = true;
        try {
          await api('/scope', {
            method: 'POST',
            body: {
              domain,
              environment: $('#s-env').value,
              asset_owner: $('#s-owner').value,
              authorization_status: $('#s-auth').value,
              authorized_by: $('#s-by').value.trim() || null,
              allow_port_override: $('#s-override').checked,
            },
          });
          toast('Added ' + domain + ' to scope', 'ok');
          route();
        } catch (err) {
          toast(err.message, 'error');
          add.disabled = false;
        }
      });
    },
  };
}

/* --------------------------------------------------------------- changes */

async function renderChanges() {
  const page = await api('/changes?limit=100');
  const rows = (page.items || []).map((c) =>
    '<tr>'
    + '<td class="nowrap faint">' + esc(relTime(c.detected_at)) + '</td>'
    + '<td>' + (c.is_risk_increasing
      ? '<span class="chip chip-HIGH">risk up</span>'
      : '<span class="chip chip-neutral">neutral</span>') + '</td>'
    + '<td><strong>' + esc(String(c.change_type).replace(/_/g, ' ')) + '</strong>'
    + '<div class="faint">' + esc(c.subject) + '</div></td>'
    + '<td class="mono faint">' + esc((c.previous_state || '—') + ' → ' + (c.current_state || '—')) + '</td>'
    + '<td>' + esc(c.security_significance) + '</td>'
    + '<td class="risk">' + c.risk_score.toFixed(1) + '</td>'
    + '<td>' + (c.acknowledged
      ? '<span class="chip chip-ok">acknowledged</span>'
      : can('graph:read') ? '<button class="btn btn-sm" data-ack="' + esc(c.id) + '">Acknowledge</button>' : '—') + '</td>'
    + '</tr>'
  ).join('');

  return {
    html: '<div class="table-wrap">'
      + (rows
        ? '<table><thead><tr><th>Detected</th><th>Direction</th><th>Change</th><th>Before → after</th>'
          + '<th>Why it matters</th><th>Risk</th><th></th></tr></thead><tbody>' + rows + '</tbody></table>'
        : emptyState('No changes detected yet. Changes appear when a second scan finds something different.'))
      + '</div>',
    after: () => {
      document.querySelectorAll('[data-ack]').forEach((btn) => {
        btn.addEventListener('click', async () => {
          btn.disabled = true;
          try {
            await api('/changes/' + encodeURIComponent(btn.dataset.ack), {
              method: 'PATCH', body: { acknowledged: true },
            });
            toast('Change acknowledged', 'ok');
            route();
          } catch (err) {
            toast(err.message, 'error');
            btn.disabled = false;
          }
        });
      });
    },
  };
}

/* ----------------------------------------------------------------- paths */

async function renderPaths() {
  const page = await api('/attack-paths?limit=50');
  const cards = (page.items || []).map((p) => {
    const steps = (p.steps || []).map((s, i) =>
      '<li><strong>' + esc(s.description || ('Step ' + (i + 1))) + '</strong>'
      + (s.evidence ? '<div class="faint">' + esc(s.evidence) + '</div>' : '') + '</li>'
    ).join('');
    return '<div class="card section">'
      + '<div class="detail-head"><h3>' + esc(p.name) + '</h3>'
      + '<span class="chip chip-neutral">' + esc(p.state) + '</span>'
      + '<span class="chip chip-neutral">confidence ' + esc(p.confidence) + '</span>'
      + '<span class="risk row-end">risk ' + p.risk_score.toFixed(1) + '</span></div>'
      + '<p>' + esc(p.summary) + '</p>'
      + (steps ? '<h2>Path</h2><ol>' + steps + '</ol>' : '')
      + '<h2>Business impact</h2><p>' + esc(p.business_impact) + '</p>'
      + '<div class="warning"><strong>Not verified:</strong> ' + esc(p.limitations) + '</div>'
      + ((p.finding_ids || []).length
        ? '<div class="row section"><span class="faint">Findings behind this path:</span>'
          + p.finding_ids.map((fid) => '<a class="btn btn-sm" href="#/findings/' + esc(fid) + '">' + esc(fid.slice(0, 8)) + '</a>').join('')
          + '</div>' : '')
      + '</div>';
  }).join('');

  return {
    html: (cards || emptyState('No attack paths have been correlated yet.'))
      + '<p class="note section">A path is labelled <strong>POTENTIAL</strong> unless an '
      + 'authorized check produced positive evidence for every step. Veyl does not exploit, '
      + 'so it does not claim a chain was demonstrated.</p>',
  };
}

/* ----------------------------------------------------------------- scans */

async function renderScans() {
  const page = await api('/scans?limit=50');
  const rows = (page.items || []).map((s) =>
    '<tr>'
    + '<td class="nowrap">' + esc(fmtDate(s.started_at)) + '</td>'
    + '<td>' + esc(s.label || s.id.slice(0, 8)) + '<div class="faint">' + esc(s.trigger) + '</div></td>'
    + '<td>' + statusChip(s.status) + '</td>'
    + '<td>' + num(s.targets_scanned) + '/' + num(s.targets_requested)
    + (s.targets_blocked ? ' <span class="chip chip-warn">' + num(s.targets_blocked) + ' refused</span>' : '') + '</td>'
    + '<td>' + num(s.assets_found) + '</td>'
    + '<td>' + num(s.services_found) + '</td>'
    + '<td>' + num(s.findings_created) + '</td>'
    + '<td>' + num(s.changes_detected) + '</td>'
    + '<td class="faint">' + esc(s.error_message || '') + '</td>'
    + '</tr>'
  ).join('');

  const blocked = (page.items || []).flatMap((s) => (s.blocked_targets || []).map((b) => ({ ...b, scan: s })));
  const blockedHtml = blocked.length
    ? '<div class="card section"><h2>Refused targets</h2>'
      + '<p class="note">These were requested and not scanned. The safety floor or the scope '
      + 'guard refused them, and the reason is recorded rather than hidden.</p>'
      + '<table><thead><tr><th>Target</th><th>Reason</th><th>Scan</th></tr></thead><tbody>'
      + blocked.map((b) => '<tr><td class="mono">' + esc(b.target || b.domain || '—') + '</td>'
        + '<td>' + esc(b.reason || '—') + '</td>'
        + '<td class="faint mono">' + esc(b.scan.id.slice(0, 8)) + '</td></tr>').join('')
      + '</tbody></table></div>'
    : '';

  return {
    html: (can('scan:create')
      ? '<div class="toolbar"><button class="btn btn-primary" id="run-scan">Run a scan now</button>'
        + '<span class="faint">Scans every currently authorized, unexpired scope entry using the '
        + 'default safe port set. In the demo that entry is <code>127.0.0.1</code> — this '
        + 'machine\'s own loopback, including any local services — so a manual scan here is '
        + 'not a scan of the bundled AcmePay target.</span></div>'
      : '')
      + '<div class="table-wrap">'
      + (rows
        ? '<table><thead><tr><th>Started</th><th>Scan</th><th>Status</th><th>Targets</th><th>Assets</th>'
          + '<th>Services</th><th>Findings</th><th>Changes</th><th>Error</th></tr></thead><tbody>' + rows + '</tbody></table>'
        : emptyState('No scans yet.'))
      + '</div>' + blockedHtml,
    after: () => {
      const run = $('#run-scan');
      if (!run) return;
      run.addEventListener('click', async () => {
        run.disabled = true;
        run.textContent = 'Scanning…';
        try {
          const scan = await api('/scans', { method: 'POST', body: { trigger: 'MANUAL' } });
          toast('Scan ' + scan.status.toLowerCase() + ': ' + scan.findings_created
            + ' findings, ' + scan.changes_detected + ' changes', 'ok');
          route();
        } catch (err) {
          toast(err.message, 'error');
          run.disabled = false;
          run.textContent = 'Run a scan now';
        }
      });
    },
  };
}

/* --------------------------------------------------------------- reports */

async function renderReports() {
  const page = await api('/reports?limit=50');
  const rows = (page.items || []).map((r) =>
    '<tr><td>' + esc(fmtDate(r.created_at)) + '</td>'
    + '<td><strong>' + esc(r.title) + '</strong><div class="faint">' + esc(r.kind) + ' · ' + esc(r.fmt) + '</div></td>'
    + '<td>' + statusChip(r.status) + '</td>'
    + '<td class="mono faint">' + esc((r.checksum || '').slice(0, 16) || '—') + '</td>'
    + '<td>' + (r.status === 'READY'
      ? '<button class="btn btn-sm" data-download="' + esc(r.id) + '" data-fmt="' + esc(r.fmt) + '" data-title="' + esc(r.title) + '">Download</button>'
      : '<span class="faint">' + esc(r.error_message || '—') + '</span>') + '</td></tr>'
  ).join('');

  const form = can('report:generate')
    ? '<div class="card section"><h2>Generate a report</h2>'
      + '<div class="row"><select id="rep-kind"><option>EXECUTIVE</option><option>TECHNICAL</option></select>'
      + '<select id="rep-fmt"><option>HTML</option><option>JSON</option><option>PDF</option></select>'
      + '<button class="btn btn-sm" id="rep-go">Generate</button>'
      + '<span class="faint">PDF is not implemented and returns 501 rather than a broken file.</span></div></div>'
    : '';

  return {
    html: '<div class="table-wrap">'
      + (rows
        ? '<table><thead><tr><th>Created</th><th>Report</th><th>Status</th><th>Checksum</th><th></th></tr></thead><tbody>'
          + rows + '</tbody></table>'
        : emptyState('No reports generated yet.'))
      + '</div>' + form,
    after: () => {
      document.querySelectorAll('[data-download]').forEach((btn) => {
        btn.addEventListener('click', async () => {
          btn.disabled = true;
          try {
            const res = await fetch(API + '/reports/' + encodeURIComponent(btn.dataset.download) + '/download', {
              headers: { Authorization: 'Bearer ' + state.token },
            });
            if (!res.ok) {
              const body = await res.json().catch(() => ({}));
              throw new Error(typeof body.detail === 'string' ? body.detail : 'download failed');
            }
            const blob = await res.blob();
            const ext = btn.dataset.fmt === 'JSON' ? 'json' : 'html';
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = btn.dataset.title.replace(/[^\w.-]+/g, '-').toLowerCase() + '.' + ext;
            document.body.appendChild(a);
            a.click();
            a.remove();
            setTimeout(() => URL.revokeObjectURL(url), 5000);
            toast('Report downloaded', 'ok');
          } catch (err) {
            toast(err.message, 'error');
          } finally {
            btn.disabled = false;
          }
        });
      });

      const go = $('#rep-go');
      if (go) {
        go.addEventListener('click', async () => {
          go.disabled = true;
          try {
            await api('/reports', {
              method: 'POST',
              body: { kind: $('#rep-kind').value, fmt: $('#rep-fmt').value },
            });
            toast('Report generated', 'ok');
            route();
          } catch (err) {
            toast(err.message, 'error');
            go.disabled = false;
          }
        });
      }
    },
  };
}

/* ----------------------------------------------------------------- audit */

async function renderAudit() {
  const page = await api('/audit?limit=200');
  const rows = (page.items || []).map((e) =>
    '<tr><td class="nowrap faint mono">' + esc(fmtDate(e.created_at)) + '</td>'
    + '<td><strong>' + esc(e.action) + '</strong></td>'
    + '<td>' + esc(e.actor_email || '—') + '<div class="faint">' + esc(e.actor_role || '') + '</div></td>'
    + '<td>' + (e.result === 'SUCCESS'
      ? '<span class="chip chip-ok">success</span>'
      : '<span class="chip chip-HIGH">' + esc(e.result || '—') + '</span>') + '</td>'
    + '<td>' + esc(e.detail || '') + '</td>'
    + '<td class="mono faint">' + esc(e.ip_address || '—') + '</td></tr>'
  ).join('');

  return {
    html: '<div class="toolbar">'
      + (can('audit:read') ? '<button class="btn btn-sm" id="verify">Verify hash chain</button>' : '')
      + '<span class="faint" id="verify-result"></span></div>'
      + '<div class="table-wrap">'
      + (rows
        ? '<table><thead><tr><th>When</th><th>Action</th><th>Actor</th><th>Result</th><th>Detail</th><th>Source</th></tr></thead><tbody>'
          + rows + '</tbody></table>'
        : emptyState('No audit entries.'))
      + '</div>'
      + '<p class="note section">Each entry includes the hash of the one before it. The chain is '
      + 'verified inside the application, which detects edits made to rows but not an operator who '
      + 'can rewrite the whole table. See SECURITY.md.</p>',
    after: () => {
      const verify = $('#verify');
      if (!verify) return;
      verify.addEventListener('click', async () => {
        verify.disabled = true;
        try {
          const result = await api('/audit/verify');
          $('#verify-result').textContent = result.is_valid
            ? 'Chain valid across ' + num(result.entries_checked) + ' entries'
            : 'Chain BROKEN at entry ' + (result.first_bad_entry_id || 'unknown')
              + (result.reason ? ' — ' + result.reason : '');
          toast(result.is_valid ? 'Audit chain verified' : 'Audit chain is broken', result.is_valid ? 'ok' : 'error');
        } catch (err) {
          toast(err.message, 'error');
        } finally {
          verify.disabled = false;
        }
      });
    },
  };
}

/* -------------------------------------------------------------- wiring */

$('#login-form').addEventListener('submit', submitLogin);
$('#signout').addEventListener('click', () => signOut('Signed out.'));
$('#helper-generate').addEventListener('click', async () => {
  const target = $('#helper-code');
  try {
    const code = await totpNow($('#helper-secret').value);
    target.textContent = code;
    $('#login-totp').value = code;
  } catch (err) {
    target.textContent = err.message;
  }
});
window.addEventListener('hashchange', () => { if (state.me) route(); });

boot();
