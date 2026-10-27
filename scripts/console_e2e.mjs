// Drive the Veyl console in a real browser over the DevTools Protocol.
// No dependencies: Node 22 has a global WebSocket client.
import { spawn } from 'node:child_process';
import { writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const CHROME = 'C:/Program Files/Google/Chrome/Application/chrome.exe';
const BASE = 'http://127.0.0.1:8000';
const PORT = 9333;
const OUT = process.argv[2] || 'C:/Users/sa595/Desktop/autonomous/veyl/artifacts/console';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const profile = mkdtempSync(join(tmpdir(), 'veyl-chrome-'));
const chrome = spawn(CHROME, [
  '--headless=new',
  `--remote-debugging-port=${PORT}`,
  `--user-data-dir=${profile}`,
  '--no-first-run',
  '--no-default-browser-check',
  '--no-proxy-server',
  '--disable-gpu',
  '--hide-scrollbars',
  '--window-size=1440,900',
  'about:blank',
], { stdio: 'ignore' });

async function waitForDevtools() {
  for (let i = 0; i < 60; i++) {
    try {
      const res = await fetch(`http://127.0.0.1:${PORT}/json/list`);
      const list = await res.json();
      const page = list.find((t) => t.type === 'page');
      if (page) return page.webSocketDebuggerUrl;
    } catch { /* not up yet */ }
    await sleep(250);
  }
  throw new Error('devtools never came up');
}

const wsUrl = await waitForDevtools();
const ws = new WebSocket(wsUrl);
await new Promise((res, rej) => { ws.onopen = res; ws.onerror = rej; });

let nextId = 1;
const pending = new Map();
ws.onmessage = (event) => {
  const msg = JSON.parse(event.data);
  if (msg.id && pending.has(msg.id)) {
    const { resolve, reject } = pending.get(msg.id);
    pending.delete(msg.id);
    if (msg.error) reject(new Error(JSON.stringify(msg.error)));
    else resolve(msg.result);
  }
};
function send(method, params = {}) {
  const id = nextId++;
  ws.send(JSON.stringify({ id, method, params }));
  return new Promise((resolve, reject) => pending.set(id, { resolve, reject }));
}

async function evaluate(expression) {
  const result = await send('Runtime.evaluate', {
    expression, returnByValue: true, awaitPromise: true,
  });
  if (result.exceptionDetails) {
    throw new Error('page error: ' + JSON.stringify(result.exceptionDetails.exception?.description
      || result.exceptionDetails.text));
  }
  return result.result.value;
}

async function waitFor(expression, label = expression, timeout = 20000) {
  const start = Date.now();
  while (Date.now() - start < timeout) {
    if (await evaluate(`(() => { try { return !!(${expression}); } catch (e) { return false; } })()`)) return;
    await sleep(120);
  }
  throw new Error('timed out waiting for ' + label);
}

async function shot(name) {
  const { data } = await send('Page.captureScreenshot', { format: 'png' });
  writeFileSync(`${OUT}/${name}.png`, Buffer.from(data, 'base64'));
}

await send('Page.enable');
await send('Runtime.enable');
await send('Log.enable');
const consoleErrors = [];
ws.addEventListener('message', (event) => {
  const msg = JSON.parse(event.data);
  if (msg.method === 'Log.entryAdded' && msg.params.entry.level === 'error') {
    consoleErrors.push(msg.params.entry.text);
  }
  if (msg.method === 'Runtime.consoleAPICalled' && msg.params.type === 'error') {
    consoleErrors.push(msg.params.args.map((a) => a.value || a.description).join(' '));
  }
});

const report = { steps: [], consoleErrors };

async function goto(url) {
  await send('Page.navigate', { url });
  await sleep(700);
}

// --- sign in as the analyst ------------------------------------------------
await goto(BASE + '/console/');
await waitFor("document.querySelector('#login-form')", 'login form');
report.steps.push({ step: 'login form rendered', ok: true });
await shot('01-login');

await evaluate(`(() => {
  const email = document.querySelector('#login-email');
  const pass = document.querySelector('#login-password');
  email.value = 'analyst@acmepay.example';
  pass.value = 'Veyl-Demo-Password-1!';
  document.querySelector('#login-form').requestSubmit();
  return true;
})()`);

await waitFor("!document.querySelector('#app').classList.contains('hidden')", 'app shell');
await waitFor("document.querySelector('#view .stat')", 'dashboard stats');
report.steps.push({
  step: 'analyst signed in, dashboard loaded',
  stats: await evaluate(`Array.from(document.querySelectorAll('#view .stat')).map(el => el.textContent.trim())`),
});
await sleep(400);
await shot('02-dashboard');

// --- every view ------------------------------------------------------------
const views = [
  ['findings', '#/findings', '#view table tbody tr'],
  ['assets', '#/assets', '#view table tbody tr'],
  ['scope', '#/scope', '#view table tbody tr'],
  ['changes', '#/changes', '#view table tbody tr'],
  ['paths', '#/paths', '#view .card'],
  ['scans', '#/scans', '#view table tbody tr'],
  ['reports', '#/reports', '#view .table-wrap'],
  ['audit', '#/audit', '#view table tbody tr'],
];

for (const [name, hash, selector] of views) {
  await evaluate(`location.hash = '${hash}'`);
  await waitFor(`document.querySelector('${selector}')`, name + ' content');
  const summary = await evaluate(`(() => {
    const rows = document.querySelectorAll('#view tbody tr');
    return {
      title: document.querySelector('#view-title').textContent,
      rows: rows.length,
      cards: document.querySelectorAll('#view .card').length,
      first: rows[0] ? rows[0].textContent.replace(/\\s+/g, ' ').trim().slice(0, 120) : null,
      empty: !!document.querySelector('#view .empty'),
    };
  })()`);
  report.steps.push({ step: 'view ' + name, ...summary });
  await sleep(250);
  await shot('03-' + name);
}

// --- asset detail ----------------------------------------------------------
await evaluate(`location.hash = '#/assets'`);
await waitFor("document.querySelector('#view tbody tr[data-asset]')", 'asset rows');
await evaluate(`document.querySelector('#view tbody tr[data-asset]').click()`);
await waitFor("document.querySelector('#view .detail-title')", 'asset detail');
report.steps.push({
  step: 'asset detail',
  detail: await evaluate(`(() => ({
    title: document.querySelector('#view .detail-title').textContent,
    tables: document.querySelectorAll('#view table').length,
    hasContext: document.querySelector('#view').textContent.includes('Business context'),
    hasRescore: !!document.querySelector('#rescore'),
  }))()`),
});
await sleep(300);
await shot('10-asset-detail');

// --- a real scan, started from the UI --------------------------------------
await evaluate(`location.hash = '#/scans'`);
await waitFor("document.querySelector('#run-scan')", 'run-scan button');
const scansBefore = await evaluate(`document.querySelectorAll('#view tbody tr').length`);
await evaluate(`document.querySelector('#run-scan').click()`);
await waitFor(`document.querySelectorAll('#view tbody tr').length > ${scansBefore}`, 'scan to appear', 90000);
report.steps.push({
  step: 'scan started from the UI',
  scansBefore,
  scansAfter: await evaluate(`document.querySelectorAll('#view tbody tr').length`),
  firstRow: await evaluate(`document.querySelector('#view tbody tr').textContent.replace(/\\s+/g, ' ').trim()`),
});
await sleep(300);
await shot('07-scan-run');

// --- report generation from the UI ----------------------------------------
await evaluate(`location.hash = '#/reports'`);
await waitFor("document.querySelector('#rep-go')", 'report form');
await evaluate(`(() => {
  document.querySelector('#rep-kind').value = 'TECHNICAL';
  document.querySelector('#rep-fmt').value = 'HTML';
  document.querySelector('#rep-go').click();
  return true;
})()`);
await waitFor("document.querySelector('[data-download]')", 'generated report', 30000);
report.steps.push({
  step: 'report generated from the UI',
  row: await evaluate(`document.querySelector('#view tbody tr').textContent.replace(/\\s+/g, ' ').trim()`),
});
await sleep(300);
await shot('08-report');

// --- finding detail, then a real mutation ---------------------------------
await evaluate(`location.hash = '#/findings'`);
await waitFor("document.querySelector('#view tbody tr[data-finding]')", 'finding rows');

const beforeSearch = await evaluate(`document.querySelectorAll('#view tbody tr[data-finding]').length`);
await evaluate(`(() => {
  const box = document.querySelector('#f-search');
  box.value = 'asset';
  box.dispatchEvent(new Event('input', { bubbles: true }));
  return true;
})()`);
await sleep(1200);
const searchState = await evaluate(`(() => ({
  rows: document.querySelectorAll('#view tbody tr[data-finding]').length,
  focused: document.activeElement && document.activeElement.id,
  total: (document.querySelector('#view .toolbar .faint') || {}).textContent || '',
}))()`);
report.steps.push({
  step: 'search filters findings',
  beforeSearch,
  ...searchState,
  filtered: searchState.rows > 0 && searchState.rows < beforeSearch,
});
await shot('09-search');

await evaluate(`(() => {
  const box = document.querySelector('#f-search');
  box.value = '';
  box.dispatchEvent(new Event('input', { bubbles: true }));
  return true;
})()`);
await sleep(1000);

await evaluate(`document.querySelector('#view tbody tr[data-finding]').click()`);
await waitFor("document.querySelector('.detail-title')", 'finding detail');
report.steps.push({
  step: 'finding detail',
  detail: await evaluate(`(() => ({
    title: document.querySelector('.detail-title').textContent,
    evidenceBlocks: document.querySelectorAll('#view .evidence').length,
    riskScore: (document.querySelector('#view .stat-value') || {}).textContent || null,
    hasDetection: document.querySelector('#view').textContent.includes('How Veyl decided this'),
  }))()`),
});
await sleep(300);
await shot('04-finding-detail');

const findingId = await evaluate(`location.hash.split('/')[2]`);
const statusButtons = await evaluate(`Array.from(document.querySelectorAll('[data-status]')).map(b => b.dataset.status)`);
report.steps.push({ step: 'status buttons offered', statusButtons });
if (statusButtons.includes('ACKNOWLEDGED')) {
  await evaluate(`document.querySelector('[data-status="ACKNOWLEDGED"]').click()`);
  await sleep(1400);
  const after = await evaluate(`document.querySelector('#view').textContent`);
  report.steps.push({ step: 'status change to ACKNOWLEDGED', applied: after.includes('ACKNOWLEDGED') });
  // Put it back so the demo data stays as seeded.
  const back = await evaluate(`(() => {
    const b = document.querySelector('[data-status="OPEN"]');
    if (b) { b.click(); return true; }
    return false;
  })()`);
  await sleep(1400);
  report.steps.push({
    step: 'status restored to OPEN',
    restored: back && (await evaluate(`document.querySelector('#view').textContent`)).includes('OPEN'),
  });
} else {
  report.steps.push({ step: 'status change', skipped: 'no ACKNOWLEDGED button', findingId });
}

// Remediation save is the path that produced a 500 in an earlier build, so it
// is exercised through the UI rather than assumed to work.
const hasRemediationForm = await evaluate(`!!document.querySelector('#r-save')`);
if (hasRemediationForm) {
  await evaluate(`(() => {
    document.querySelector('#r-notes').value = 'Console smoke test: patched by the E2E check.';
    document.querySelector('#r-priority').value = 'HIGH';
    document.querySelector('#r-save').click();
    return true;
  })()`);
  await sleep(1400);
  const body = await evaluate(`document.querySelector('#view').textContent`);
  report.steps.push({
    step: 'remediation saved through the UI',
    ok: body.includes('HIGH') && !body.includes('internal server error'),
  });
}

// --- admin sign-in exercises the MFA path + TOTP helper --------------------
await evaluate(`document.querySelector('#signout').click()`);
await waitFor("!document.querySelector('#login-form').closest('.hidden')", 'login form after sign out');

await evaluate(`(() => {
  document.querySelector('#login-email').value = 'admin@acmepay.example';
  document.querySelector('#login-password').value = 'Veyl-Demo-Password-1!';
  document.querySelector('#login-form').requestSubmit();
  return true;
})()`);
await waitFor("!document.querySelector('#totp-field').hidden", 'second-factor field');
report.steps.push({
  step: 'admin password accepted, second factor requested',
  message: await evaluate(`document.querySelector('#login-error').textContent`),
});
await shot('05-mfa-required');

const TOTP_SECRET = process.env.VEYL_TOTP_SECRET || '';
if (!TOTP_SECRET) throw new Error('set VEYL_TOTP_SECRET to the secret the demo printed');

await evaluate(`(() => {
  document.querySelector('#helper-secret').value = ${JSON.stringify(TOTP_SECRET)};
  document.querySelector('#helper-generate').click();
  return true;
})()`);
await sleep(400);

const code = await evaluate(`document.querySelector('#login-totp').value`);
report.steps.push({ step: 'totp helper produced a code', codeLength: (code || '').length });

if (code && code.length === 6) {
  await evaluate(`document.querySelector('#login-form').requestSubmit()`);
  await waitFor("!document.querySelector('#app').classList.contains('hidden')", 'admin session', 15000);
  report.steps.push({
    step: 'admin signed in with TOTP',
    who: await evaluate(`document.querySelector('#who').textContent.replace(/\\s+/g, ' ').trim()`),
  });
  await shot('06-admin-dashboard');
}

report.consoleErrors = consoleErrors;
writeFileSync(`${OUT}/report.json`, JSON.stringify(report, null, 2));
console.log(JSON.stringify(report, null, 2));

ws.close();
chrome.kill();
process.exit(0);
