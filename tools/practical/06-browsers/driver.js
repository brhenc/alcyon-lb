// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
// Drives one headless browser through the proxy and prints "PASS|FAIL|SKIP <browser> <case> <detail>".
//   node driver.js chrome|firefox ORIGIN WORKDIR DEBUG_PORT
// No npm packages: Chrome over CDP, Firefox over WebDriver BiDi, both with node's built-in WebSocket.
// The browser is killed by PID at the end and its profile removed.
const { spawn } = require('child_process');
const fs = require('fs');
const [, , browser, origin, work, dport] = process.argv;
const sleep = ms => new Promise(r => setTimeout(r, ms));
const out = [];
const rec = (name, ok, detail) => { out.push([ok === null ? 'SKIP' : ok ? 'PASS' : 'FAIL', browser, name, detail || ''].join(' ')); };

class Rpc {   // JSON-RPC over WebSocket; CDP and BiDi both use {id, method, params} / {id, result|error}
  constructor(url, onEvent) {
    this.id = 0; this.pending = new Map(); this.onEvent = onEvent;
    this.ws = new WebSocket(url);
    this.ready = new Promise((res, rej) => { this.ws.onopen = res; this.ws.onerror = () => rej(new Error('rpc ws error')); });
    this.ws.onmessage = ev => {
      const m = JSON.parse(ev.data);
      if (m.id !== undefined && this.pending.has(m.id)) {
        const p = this.pending.get(m.id); this.pending.delete(m.id);
        (m.error ? p.rej(new Error(JSON.stringify(m.error))) : p.res(m.result));
      } else this.onEvent(m);
    };
  }
  call(method, params = {}) {
    const id = ++this.id;
    this.ws.send(JSON.stringify({ id, method, params }));
    return new Promise((res, rej) => { this.pending.set(id, { res, rej }); setTimeout(() => rej(new Error('timeout ' + method)), 30000); });
  }
}

const WAIT_DONE = `new Promise((r, j) => { const t0 = Date.now(); const t = setInterval(() => {
  if (window.__done) { clearInterval(t); r(JSON.stringify({done: window.__done, res: window.__results,
    nav: performance.getEntriesByType('resource').map(e => [e.name, e.nextHopProtocol])})); }
  else if (Date.now() - t0 > 20000) { clearInterval(t); r(JSON.stringify({done: 'timeout', res: window.__results || null, nav: []})); } }, 50); })`;

// One page load: { reqs:[{url,status,protocol,connId,reused}], consoleErrors:[], failed:[], page:{done,res,nav} }
function newLog() { return { reqs: [], consoleErrors: [], failed: [], ws: [] }; }

function check(log, page, tag) {
  const R = page.res || {};
  const same = log.reqs.filter(r => r.url.startsWith(origin));
  const bad = same.filter(r => r.protocol !== 'h2');
  rec(`${tag}page-h2`, same.length >= 10 && bad.length === 0, `${same.length} reqs, non-h2: ${bad.map(r => r.url + '=' + r.protocol).join(',') || 'none'}`);
  const want = ['/', '/assets/main.js', ...[0, 1, 2, 3, 4, 5].map(i => `/assets/app${i}.js`), ...[0, 1, 2].map(i => `/assets/style${i}.css`)];
  const miss = want.filter(p => !same.some(r => r.url === origin + p && r.status === 200));
  rec(`${tag}assets-200`, miss.length === 0, miss.length ? 'missing/non-200: ' + miss.join(',') : `${want.length} assets 200`);
  rec(`${tag}app-completed`, page.done === 'ok', String(page.done));
  rec(`${tag}no-console-errors`, log.consoleErrors.length === 0, log.consoleErrors.join(' | ') || 'none');
  rec(`${tag}no-failed-requests`, log.failed.length === 0, log.failed.join(' | ') || 'none');
  const apiOk = JSON.stringify(R.api) === '{"items":[{"id":0,"name":"item0"},{"id":1,"name":"item1"},{"id":2,"name":"item2"}]}'
    && JSON.stringify(R.post) === '{"got":{"a":[1,2,3],"s":"héllo"}}' && R.mods === 6 && JSON.stringify(R.css) === '["v0","v1","v2"]';
  rec(`${tag}api-json`, apiOk, JSON.stringify([R.api, R.post, R.mods, R.css]).slice(0, 200));
  rec(`${tag}ws-text`, R.wsText === 'hello ws', String(R.wsText));
  rec(`${tag}ws-binary`, R.wsBinOk === true, String(R.wsBinOk));
  rec(`${tag}sse-5-in-order`, JSON.stringify(R.sse) === '["event-1","event-2","event-3","event-4","event-5"]', JSON.stringify(R.sse));
  rec(`${tag}forwardfor`, !!(R.headers && R.headers.xff === '127.0.0.1'), JSON.stringify(R.headers));
}

async function chrome() {
  const prof = work + '/chrome';
  const p = spawn('/usr/bin/google-chrome', ['--headless=new', `--remote-debugging-port=${dport}`, `--user-data-dir=${prof}`,
    '--ignore-certificate-errors', '--no-first-run', '--no-default-browser-check', '--disable-gpu', '--no-sandbox', 'about:blank'], { stdio: 'ignore' });
  let pageWs;
  try {
    for (let i = 0; i < 100 && !pageWs; i++) {
      await sleep(100);
      try { const r = await fetch(`http://127.0.0.1:${dport}/json/new?about:blank`, { method: 'PUT' }); pageWs = (await r.json()).webSocketDebuggerUrl; } catch (e) {}
    }
    if (!pageWs) throw new Error('chrome did not start');
    let log = newLog(); const byId = new Map(); let loaded = null;
    const rpc = new Rpc(pageWs, m => {
      const q = m.params || {};
      if (m.method === 'Network.responseReceived') {
        const r = q.response; log.reqs.push({ url: r.url, status: r.status, protocol: r.protocol, connId: r.connectionId, reused: r.connectionReused, type: q.type });
      } else if (m.method === 'Network.loadingFailed') { if (!q.canceled) log.failed.push(`${q.errorText} ${q.requestId}`); }
      else if (m.method === 'Network.webSocketHandshakeResponseReceived') log.ws.push(q.response.status);
      else if (m.method === 'Network.webSocketFrameError') log.failed.push('ws frame error ' + q.errorMessage);
      else if (m.method === 'Runtime.consoleAPICalled') { if (q.type === 'error' || q.type === 'assert') log.consoleErrors.push('console.' + q.type + ': ' + (q.args || []).map(a => a.value || a.description).join(' ')); }
      else if (m.method === 'Runtime.exceptionThrown') log.consoleErrors.push('exception: ' + (q.exceptionDetails.exception && q.exceptionDetails.exception.description || q.exceptionDetails.text));
      else if (m.method === 'Log.entryAdded') { if (q.entry.level === 'error') log.consoleErrors.push(`log: ${q.entry.text} ${q.entry.url || ''}`); }
      else if (m.method === 'Page.loadEventFired' && loaded) loaded();
    });
    await rpc.ready;
    for (const d of ['Network', 'Runtime', 'Log', 'Page']) await rpc.call(d + '.enable');
    const load = async (fn) => { const w = new Promise(r => { loaded = r; }); await fn(); await Promise.race([w, sleep(20000)]); loaded = null;
      const r = await rpc.call('Runtime.evaluate', { expression: WAIT_DONE, awaitPromise: true, returnByValue: true });
      return JSON.parse(r.result.value); };
    const page1 = await load(() => rpc.call('Page.navigate', { url: origin + '/' }));
    const log1 = log; check(log1, page1, '');
    // nextHopProtocol cross-check from the page itself
    const nav = page1.nav.filter(e => e[0].startsWith(origin)); const nb = nav.filter(e => e[1] !== 'h2');
    rec('perf-nextHopProtocol-h2', nav.length >= 9 && nb.length === 0, `${nav.length} entries, non-h2: ${nb.map(e => e.join('=')).join(',') || 'none'}`);
    log = newLog();
    const page2 = await load(() => rpc.call('Page.reload', { ignoreCache: false }));
    const log2 = log; check(log2, page2, 'reload-');
    const d1 = log1.reqs.find(r => r.url === origin + '/'), d2 = log2.reqs.find(r => r.url === origin + '/');
    rec('reload-reuses-conn', !!(d2 && d2.reused === true), `conn ${d1 && d1.connId} -> ${d2 && d2.connId}, reused=${d2 && d2.reused}`);
    rpc.ws.close();
  } finally { p.kill('SIGTERM'); await sleep(500); try { p.kill('SIGKILL'); } catch (e) {} }
}

async function firefox() {
  const prof = work + '/ffprof'; fs.mkdirSync(prof, { recursive: true });
  fs.writeFileSync(prof + '/user.js', 'user_pref("remote.active-protocols", 1);\nuser_pref("datareporting.policy.dataSubmissionEnabled", false);\n' +
    'user_pref("app.update.enabled", false);\nuser_pref("browser.shell.checkDefaultBrowser", false);\nuser_pref("network.captive-portal-service.enabled", false);\n');
  const p = spawn('/usr/bin/firefox', ['--headless', '--no-remote', '--profile', prof, '--remote-debugging-port', dport, 'about:blank'],
    { stdio: 'ignore', env: { ...process.env, MOZ_DISABLE_CONTENT_SANDBOX: '1' } });
  try {
    let log = newLog(); let rpc;
    for (let i = 0; i < 150 && !rpc; i++) {
      await sleep(200);
      try { const r = new Rpc(`ws://127.0.0.1:${dport}/session`, m => {
        const q = m.params || {};
        if (m.method === 'network.responseCompleted') log.reqs.push({ url: q.request.url, status: q.response.status, protocol: q.response.protocol });
        else if (m.method === 'network.fetchError') log.failed.push(`${q.errorText} ${q.request.url}`);
        else if (m.method === 'log.entryAdded') { if (q.level === 'error') log.consoleErrors.push(`${q.type}: ${q.text}`); }
      }); await r.ready; rpc = r; } catch (e) {}
    }
    if (!rpc) throw new Error('firefox did not start');
    await rpc.call('session.new', { capabilities: { alwaysMatch: { acceptInsecureCerts: true } } });
    await rpc.call('session.subscribe', { events: ['log.entryAdded', 'network.responseCompleted', 'network.fetchError'] });
    const ctx = (await rpc.call('browsingContext.getTree', {})).contexts[0].context;
    const done = async () => { const r = await rpc.call('script.evaluate', { expression: WAIT_DONE, awaitPromise: true, target: { context: ctx } });
      if (r.type !== 'success') throw new Error(JSON.stringify(r)); return JSON.parse(r.result.value); };
    await rpc.call('browsingContext.navigate', { context: ctx, url: origin + '/', wait: 'complete' });
    const page1 = await done(); await sleep(300); check(log, page1, '');
    const nav = page1.nav.filter(e => e[0].startsWith(origin)); const nb = nav.filter(e => e[1] !== 'h2');
    rec('perf-nextHopProtocol-h2', nav.length >= 9 && nb.length === 0, `${nav.length} entries, non-h2: ${nb.map(e => e.join('=')).join(',') || 'none'}`);
    log = newLog();
    await rpc.call('browsingContext.reload', { context: ctx, wait: 'complete' });
    const page2 = await done(); await sleep(300); check(log, page2, 'reload-');
    rec('reload-reuses-conn', null, 'not observable over BiDi');
    rpc.ws.close();
  } finally { p.kill('SIGTERM'); await sleep(1000); try { p.kill('SIGKILL'); } catch (e) {} }
}

(async () => {
  const t = setTimeout(() => { console.log(`FAIL ${browser} driver-timeout overall 120 s`); process.exit(3); }, 120000);
  try { await (browser === 'chrome' ? chrome() : firefox()); }
  catch (e) { rec('driver', false, String(e && e.stack || e).split('\n').slice(0, 3).join(' / ')); }
  clearTimeout(t); console.log(out.join('\n')); process.exit(0);
})();
