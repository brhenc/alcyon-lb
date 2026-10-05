// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
// Test backend for practical topology 06. Plain http, no npm packages. Usage: node app.js PORT
const http = require('http');
const crypto = require('crypto');
const port = +process.argv[2] || 26001;
const NJS = 6, NCSS = 3;

const index = `<!doctype html><html><head><meta charset="utf-8"><title>spa</title>
<link rel="icon" href="data:,">
${[...Array(NCSS).keys()].map(i => `<link rel="stylesheet" href="/assets/style${i}.css">`).join('\n')}
</head><body><h1 id="h">SPA</h1><div id="out"></div>
${[...Array(NJS).keys()].map(i => `<script src="/assets/app${i}.js"></script>`).join('\n')}
<script src="/assets/main.js"></script></body></html>`;

const main = `
window.__results = {};
const R = window.__results;
async function run() {
  const r = await fetch('/api/items?n=3'); R.api = await r.json();
  const r2 = await fetch('/api/echo', {method: 'POST', headers: {'content-type': 'application/json'}, body: JSON.stringify({a: [1, 2, 3], s: 'h\\u00e9llo'})});
  R.post = await r2.json();
  const r3 = await fetch('/api/headers'); R.headers = await r3.json();
  R.mods = (window.__mods || []).length;
  R.css = [...Array(${NCSS}).keys()].map(i => getComputedStyle(document.body).getPropertyValue('--c' + i).trim());
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  await new Promise((res, rej) => {
    const ws = new WebSocket(proto + '//' + location.host + '/ws'); ws.binaryType = 'arraybuffer';
    const got = []; const bin = new Uint8Array(70000); for (let i = 0; i < bin.length; i++) bin[i] = (i * 7) & 255;
    ws.onopen = () => { ws.send('hello ws'); ws.send(bin.buffer); };
    ws.onmessage = e => { got.push(e.data);
      if (got.length === 2) { R.wsText = got[0]; const b = new Uint8Array(got[1]); R.wsBinOk = b.length === bin.length && b.every((v, i) => v === bin[i]); ws.close(); } };
    ws.onclose = () => res(); ws.onerror = () => rej(new Error('ws error'));
  });
  await new Promise((res, rej) => {
    const es = new EventSource('/sse'); R.sse = [];
    es.onmessage = e => { R.sse.push(e.data); if (R.sse.length === 5) { es.close(); res(); } };
    es.onerror = () => { if (R.sse.length < 5) { es.close(); rej(new Error('sse error')); } };
  });
}
run().then(() => { window.__done = 'ok'; }, e => { window.__done = 'error: ' + e; });
`;

const srv = http.createServer((req, res) => {
  const u = new URL(req.url, 'http://x');
  const send = (code, type, body) => { res.writeHead(code, {'content-type': type, 'cache-control': 'no-store'}); res.end(body); };
  let m;
  if (u.pathname === '/') return send(200, 'text/html; charset=utf-8', index);
  if (u.pathname === '/assets/main.js') return send(200, 'application/javascript', main);
  if ((m = /^\/assets\/app(\d+)\.js$/.exec(u.pathname))) return send(200, 'application/javascript',
    `(window.__mods = window.__mods || []).push(${m[1]});\n` + '// pad\n'.repeat(2000));
  if ((m = /^\/assets\/style(\d+)\.css$/.exec(u.pathname))) return send(200, 'text/css', `body{--c${m[1]}: v${m[1]}}`);
  if (u.pathname === '/api/items') { const n = +u.searchParams.get('n') || 0;
    return send(200, 'application/json', JSON.stringify({items: [...Array(n).keys()].map(i => ({id: i, name: 'item' + i}))})); }
  if (u.pathname === '/api/headers') return send(200, 'application/json', JSON.stringify({xff: req.headers['x-forwarded-for'] || null}));
  if (u.pathname === '/api/echo') { const b = []; req.on('data', c => b.push(c));
    return req.on('end', () => send(200, 'application/json', JSON.stringify({got: JSON.parse(Buffer.concat(b).toString())}))); }
  if (u.pathname === '/sse') {
    res.writeHead(200, {'content-type': 'text/event-stream', 'cache-control': 'no-store'});
    let i = 0; const t = setInterval(() => { i++; res.write(`id: ${i}\ndata: event-${i}\n\n`); if (i === 5) { clearInterval(t); res.end(); } }, 100);
    return res.on('close', () => clearInterval(t));
  }
  send(404, 'text/plain', 'not found');
});

// Minimal RFC 6455 echo: text and binary, ping/pong, close; fragmentation not needed.
srv.on('upgrade', (req, sock) => {
  if (req.url !== '/ws') return sock.end('HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n');
  const key = req.headers['sec-websocket-key'];
  const acc = crypto.createHash('sha1').update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
  sock.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ' + acc + '\r\n\r\n');
  let buf = Buffer.alloc(0);
  const frame = (op, p) => { const l = p.length;
    const h = l < 126 ? Buffer.from([0x80 | op, l]) : l < 65536 ? Buffer.from([0x80 | op, 126, l >> 8, l & 255])
      : (() => { const x = Buffer.alloc(10); x[0] = 0x80 | op; x[1] = 127; x.writeBigUInt64BE(BigInt(l), 2); return x; })();
    return Buffer.concat([h, p]); };
  sock.on('data', d => {
    buf = Buffer.concat([buf, d]);
    for (;;) {
      if (buf.length < 2) return;
      const op = buf[0] & 15; let len = buf[1] & 127, off = 2;
      if (len === 126) { if (buf.length < 4) return; len = buf.readUInt16BE(2); off = 4; }
      else if (len === 127) { if (buf.length < 10) return; len = Number(buf.readBigUInt64BE(2)); off = 10; }
      const masked = buf[1] & 128; if (buf.length < off + (masked ? 4 : 0) + len) return;
      const mask = masked ? buf.subarray(off, off + 4) : null; off += masked ? 4 : 0;
      const p = Buffer.from(buf.subarray(off, off + len)); if (mask) for (let i = 0; i < len; i++) p[i] ^= mask[i & 3];
      buf = buf.subarray(off + len);
      if (op === 1 || op === 2) sock.write(frame(op, p));
      else if (op === 9) sock.write(frame(10, p));
      else if (op === 8) { sock.end(frame(8, p.subarray(0, 2))); return; }
    }
  });
  sock.on('error', () => {});
});
srv.listen(port, '127.0.0.1', () => console.log('listening', port));
