// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//
// Test backend for practical topology 01. Plain node http + the "ws" package.
// Usage: node app.js PORT
const http = require('http');
const crypto = require('crypto');
const zlib = require('zlib');
const { WebSocketServer } = require('ws');

const port = parseInt(process.argv[2] || '3000', 10);
const DL_BYTES = parseInt(process.env.DL_BYTES || String(100 * 1024 * 1024), 10);

// Deterministic 64 KiB block for downloads; the client checks the sha256 header.
const block = Buffer.alloc(65536);
for (let i = 0; i < block.length; i++) block[i] = (i * 31 + 7) & 0xff;
function dlSha(n) {
  const h = crypto.createHash('sha256');
  let left = n;
  while (left > 0) { const k = Math.min(left, block.length); h.update(block.subarray(0, k)); left -= k; }
  return h.digest('hex');
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://x');
  const p = url.pathname;
  if (p === '/ka') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('hello from node\n');
  } else if (p === '/upload') {
    // Reads the whole body (any framing), answers with its sha256 and size.
    const h = crypto.createHash('sha256'); let n = 0;
    req.on('data', (c) => { h.update(c); n += c.length; });
    req.on('end', () => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ sha256: h.digest('hex'), bytes: n,
        te: req.headers['transfer-encoding'] || null }) + '\n');
    });
  } else if (p === '/download') {
    const n = parseInt(url.searchParams.get('bytes') || String(DL_BYTES), 10);
    res.writeHead(200, { 'Content-Type': 'application/octet-stream',
      'Content-Length': n, 'X-Sha256': dlSha(n) });
    let left = n;
    (function pump() {
      while (left > 0) {
        const k = Math.min(left, block.length); left -= k;
        if (!res.write(block.subarray(0, k))) { res.once('drain', pump); return; }
      }
      res.end();
    })();
  } else if (p === '/sse') {
    const n = parseInt(url.searchParams.get('n') || '5', 10);
    res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache' });
    let i = 0;
    const t = setInterval(() => {
      i++; res.write(`id: ${i}\ndata: event ${i}\n\n`);
      if (i >= n) { clearInterval(t); res.end(); }
    }, 1000);
    res.write(': start\n\n');
    req.on('close', () => clearInterval(t));
  } else if (p === '/slow') {
    setTimeout(() => { res.writeHead(200, { 'Content-Type': 'text/plain' }); res.end('slow done\n'); }, 5000);
  } else if (p === '/fail') {
    res.writeHead(503, { 'Content-Type': 'text/plain' });
    res.end('backend failure\n');
  } else if (p === '/gzip') {
    const body = zlib.gzipSync('gzip body '.repeat(1000));
    res.writeHead(200, { 'Content-Type': 'text/plain', 'Content-Encoding': 'gzip',
      'Content-Length': body.length });
    res.end(body);
  } else {
    res.writeHead(404); res.end('not found\n');
  }
});

const wss = new WebSocketServer({ server, path: '/ws' });
wss.on('connection', (ws) => {
  ws.on('message', (data, isBinary) => ws.send(data, { binary: isBinary }));
});

server.listen(port, '127.0.0.1', () => console.log(`app listening on ${port}`));
