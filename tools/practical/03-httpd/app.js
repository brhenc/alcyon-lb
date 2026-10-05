// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//
// Backend for practical topology 03. Usage: node app.js PORT
const http = require('http');
const crypto = require('crypto');
const port = parseInt(process.argv[2] || '3000', 10);
http.createServer((req, res) => {
  const p = new URL(req.url, 'http://x').pathname;
  if (p === '/upload') {
    const h = crypto.createHash('sha256'); let n = 0;
    req.on('data', (c) => { h.update(c); n += c.length; });
    req.on('end', () => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ sha256: h.digest('hex'), bytes: n, te: req.headers['transfer-encoding'] || null,
        cl: req.headers['content-length'] || null }) + '\n');
    });
  } else {
    req.resume();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ path: p, xff: req.headers['x-forwarded-for'] || null,
      port: req.socket.remotePort }) + '\n');
  }
}).listen(port, '127.0.0.1');
