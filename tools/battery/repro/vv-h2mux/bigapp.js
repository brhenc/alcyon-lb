// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//
// Large-body backend for the h2 soak traffic. Plain node http, no dependencies.
// Usage: node bigapp.js PORT LOGFILE
//   GET  /big/<n>  -> n bytes of 'a'
//   POST /up       -> reads the body, answers "got <bytes>"
// Every 60 s appends one line: ts conns reqs aborted (requests whose client went away)
const http = require('http');
const fs = require('fs');
const port = parseInt(process.argv[2], 10);
const logf = process.argv[3];
let conns = 0, reqs = 0, aborted = 0;
const srv = http.createServer((req, res) => {
  reqs++;
  res.on('close', () => { if (!res.writableFinished) aborted++; });
  if (req.method === 'POST') {
    let n = 0;
    req.on('data', (d) => { n += d.length; });
    req.on('end', () => {
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end('got ' + n);
    });
    return;
  }
  const m = /^\/big\/(\d+)/.exec(req.url);
  const n = m ? Math.min(parseInt(m[1], 10), 16 << 20) : 3;
  res.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Content-Length': n });
  res.end(Buffer.alloc(n, 'a'));
});
srv.on('connection', () => { conns++; });
srv.keepAliveTimeout = 30000;
srv.listen(port, '127.0.0.1');
setInterval(() => {
  fs.appendFileSync(logf, `${Math.floor(Date.now() / 1000)} conns=${conns} reqs=${reqs} aborted=${aborted}\n`);
}, 60000);
