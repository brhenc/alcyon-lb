// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//
// Constant load (wrk is not installed here). Usage: node load.js URL CLIENTS LOGFILE
// CLIENTS keep-alive clients loop forever; one line per request: "start_ms status srv duration_ms",
// start_ms is when the request began; status is the HTTP code or ERR (connect/reset/timeout), srv is the X-Srv header or -.
// Stops on SIGTERM.
const http = require('http');
const fs = require('fs');
const [url, nc, logf] = [process.argv[2], parseInt(process.argv[3] || '8', 10), process.argv[4]];
const agent = new http.Agent({ keepAlive: true });
const out = fs.openSync(logf, 'w');
let buf = [];
const flush = () => { if (buf.length) { fs.writeSync(out, buf.join('')); buf = []; } };
setInterval(flush, 200);
process.on('SIGTERM', () => { flush(); process.exit(0); });
function one() {
  const t0 = Date.now();
  const req = http.get(url, { agent, timeout: 3000 }, (res) => {
    res.resume();
    res.on('end', () => { buf.push(`${t0} ${res.statusCode} ${res.headers["x-srv"] || "-"} ${Date.now() - t0}\n`); setTimeout(one, 3); });
  });
  req.on('timeout', () => req.destroy());
  req.once('error', () => { buf.push(`${t0} ERR - ${Date.now() - t0}\n`); setTimeout(one, 3); });
}
for (let i = 0; i < nc; i++) one();
