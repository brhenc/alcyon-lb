// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//
// Stand-in for nginx's stream module (used only when that module is not installed):
// sends a PROXY v1 line, then a GET. Prints the response body.
// Usage: node ppclient.js PORT SRC_IP PATH [EXTRA_HEADER]
const net = require('net');
const [port, src, path, extra] = process.argv.slice(2);
const s = net.connect(+port, '127.0.0.1', () => {
  s.write(`PROXY TCP4 ${src} 127.0.0.1 54321 ${port}\r\nGET ${path} HTTP/1.1\r\nHost: x\r\n` +
    (extra ? extra + '\r\n' : '') + 'Connection: close\r\n\r\n');
});
let buf = '';
s.on('data', (d) => { buf += d; });
s.on('end', () => { process.stdout.write(buf.split('\r\n\r\n').slice(1).join('\r\n\r\n')); });
s.on('error', (e) => { console.error(e.message); process.exit(1); });
