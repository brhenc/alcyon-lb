// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//
// WebSocket echo check. Usage: node wsclient.js URL [COUNT]
// Sends COUNT text messages plus one 1 MB binary message; exits 0 if all come back intact.
const WebSocket = require('ws');
const url = process.argv[2];
const count = parseInt(process.argv[3] || '100', 10);
const ws = new WebSocket(url);
const big = Buffer.alloc(1024 * 1024, 0xab);
let got = 0, bad = 0, gotBig = false;
const timer = setTimeout(() => { console.log('timeout'); process.exit(2); }, 15000);
ws.on('open', () => {
  for (let i = 0; i < count; i++) ws.send('msg ' + i);
  ws.send(big);
});
ws.on('message', (d, isBin) => {
  if (isBin) { gotBig = Buffer.compare(d, big) === 0; if (!gotBig) bad++; }
  else { if (d.toString() !== 'msg ' + got) bad++; got++; }
  if (got === count && (gotBig || bad)) {
    clearTimeout(timer);
    console.log(`echoed ${got} text + big binary, bad=${bad}`);
    ws.close(); process.exit(bad ? 1 : 0);
  }
});
ws.on('error', (e) => { console.log('error ' + e.message); process.exit(3); });
