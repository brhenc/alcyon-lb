// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//
// Test backend for practical topology 05. Plain node http, no dependencies.
// Usage: node app.js PORT NAME     answers "NAME" on every path, also /health.
const http = require('http');
const port = parseInt(process.argv[2] || '3000', 10);
const name = process.argv[3] || 'n' + port;
http.createServer((req, res) => {
  res.writeHead(200, { 'Content-Type': 'text/plain', 'X-Srv': name });
  res.end(name + '\n');
}).listen(port, '127.0.0.1');
