<!--
SPDX-License-Identifier: GPL-2.0-or-later
Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
-->
# Practical topologies

Each directory is one real-software setup (see "Practical testing" in
`docs/milestones.md`). Every one is run against Ibex and against HAProxy; the PASS/FAIL
tables must be the same.

## 01-node: client -> proxy -> node.js

Needs `node`, `npm`, `curl`, `sha256sum` (all installed). Ibex is built with:

    CARGO_TARGET_DIR=/home/bhenc/ibex-targets/t167 CARGO_INCREMENTAL=0 cargo build --release --bin ibex

Run:

    cd tools/practical/01-node
    ./run.sh               # against Ibex
    ./run.sh --haproxy     # against HAProxy (oracle)
    SIZE_MB=10 ./run.sh    # smaller upload/download

Settings (binaries, ports, sizes) are variables at the top of `run.sh`; each can be set
from the environment. The script runs `npm ci` the first time (`node_modules/` is not
committed), starts the app and the proxy, runs the cases, prints a PASS/FAIL table, and
kills what it started by PID. Exit status is 0 only if every case passed. The proxy's
config is `proxy.cfg`, the same file for both proxies; `run.sh` fills in the ports.

Cases: keep-alive (one connection for two requests), 100 MB chunked upload (sha256), 100 MB
download (sha256), SSE (events arrive one per second, first byte at once), WebSocket echo
(text and 1 MB binary), 5 s slow response, backend 503 passthrough, backend-made gzip.

## Adding a topology (nginx, apache2, ...)

1. Copy `01-node` to `NN-name`; keep `app.js` if node stays at the back.
2. In `run.sh`, add the new daemon next to the app: a variable for its binary and port at
   the top, a config file it reads, a start line that appends its PID to `PIDS`, and a
   `wait_port` for it.
3. Point `proxy.cfg` at the new daemon (or put the daemon in front: the clients then
   connect to its port instead of `PROXY_PORT`).
4. Add cases with `record NAME 0|1 "detail"`; keep each case one short block.
5. Run with and without `--haproxy`. File every difference as `tasks/T17x-practical-*.md`
   with the exact command, HAProxy's output and Ibex's.
