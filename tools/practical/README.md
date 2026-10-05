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

## 06-browsers: Chrome / Firefox (headless) -> proxy (TLS, h2) -> node.js SPA

Needs `node` 22 (built-in WebSocket/fetch), `openssl`, `/usr/bin/google-chrome`, `/usr/bin/firefox`; no npm
packages (`app.js` hand-rolls the WebSocket echo). Ibex build:
`CARGO_TARGET_DIR=/home/bhenc/ibex-targets/t212 CARGO_INCREMENTAL=0 cargo build --release --bin ibex`.

    ./tools/practical/06-browsers/run.sh [--haproxy]     # BROWSERS=chrome to run one; KEEP=1 keeps /tmp/practical06-*

`driver.js` drives Chrome over CDP and Firefox over WebDriver BiDi (temporary profiles, cert accepted by
`--ignore-certificate-errors` / `acceptInsecureCerts`; the system trust store is untouched). Per browser, for
the first load and for a reload: every request h2, all 11 assets 200, no console errors, no failed requests,
API JSON, WebSocket text and 70 KB binary echo, SSE 5 events in order, `X-Forwarded-For`; plus
`nextHopProtocol` and (Chrome only; Firefox: SKIP, not observable) reload reuses the connection.
Ports 26001 (node), 26080 (proxy), 26010/26011 (browser debug). About 25 s.

## 05-node-cluster: 3 x node.js, roundrobin + health checks

Needs `node`, `curl`, `socat` (no npm packages, no wrk: the load is `load.js`). Build Ibex with
`CARGO_TARGET_DIR=/home/bhenc/ibex-targets/t181 CARGO_INCREMENTAL=0 cargo build --release --bin ibex`.

    cd tools/practical/05-node-cluster
    ./run.sh               # against Ibex
    ./run.sh --haproxy     # against HAProxy (oracle)

Takes about 80 s. `proxy.cfg`: `option httpchk`, `inter 500ms fall 2 rise 2`, `retries 3` and
`option redispatch 1`, and a second backend with `cookie SRV insert indirect nocache`. Cases: baseline
under load, kill one node by PID (DOWN within inter*fall + 500 ms, no errors from requests started
after that, only the two others serve), start it again (UP within inter*rise + 500 ms, no traffic
before UP, no errors), rolling restart of all three, cookie persistence (sessions stay; those of a
killed server move once and stay; nobody moves back; new sessions use the returned server). The
run ends with the `show stat` status changes over time. Ports 23001-23003 (nodes), 23080-23081
(proxy); other agents' HAProxy processes bind 180xx with SO_REUSEPORT, so avoid those.

## 02-nginx-h2: client -> proxy (TLS, h2) -> nginx -> node.js

Needs `nginx` (`/usr/sbin/nginx`, run unprivileged inside the work dir), `h2load`, `openssl`, `curl`,
`node`. `app.js` is reused from `01-node` (its `npm ci` runs there). Ibex build:
`CARGO_TARGET_DIR=/home/bhenc/ibex-targets/t193 CARGO_INCREMENTAL=0 cargo build --release --bin ibex`.
The self-signed certificate and the 20 MB static file are generated into the work dir (nothing committed).

    ./tools/practical/02-nginx-h2/run.sh [--haproxy]

`use_backend static if { path_beg /static/ }`: nginx block 1 serves the static files, block 2 proxies to
node. Cases: h2 via ALPN, 20 MB static sha256, dynamic request, 50 MB POST over h2 (sha256 echoed by
node), `h2load -n 2000 -c 10 -m 10` (0 failed/errored; req/s informational), `option forwardfor`,
backend 503 passthrough. Ports 24001 (node), 24011/24012 (nginx), 24080 (proxy). About 25 s.

## 04-nginx-front: client -> nginx -> proxy -> node.js

nginx's http module cannot send the PROXY protocol to an upstream; its `stream` module can
(`nginx-mod-stream`, a dynamic module). `run.sh` picks the mode: `stream` (`proxy_protocol on;` into the
proxy's `bind ... accept-proxy`) if `/usr/lib64/nginx/modules/ngx_stream_module.so` exists, otherwise
`http` (nginx builds the XFF chain, expected values differ and are set by the script). **On this machine
the stream module is not installed, so only the `http` mode has been run**; `ppclient.js` stands in for
nginx's stream module (sends a PROXY v1 line) so `accept-proxy` is still exercised (case
proxy-v1-direct). Install with `sudo dnf install nginx-mod-stream` and the PROXY path through real nginx
runs automatically (extra case log-source-nginx; untested).

    ./tools/practical/04-nginx-front/run.sh [--haproxy]

Clients use source 127.0.0.2 so the "real client" differs from nginx's 127.0.0.1. Cases: XFF with the
real client, XFF chain with a client-sent `X-Forwarded-For: 1.2.3.4`, PROXY v1 straight into
`accept-proxy`, keep-alive through nginx, 100 MB download sha256, WebSocket echo, proxy log line
shows the PROXY source (`log stdout format raw`). Ports 24040 (nginx), 24041 (node), 24042 (proxy plain),
24043 (proxy accept-proxy).

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

## 03-httpd: proxy -> httpd (mod_proxy) -> node.js, plus static files and CGI

Needs `node`, `curl`, `sha256sum`, `/usr/sbin/httpd` (2.4, modules in `/usr/lib64/httpd/modules`),
`python3` (the CGI scripts) and `~/.local/bin/wrk2`. Build Ibex with
`CARGO_TARGET_DIR=/home/bhenc/ibex-targets/t201 CARGO_INCREMENTAL=0 cargo build --release --bin ibex`.

    cd tools/practical/03-httpd
    ./run.sh               # against Ibex
    ./run.sh --haproxy     # against HAProxy (oracle)

Takes about 40 s. httpd runs unprivileged in the foreground from `httpd.conf` (filled in under
`$WORK`); `/static/` and `/cgi-bin/` go to httpd directly, everything else is `ProxyPass`ed to node.
Cases: keep-alive through both hops, 50 MB static sha256, `Range` (206), CGI GET with query string,
CGI POST echo (sha256), dynamic via httpd -> node, 50 MB chunked upload (sha256 at node),
`X-Forwarded-For` as node sees it (`127.0.0.2, 127.0.0.1`: `option forwardfor` plus httpd's append),
httpd 404 and CGI 500 passthrough, 3 s CGI under `timeout server 10s`, `wrk2 -t2 -c20 -d10s -R500`
(0 socket errors, 0 non-2xx; p99 printed, not judged). Ports 25001 (httpd), 25002 (node), 25080 (proxy).
