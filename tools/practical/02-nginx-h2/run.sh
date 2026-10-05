#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
#
# Practical topology 02:  client (curl, h2load) -> proxy (TLS, h2) -> nginx -> node.js
#   /static/*  -> nginx as a static-file server        (use_backend static)
#   anything else -> nginx as a proxy to the node app  (default backend dyn)
#
#   ./run.sh              run against Ibex
#   ./run.sh --haproxy    run against HAProxy (the oracle)
#
# Needs node, curl, openssl, sha256sum, h2load, nginx. Everything is started by this
# script and killed by PID at the end. The certificate is generated into the work dir.

# ---- settings you may want to change ---------------------------------------
IBEX_BIN=${IBEX_BIN:-/home/bhenc/ibex-targets/t193/release/ibex}
HAPROXY_BIN=${HAPROXY_BIN:-/home/bhenc/reference/haproxy/haproxy}
NGINX_BIN=${NGINX_BIN:-/usr/sbin/nginx}
H2LOAD_BIN=${H2LOAD_BIN:-/usr/bin/h2load}
PROXY_PORT=${PROXY_PORT:-24080}         # proxy, TLS (clients connect here)
NGX_DYN_PORT=${NGX_DYN_PORT:-24011}     # nginx server block proxying to node
NGX_STATIC_PORT=${NGX_STATIC_PORT:-24012}  # nginx server block serving static files
APP_PORT=${APP_PORT:-24001}             # node.js app
STATIC_MB=${STATIC_MB:-20}
UPLOAD_MB=${UPLOAD_MB:-50}
# -----------------------------------------------------------------------------

HERE=$(cd "$(dirname "$0")" && pwd)
NODE_DIR=$HERE/../01-node           # app.js (and its ws package) are reused
PROXY=ibex
[ "$1" = "--haproxy" ] && PROXY=haproxy
if [ "$PROXY" = ibex ]; then PROXY_BIN=$IBEX_BIN; else PROXY_BIN=$HAPROXY_BIN; fi

WORK=$(mktemp -d /tmp/practical02-XXXXXX)
BASE=https://127.0.0.1:$PROXY_PORT
PIDS=""
RESULTS=()
FAILS=0

cleanup() { for p in $PIDS; do kill "$p" 2>/dev/null; done; wait 2>/dev/null; }
trap cleanup EXIT

# record NAME OK(0/1) DETAIL
record() {
    if [ "$2" = 0 ]; then RESULTS+=("PASS  $1  $3"); else RESULTS+=("FAIL  $1  $3"); FAILS=$((FAILS+1)); fi
}

wait_port() {   # wait_port PORT : up to 10 s
    for _ in $(seq 100); do
        (exec 3<>/dev/tcp/127.0.0.1/"$1") 2>/dev/null && return 0
        sleep 0.1
    done
    return 1
}

fill() { sed -e "s#@WORK@#$WORK#g" -e "s#@PROXY_PORT@#$PROXY_PORT#g" -e "s#@APP_PORT@#$APP_PORT#g" \
    -e "s#@NGX_DYN_PORT@#$NGX_DYN_PORT#g" -e "s#@NGX_STATIC_PORT@#$NGX_STATIC_PORT#g" \
    -e "s#@CERT@#$WORK/cert.pem#g" "$1" > "$2"; }

# ---- certificate, static file, app, nginx, proxy ---------------------------
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=localhost \
    -keyout "$WORK/key.pem" -out "$WORK/crt.pem" > /dev/null 2>&1 || { echo "openssl failed"; exit 2; }
cat "$WORK/crt.pem" "$WORK/key.pem" > "$WORK/cert.pem"
mkdir -p "$WORK/static" "$WORK/tmp"
head -c $((STATIC_MB * 1024 * 1024)) /dev/urandom > "$WORK/static/big.bin"

[ -d "$NODE_DIR/node_modules" ] || (cd "$NODE_DIR" && npm ci --silent) || { echo "npm ci failed"; exit 2; }
node "$NODE_DIR/app.js" "$APP_PORT" > "$WORK/app.log" 2>&1 &
PIDS="$PIDS $!"
wait_port "$APP_PORT" || { echo "app did not start"; cat "$WORK/app.log"; exit 2; }

fill "$HERE/nginx.conf" "$WORK/nginx.conf"
"$NGINX_BIN" -p "$WORK" -c "$WORK/nginx.conf" -e "$WORK/nginx-error.log" > "$WORK/nginx.log" 2>&1 &
PIDS="$PIDS $!"
wait_port "$NGX_DYN_PORT" && wait_port "$NGX_STATIC_PORT" || { echo "nginx did not start"; cat "$WORK/nginx.log" "$WORK/nginx-error.log"; exit 2; }

fill "$HERE/proxy.cfg" "$WORK/proxy.cfg"
"$PROXY_BIN" -c -f "$WORK/proxy.cfg" > "$WORK/check.log" 2>&1 \
    || { echo "$PROXY config check failed:"; cat "$WORK/check.log"; exit 2; }
"$PROXY_BIN" -f "$WORK/proxy.cfg" > "$WORK/proxy.log" 2>&1 &
PIDS="$PIDS $!"
wait_port "$PROXY_PORT" || { echo "$PROXY did not start"; cat "$WORK/proxy.log"; exit 2; }

echo "== topology 02 via $PROXY ($PROXY_BIN), work dir $WORK"

# ---- cases -----------------------------------------------------------------

# 1. h2 negotiated through ALPN
out=$(curl -sk --http2 -o /dev/null -w '%{http_version}' "$BASE/ka")
[ "$out" = 2 ] && record h2-alpn 0 "http_version $out" || record h2-alpn 1 "http_version '$out', want 2"

# 2. static file from nginx over h2: size and sha256
want=$(sha256sum < "$WORK/static/big.bin" | cut -d' ' -f1)
curl -sk --http2 -o "$WORK/dl.bin" -w '%{http_version}' "$BASE/static/big.bin" > "$WORK/ver"
got=$(sha256sum < "$WORK/dl.bin" | cut -d' ' -f1); size=$(stat -c %s "$WORK/dl.bin")
if [ "$got" = "$want" ] && [ "$size" = $((STATIC_MB * 1024 * 1024)) ] && [ "$(cat "$WORK/ver")" = 2 ]; then
    record static-h2 0 "$size bytes, sha256 ok, http $(cat "$WORK/ver")"
else record static-h2 1 "size $size, sha256 '$got' want '$want', http $(cat "$WORK/ver")"; fi
rm -f "$WORK/dl.bin"

# 3. dynamic request: proxy -> nginx -> node
out=$(curl -sk --http2 -w ' %{http_code}' "$BASE/ka" | tr '\n' ' ')
[ "$out" = "hello from node  200" ] && record dynamic 0 "$out" || record dynamic 1 "got '$out'"

# 4. upload over h2: node echoes the sha256 of what it received
head -c $((UPLOAD_MB * 1024 * 1024)) /dev/urandom > "$WORK/up.bin"
want=$(sha256sum < "$WORK/up.bin" | cut -d' ' -f1)
resp=$(curl -sk --http2 -X POST --data-binary @"$WORK/up.bin" -H 'Content-Type: application/octet-stream' "$BASE/upload")
got=$(echo "$resp" | sed -n 's/.*"sha256":"\([0-9a-f]*\)".*/\1/p')
bytes=$(echo "$resp" | sed -n 's/.*"bytes":\([0-9]*\).*/\1/p')
if [ "$got" = "$want" ] && [ "$bytes" = $((UPLOAD_MB * 1024 * 1024)) ]; then record upload-h2 0 "$bytes bytes, sha256 ok"
else record upload-h2 1 "response '$resp'"; fi
rm -f "$WORK/up.bin"

# 5. multiplexed load: h2load, 10 connections x 10 streams; req/s is informational only
"$H2LOAD_BIN" -n 2000 -c 10 -m 10 "$BASE/ka" > "$WORK/h2load.out" 2>&1
line=$(grep '^requests:' "$WORK/h2load.out")
rps=$(sed -n 's/^finished in .*, \([0-9.]*\) req\/s.*/\1/p' "$WORK/h2load.out")
if echo "$line" | grep -q ' 2000 succeeded, 0 failed, 0 errored'; then record h2load 0 "2000 succeeded, $rps req/s (informational)"
else record h2load 1 "'$line'"; fi

# 6. option forwardfor: node sees the client address (the proxy's peer), over h2
out=$(curl -sk --http2 "$BASE/headers" | sed -n 's/.*"xff":"\([^"]*\)".*/\1/p')
[ "$out" = 127.0.0.1 ] && record forwardfor 0 "xff $out" || record forwardfor 1 "xff '$out', want 127.0.0.1"

# 7. backend 503 passes through nginx and the proxy unchanged
out=$(curl -sk --http2 -w ' %{http_code}' "$BASE/fail" | tr '\n' ' ')
[ "$out" = "backend failure  503" ] && record backend-503 0 "$out" || record backend-503 1 "got '$out'"

# ---- results ---------------------------------------------------------------
echo
echo "RESULTS ($PROXY)"
printf '%s\n' "${RESULTS[@]}"
echo "$FAILS failed"
rm -rf "$WORK"
[ "$FAILS" = 0 ]
