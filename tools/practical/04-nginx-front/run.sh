#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
#
# Practical topology 04:  client -> nginx -> proxy -> node.js
#
# nginx's http module cannot send the PROXY protocol to an upstream; only its stream
# module can (package nginx-mod-stream, dynamic module). Two modes, chosen automatically:
#   MODE=stream  nginx stream { proxy_protocol on; } -> proxy bind ... accept-proxy
#   MODE=http    stream module not installed: nginx http proxy with its own
#                X-Forwarded-For chain; the PROXY-protocol part is then covered only by
#                the stand-in client ppclient.js (case proxy-v1-direct).
#
#   ./run.sh              run against Alcyon
#   ./run.sh --haproxy    run against HAProxy (the oracle)
#
# Needs node, curl, sha256sum, nginx. The clients use 127.0.0.2 as their source address so
# that "the real client" differs from nginx's own address (127.0.0.1).

# ---- settings you may want to change ---------------------------------------
ALCYON_BIN=${ALCYON_BIN:-/home/bhenc/ibex-targets/t193/release/alcyon}
HAPROXY_BIN=${HAPROXY_BIN:-/home/bhenc/reference/haproxy/haproxy}
NGINX_BIN=${NGINX_BIN:-/usr/sbin/nginx}
STREAM_MODULE=${STREAM_MODULE:-/usr/lib64/nginx/modules/ngx_stream_module.so}
NGX_PORT=${NGX_PORT:-24040}         # nginx (clients connect here)
APP_PORT=${APP_PORT:-24041}         # node.js app
PLAIN_PORT=${PLAIN_PORT:-24042}     # proxy, plain bind (nginx http mode)
PP_PORT=${PP_PORT:-24043}           # proxy, bind ... accept-proxy
SIZE_MB=${SIZE_MB:-100}
WS_MESSAGES=${WS_MESSAGES:-100}
# -----------------------------------------------------------------------------

HERE=$(cd "$(dirname "$0")" && pwd)
NODE_DIR=$HERE/../01-node           # app.js, wsclient.js (and the ws package) are reused
PROXY=alcyon
[ "$1" = "--haproxy" ] && PROXY=haproxy
if [ "$PROXY" = alcyon ]; then PROXY_BIN=$ALCYON_BIN; else PROXY_BIN=$HAPROXY_BIN; fi
if [ -r "$STREAM_MODULE" ]; then MODE=stream; else MODE=http; fi

WORK=$(mktemp -d /tmp/practical04-XXXXXX)
BASE=http://127.0.0.1:$NGX_PORT
BYTES=$((SIZE_MB * 1024 * 1024))
PIDS=""
RESULTS=()
FAILS=0

cleanup() { for p in $PIDS; do kill "$p" 2>/dev/null; done; wait 2>/dev/null; }
trap cleanup EXIT

record() {   # record NAME OK(0/1) DETAIL
    if [ "$2" = 0 ]; then RESULTS+=("PASS  $1  $3"); else RESULTS+=("FAIL  $1  $3"); FAILS=$((FAILS+1)); fi
}

wait_port() {   # wait_port PORT : up to 10 s
    for _ in $(seq 100); do
        (exec 3<>/dev/tcp/127.0.0.1/"$1") 2>/dev/null && return 0
        sleep 0.1
    done
    return 1
}

fill() { sed -e "s#@WORK@#$WORK#g" -e "s#@APP_PORT@#$APP_PORT#g" -e "s#@NGX_PORT@#$NGX_PORT#g" \
    -e "s#@PLAIN_PORT@#$PLAIN_PORT#g" -e "s#@PP_PORT@#$PP_PORT#g" -e "s#@STREAM_MODULE@#$STREAM_MODULE#g" "$1" > "$2"; }

# ---- app, proxy, nginx (back to front) -------------------------------------
mkdir -p "$WORK/tmp"
[ -d "$NODE_DIR/node_modules" ] || (cd "$NODE_DIR" && npm ci --silent) || { echo "npm ci failed"; exit 2; }
DL_BYTES=$BYTES node "$NODE_DIR/app.js" "$APP_PORT" > "$WORK/app.log" 2>&1 &
PIDS="$PIDS $!"
wait_port "$APP_PORT" || { echo "app did not start"; cat "$WORK/app.log"; exit 2; }

fill "$HERE/proxy.cfg" "$WORK/proxy.cfg"
"$PROXY_BIN" -c -f "$WORK/proxy.cfg" > "$WORK/check.log" 2>&1 \
    || { echo "$PROXY config check failed:"; cat "$WORK/check.log"; exit 2; }
"$PROXY_BIN" -f "$WORK/proxy.cfg" > "$WORK/proxy.log" 2>&1 &
PIDS="$PIDS $!"
wait_port "$PLAIN_PORT" || { echo "$PROXY did not start"; cat "$WORK/proxy.log"; exit 2; }

fill "$HERE/nginx-$MODE.conf" "$WORK/nginx.conf"
"$NGINX_BIN" -p "$WORK" -c "$WORK/nginx.conf" -e "$WORK/nginx-error.log" > "$WORK/nginx.log" 2>&1 &
PIDS="$PIDS $!"
wait_port "$NGX_PORT" || { echo "nginx did not start"; cat "$WORK/nginx.log" "$WORK/nginx-error.log"; exit 2; }

echo "== topology 04 via $PROXY ($PROXY_BIN), nginx mode $MODE, work dir $WORK"

xff() { sed -n 's/.*"xff":"\([^"]*\)".*/\1/p'; }
if [ "$MODE" = stream ]; then WANT_REAL=127.0.0.2; WANT_CHAIN="1.2.3.4, 127.0.0.2"
else WANT_REAL="127.0.0.2, 127.0.0.1"; WANT_CHAIN="1.2.3.4, 127.0.0.2, 127.0.0.1"; fi

# ---- cases -----------------------------------------------------------------

# 1. the address node sees is the real client (not nginx's 127.0.0.1)
out=$(curl -s --interface 127.0.0.2 "$BASE/headers" | xff)
[ "$out" = "$WANT_REAL" ] && record xff-real-client 0 "xff '$out'" || record xff-real-client 1 "xff '$out', want '$WANT_REAL'"

# 2. client already sends X-Forwarded-For: the chain is kept and extended
out=$(curl -s --interface 127.0.0.2 -H 'X-Forwarded-For: 1.2.3.4' "$BASE/headers" | xff)
[ "$out" = "$WANT_CHAIN" ] && record xff-chain 0 "xff '$out'" || record xff-chain 1 "xff '$out', want '$WANT_CHAIN'"

# 3. PROXY protocol v1 straight into the accept-proxy bind (nginx stand-in), with a chain
out=$(node "$HERE/ppclient.js" "$PP_PORT" 10.9.8.7 /headers 'X-Forwarded-For: 1.2.3.4' | xff)
[ "$out" = "1.2.3.4, 10.9.8.7" ] && record proxy-v1-direct 0 "xff '$out'" || record proxy-v1-direct 1 "xff '$out', want '1.2.3.4, 10.9.8.7'"

# 4. keep-alive through nginx: two requests, one client connection
out=$(curl -s -o /dev/null -o /dev/null -w '%{http_code} %{num_connects}\n' "$BASE/ka" "$BASE/ka" | tr '\n' ' ')
[ "$out" = "200 1 200 0 " ] && record keepalive 0 "$out" || record keepalive 1 "got '$out', want '200 1 200 0 '"

# 5. 100 MB download: size and sha256 against the X-Sha256 header the app sends
curl -s -D "$WORK/dl.hdr" -o "$WORK/dl.bin" "$BASE/download"
want=$(tr -d '\r' < "$WORK/dl.hdr" | sed -n 's/^[Xx]-[Ss]ha256: //p')
got=$(sha256sum < "$WORK/dl.bin" | cut -d' ' -f1); size=$(stat -c %s "$WORK/dl.bin")
if [ "$got" = "$want" ] && [ "$size" = "$BYTES" ]; then record download 0 "$size bytes, sha256 ok"
else record download 1 "size $size want $BYTES, sha256 '$got' want '$want'"; fi
rm -f "$WORK/dl.bin"

# 6. WebSocket echo through nginx and the proxy
msg=$(node "$NODE_DIR/wsclient.js" "ws://127.0.0.1:$NGX_PORT/ws" "$WS_MESSAGES" 2>&1)
[ $? = 0 ] && record websocket 0 "$msg" || record websocket 1 "$msg"

# 7. the proxy's log line shows the PROXY-protocol source address (case 3's client, 10.9.8.7:54321)
sleep 0.5
line=$(grep 'GET /headers' "$WORK/proxy.log" | grep -E '^10\.9\.8\.7:54321 ' | head -1)
if [ -n "$line" ]; then record log-source 0 "$(echo "$line" | cut -c1-120)"
else record log-source 1 "no line with 10.9.8.7:54321; log: $(tail -3 "$WORK/proxy.log" | cut -c1-120 | tr '\n' '|')"; fi
if [ "$MODE" = stream ]; then
    line=$(grep 'GET /headers' "$WORK/proxy.log" | grep -E '^127\.0\.0\.2:[0-9]+ ' | head -1)
    [ -n "$line" ] && record log-source-nginx 0 "$(echo "$line" | cut -c1-120)" \
        || record log-source-nginx 1 "no log line with source 127.0.0.2 (via nginx stream)"
fi

# ---- results ---------------------------------------------------------------
echo
echo "RESULTS ($PROXY, nginx $MODE)"
printf '%s\n' "${RESULTS[@]}"
echo "$FAILS failed"
rm -rf "$WORK"
[ "$FAILS" = 0 ]
