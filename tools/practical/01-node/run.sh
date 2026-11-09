#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
#
# Practical topology 01:  client (curl / node) -> proxy -> node.js app
#
#   ./run.sh              run against Alcyon
#   ./run.sh --haproxy    run against HAProxy (the oracle)
#
# Everything is started by this script and killed by PID at the end.
# Override any variable below from the environment, e.g.  SIZE_MB=10 ./run.sh

# ---- settings you may want to change ---------------------------------------
ALCYON_BIN=${ALCYON_BIN:-${ALCYON_TARGETS:-${XDG_CACHE_HOME:-$HOME/.cache}/alcyon/targets}/t167/release/alcyon}
HAPROXY_BIN=${HAPROXY_BIN:-${ALCYON_REFERENCE:?set ALCYON_REFERENCE (README, "Running the oracle tests") or HAPROXY_BIN}/haproxy/haproxy}
PROXY_PORT=${PROXY_PORT:-18080}     # where the proxy listens (clients connect here)
APP_PORT=${APP_PORT:-13000}         # where the node.js app listens
SIZE_MB=${SIZE_MB:-100}             # size of the upload and download cases
SSE_EVENTS=${SSE_EVENTS:-5}         # SSE case: number of events, one per second
WS_MESSAGES=${WS_MESSAGES:-100}     # WebSocket case: number of echoed messages
# -----------------------------------------------------------------------------

HERE=$(cd "$(dirname "$0")" && pwd)
PROXY=alcyon
[ "$1" = "--haproxy" ] && PROXY=haproxy
if [ "$PROXY" = alcyon ]; then PROXY_BIN=$ALCYON_BIN; else PROXY_BIN=$HAPROXY_BIN; fi

WORK=$(mktemp -d /tmp/practical01-XXXXXX)
BASE=http://127.0.0.1:$PROXY_PORT
BYTES=$((SIZE_MB * 1024 * 1024))
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

# ---- start the app ---------------------------------------------------------
[ -d "$HERE/node_modules" ] || (cd "$HERE" && npm ci --silent) || { echo "npm ci failed"; exit 2; }
DL_BYTES=$BYTES node "$HERE/app.js" "$APP_PORT" > "$WORK/app.log" 2>&1 &
PIDS="$PIDS $!"
wait_port "$APP_PORT" || { echo "app did not start"; cat "$WORK/app.log"; exit 2; }

# ---- start the proxy -------------------------------------------------------
sed -e "s/@PROXY_PORT@/$PROXY_PORT/" -e "s/@APP_PORT@/$APP_PORT/" "$HERE/proxy.cfg" > "$WORK/proxy.cfg"
"$PROXY_BIN" -c -f "$WORK/proxy.cfg" > "$WORK/check.log" 2>&1 \
    || { echo "$PROXY config check failed:"; cat "$WORK/check.log"; exit 2; }
"$PROXY_BIN" -f "$WORK/proxy.cfg" > "$WORK/proxy.log" 2>&1 &
PIDS="$PIDS $!"
wait_port "$PROXY_PORT" || { echo "$PROXY did not start"; cat "$WORK/proxy.log"; exit 2; }

echo "== topology 01 via $PROXY ($PROXY_BIN), size ${SIZE_MB} MB, work dir $WORK"

# ---- cases -----------------------------------------------------------------

# 1. keep-alive: two requests in one curl must reuse one client connection
out=$(curl -s -o /dev/null -o /dev/null -w '%{http_code} %{num_connects}\n' "$BASE/ka" "$BASE/ka" | tr '\n' ' ')
[ "$out" = "200 1 200 0 " ] && record keepalive 0 "$out" || record keepalive 1 "got '$out', want '200 1 200 0 '"

# 2. chunked upload: body streamed from stdin, so curl sends Transfer-Encoding: chunked
head -c "$BYTES" /dev/urandom > "$WORK/up.bin"
want=$(sha256sum < "$WORK/up.bin" | cut -d' ' -f1)
resp=$(curl -s -X POST -H 'Transfer-Encoding: chunked' -T - "$BASE/upload" < "$WORK/up.bin")
got=$(echo "$resp" | sed -n 's/.*"sha256":"\([0-9a-f]*\)".*/\1/p')
bytes=$(echo "$resp" | sed -n 's/.*"bytes":\([0-9]*\).*/\1/p')
if [ "$got" = "$want" ] && [ "$bytes" = "$BYTES" ]; then record upload-chunked 0 "$bytes bytes, sha256 ok"
else record upload-chunked 1 "response '$resp'"; fi

# 3. large download: size and sha256 against the X-Sha256 header the app sends
curl -s -D "$WORK/dl.hdr" -o "$WORK/dl.bin" "$BASE/download"
want=$(tr -d '\r' < "$WORK/dl.hdr" | sed -n 's/^[Xx]-[Ss]ha256: //p')
got=$(sha256sum < "$WORK/dl.bin" | cut -d' ' -f1)
size=$(stat -c %s "$WORK/dl.bin")
if [ "$got" = "$want" ] && [ "$size" = "$BYTES" ]; then record download 0 "$size bytes, sha256 ok"
else record download 1 "size $size want $BYTES, sha256 '$got' want '$want'"; fi
rm -f "$WORK/up.bin" "$WORK/dl.bin"

# 4. SSE: all events arrive, the first one promptly (not held back until the end)
curl -sN -w 'TTFB %{time_starttransfer}\n' "$BASE/sse?n=$SSE_EVENTS" > "$WORK/sse.out"
n=$(grep -c '^data: event' "$WORK/sse.out")
ttfb=$(sed -n 's/^TTFB //p' "$WORK/sse.out")
# "start" comment is sent at once, so TTFB must be well under 1 s if headers are not buffered
if [ "$n" = "$SSE_EVENTS" ] && awk "BEGIN{exit !($ttfb < 1.0)}"; then record sse 0 "$n events, first byte after ${ttfb}s"
else record sse 1 "$n events (want $SSE_EVENTS), first byte after ${ttfb}s (want < 1)"; fi

# 5. WebSocket echo: text messages and a 1 MB binary frame through the proxy
msg=$(node "$HERE/wsclient.js" "ws://127.0.0.1:$PROXY_PORT/ws" "$WS_MESSAGES" 2>&1)
[ $? = 0 ] && record websocket 0 "$msg" || record websocket 1 "$msg"

# 6. slow response: 5 s, must come back intact (timeout server is 30 s)
start=$(date +%s.%N)
body=$(curl -s -w ' %{http_code}' "$BASE/slow" | tr '\n' ' ')
el=$(awk "BEGIN{printf \"%.1f\", $(date +%s.%N) - $start}")
[ "$body" = "slow done  200" ] && awk "BEGIN{exit !($el >= 4.9)}" \
    && record slow 0 "200 after ${el}s" || record slow 1 "got '$body' after ${el}s"

# 7. backend 5xx: status and body pass through unchanged
out=$(curl -s -w ' %{http_code}' "$BASE/fail" | tr '\n' ' ')
[ "$out" = "backend failure  503" ] && record backend-503 0 "$out" || record backend-503 1 "got '$out'"

# 8. gzip done by the backend: Content-Encoding is kept, body decodes
out=$(curl -s --compressed -D "$WORK/gz.hdr" "$BASE/gzip" | wc -c)
enc=$(tr -d '\r' < "$WORK/gz.hdr" | sed -n 's/^[Cc]ontent-[Ee]ncoding: //p')
[ "$out" = 10000 ] && [ "$enc" = gzip ] && record gzip-backend 0 "$out bytes decoded, encoding $enc" \
    || record gzip-backend 1 "$out bytes, encoding '$enc'"

# ---- results ---------------------------------------------------------------
echo
echo "RESULTS ($PROXY)"
printf '%s\n' "${RESULTS[@]}"
echo "$FAILS failed"
rm -rf "$WORK"
[ "$FAILS" = 0 ]
