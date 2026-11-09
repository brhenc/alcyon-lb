#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
#
# Practical topology 06:  Chrome / Firefox (headless) -> proxy (TLS, h2) -> node.js SPA
#
#   ./run.sh              run against Alcyon
#   ./run.sh --haproxy    run against HAProxy (the oracle)
#   BROWSERS="chrome" ./run.sh   only one browser
#
# Needs node 22 (built-in WebSocket/fetch), openssl, google-chrome, firefox. No npm packages.
# The certificate is generated into the work dir and accepted by browser flags/capabilities;
# the system trust store is never touched. Everything is killed by PID and the work dir removed.

# ---- settings you may want to change ---------------------------------------
ALCYON_BIN=${ALCYON_BIN:-/home/bhenc/ibex-targets/t212/release/alcyon}
HAPROXY_BIN=${HAPROXY_BIN:-/home/bhenc/reference/haproxy/haproxy}
APP_PORT=${APP_PORT:-26001}
PROXY_PORT=${PROXY_PORT:-26080}
CHROME_DEBUG_PORT=${CHROME_DEBUG_PORT:-26010}
FIREFOX_DEBUG_PORT=${FIREFOX_DEBUG_PORT:-26011}
BROWSERS=${BROWSERS:-"chrome firefox"}
KEEP=${KEEP:-0}                         # KEEP=1 leaves the work dir (logs) in /tmp
# -----------------------------------------------------------------------------

HERE=$(cd "$(dirname "$0")" && pwd)
PROXY=alcyon
[ "$1" = "--haproxy" ] && PROXY=haproxy
if [ "$PROXY" = alcyon ]; then PROXY_BIN=$ALCYON_BIN; else PROXY_BIN=$HAPROXY_BIN; fi

WORK=$(mktemp -d /tmp/practical06-XXXXXX)
PIDS=""
cleanup() {
    for p in $PIDS; do kill "$p" 2>/dev/null; done; wait 2>/dev/null
    [ "$KEEP" = 1 ] || rm -rf "$WORK"
}
trap cleanup EXIT

wait_port() {
    for _ in $(seq 100); do
        (exec 3<>/dev/tcp/127.0.0.1/"$1") 2>/dev/null && return 0
        sleep 0.1
    done
    return 1
}

openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=localhost \
    -addext "subjectAltName=IP:127.0.0.1,DNS:localhost" \
    -keyout "$WORK/key.pem" -out "$WORK/crt.pem" > /dev/null 2>&1 || { echo "openssl failed"; exit 2; }
cat "$WORK/crt.pem" "$WORK/key.pem" > "$WORK/cert.pem"

node "$HERE/app.js" "$APP_PORT" > "$WORK/app.log" 2>&1 &
PIDS="$PIDS $!"
wait_port "$APP_PORT" || { echo "app did not start"; cat "$WORK/app.log"; exit 2; }

sed -e "s#@PROXY_PORT@#$PROXY_PORT#g" -e "s#@APP_PORT@#$APP_PORT#g" -e "s#@CERT@#$WORK/cert.pem#g" \
    "$HERE/proxy.cfg" > "$WORK/proxy.cfg"
"$PROXY_BIN" -c -f "$WORK/proxy.cfg" > "$WORK/check.log" 2>&1 \
    || { echo "$PROXY config check failed:"; cat "$WORK/check.log"; exit 2; }
"$PROXY_BIN" -f "$WORK/proxy.cfg" > "$WORK/proxy.log" 2>&1 &
PIDS="$PIDS $!"
wait_port "$PROXY_PORT" || { echo "$PROXY did not start"; cat "$WORK/proxy.log"; exit 2; }

echo "== topology 06 via $PROXY ($PROXY_BIN), work dir $WORK"
FAILS=0
for b in $BROWSERS; do
    if [ "$b" = chrome ]; then dp=$CHROME_DEBUG_PORT; else dp=$FIREFOX_DEBUG_PORT; fi
    node "$HERE/driver.js" "$b" "https://127.0.0.1:$PROXY_PORT" "$WORK" "$dp" 2>&1 | tee -a "$WORK/results.txt"
done
FAILS=$(grep -c '^FAIL' "$WORK/results.txt")
echo "== $PROXY: $(grep -c '^PASS' "$WORK/results.txt") passed, $FAILS failed, $(grep -c '^SKIP' "$WORK/results.txt") skipped"
[ "$KEEP" = 1 ] && cp "$WORK/results.txt" /tmp/practical06-last-$PROXY.txt
[ "$FAILS" = 0 ]
