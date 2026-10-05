#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
#
# Practical topology 03:  client -> proxy -> httpd (mod_proxy) -> node.js
#                         and httpd serving static files and a CGI app
#
#   ./run.sh              run against Ibex
#   ./run.sh --haproxy    run against HAProxy (the oracle)
#
# Everything is started by this script and killed by PID at the end.

# ---- settings you may want to change ---------------------------------------
IBEX_BIN=${IBEX_BIN:-/home/bhenc/ibex-targets/t201/release/ibex}
HAPROXY_BIN=${HAPROXY_BIN:-/home/bhenc/reference/haproxy/haproxy}
HTTPD_BIN=${HTTPD_BIN:-/usr/sbin/httpd}
HTTPD_MODS=${HTTPD_MODS:-/usr/lib64/httpd/modules}
WRK2=${WRK2:-$HOME/.local/bin/wrk2}
PROXY_PORT=${PROXY_PORT:-25080}     # where the proxy listens (clients connect here)
HTTPD_PORT=${HTTPD_PORT:-25001}     # httpd
NODE_PORT=${NODE_PORT:-25002}       # node.js app
SIZE_MB=${SIZE_MB:-50}              # size of the static file and of the upload
LOAD_RATE=${LOAD_RATE:-500}
LOAD_SECS=${LOAD_SECS:-10}
# -----------------------------------------------------------------------------

HERE=$(cd "$(dirname "$0")" && pwd)
PROXY=ibex
[ "$1" = "--haproxy" ] && PROXY=haproxy
if [ "$PROXY" = ibex ]; then PROXY_BIN=$IBEX_BIN; else PROXY_BIN=$HAPROXY_BIN; fi

WORK=$(mktemp -d /tmp/practical03-XXXXXX)
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

jfield() { sed -n "s/.*\"$1\":\"\\{0,1\\}\\([^\",}]*\\).*/\\1/p"; }

# ---- start node, httpd -----------------------------------------------------
node "$HERE/app.js" "$NODE_PORT" > "$WORK/app.log" 2>&1 &
PIDS="$PIDS $!"
wait_port "$NODE_PORT" || { echo "app did not start"; cat "$WORK/app.log"; exit 2; }

mkdir -p "$WORK/run" "$WORK/htdocs/static"
head -c "$BYTES" /dev/urandom > "$WORK/htdocs/static/big.bin"
SRC_SHA=$(sha256sum < "$WORK/htdocs/static/big.bin" | cut -d' ' -f1)
echo "hello static" > "$WORK/htdocs/static/hello.txt"
sed -e "s|@WORK@|$WORK|g" -e "s|@HERE@|$HERE|g" -e "s|@MODS@|$HTTPD_MODS|g" \
    -e "s/@HTTPD_PORT@/$HTTPD_PORT/g" -e "s/@NODE_PORT@/$NODE_PORT/g" "$HERE/httpd.conf" > "$WORK/httpd.conf"
"$HTTPD_BIN" -f "$WORK/httpd.conf" -DFOREGROUND > "$WORK/httpd.log" 2>&1 &
HTTPD_PID=$!
PIDS="$PIDS $HTTPD_PID"
wait_port "$HTTPD_PORT" || { echo "httpd did not start"; cat "$WORK/httpd.log" "$WORK/httpd-error.log"; exit 2; }

# ---- start the proxy -------------------------------------------------------
sed -e "s/@PROXY_PORT@/$PROXY_PORT/" -e "s/@HTTPD_PORT@/$HTTPD_PORT/" "$HERE/proxy.cfg" > "$WORK/proxy.cfg"
"$PROXY_BIN" -c -f "$WORK/proxy.cfg" > "$WORK/check.log" 2>&1 \
    || { echo "$PROXY config check failed:"; cat "$WORK/check.log"; exit 2; }
"$PROXY_BIN" -f "$WORK/proxy.cfg" > "$WORK/proxy.log" 2>&1 &
PIDS="$PIDS $!"
wait_port "$PROXY_PORT" || { echo "$PROXY did not start"; cat "$WORK/proxy.log"; exit 2; }

echo "== topology 03 via $PROXY ($PROXY_BIN), size ${SIZE_MB} MB, work dir $WORK"

# ---- cases -----------------------------------------------------------------

# 1. keep-alive through both hops: one client connection for two requests, and the same
#    connection seen behind each hop (CGI REMOTE_PORT = proxy->httpd; node's remotePort = httpd->node)
c=$(curl -s -o /dev/null -o /dev/null -w '%{num_connects} ' "$BASE/cgi-bin/echo.cgi" "$BASE/cgi-bin/echo.cgi")
set -- $(curl -s "$BASE/cgi-bin/echo.cgi" "$BASE/cgi-bin/echo.cgi" | sed -n 's/.* port=//p')
p1=$1; p2=$2
set -- $(curl -s "$BASE/ka" "$BASE/ka" | jfield port)
[ "$c" = "1 0 " ] && [ -n "$p1" ] && [ "$p1" = "$p2" ] && [ -n "$1" ] && [ "$1" = "$2" ] \
    && record keepalive 0 "client conn reused; httpd-side port same twice; node-side port same twice" \
    || record keepalive 1 "num_connects '$c', cgi ports '$p1' '$p2', node ports '$1' '$2'"

# 2. static 50 MB: sha256
curl -s -o "$WORK/dl.bin" "$BASE/static/big.bin"
got=$(sha256sum < "$WORK/dl.bin" | cut -d' ' -f1); size=$(stat -c %s "$WORK/dl.bin")
[ "$got" = "$SRC_SHA" ] && [ "$size" = "$BYTES" ] && record static-sha 0 "$size bytes, sha256 ok" \
    || record static-sha 1 "size $size want $BYTES, sha '$got' want '$SRC_SHA'"
rm -f "$WORK/dl.bin"

# 3. Range on the static file: 206, Content-Range, exact bytes
code=$(curl -s -H 'Range: bytes=1000000-1999999' -D "$WORK/rg.hdr" -o "$WORK/rg.bin" -w '%{http_code}' "$BASE/static/big.bin")
cr=$(tr -d '\r' < "$WORK/rg.hdr" | sed -n 's/^[Cc]ontent-[Rr]ange: //p')
want=$(dd if="$WORK/htdocs/static/big.bin" bs=1000000 skip=1 count=1 2>/dev/null | sha256sum | cut -d' ' -f1)
got=$(sha256sum < "$WORK/rg.bin" | cut -d' ' -f1)
[ "$code" = 206 ] && [ "$cr" = "bytes 1000000-1999999/$BYTES" ] && [ "$got" = "$want" ] \
    && record range 0 "206, $cr, bytes ok" || record range 1 "code $code, content-range '$cr', sha ok=$([ "$got" = "$want" ] && echo y || echo n)"

# 4. CGI GET with query string, and CGI POST (1 MB, echoed back)
out=$(curl -s -w ' %{http_code}' "$BASE/cgi-bin/echo.cgi?a=1&b=two%20words" | sed 's/ port=[0-9]*//' | tr '\n' ' ')
[ "$out" = "q=a=1&b=two%20words  200" ] && record cgi-get 0 "$out" || record cgi-get 1 "got '$out'"
head -c 1048576 /dev/urandom > "$WORK/post.bin"
want=$(sha256sum < "$WORK/post.bin" | cut -d' ' -f1)
got=$(curl -s -X POST --data-binary @"$WORK/post.bin" "$BASE/cgi-bin/echo.cgi" | sha256sum | cut -d' ' -f1)
[ "$got" = "$want" ] && record cgi-post 0 "1 MB echoed, sha256 ok" || record cgi-post 1 "echo sha '$got' want '$want'"

# 5. dynamic request through httpd -> node
out=$(curl -s -w ' %{http_code}' "$BASE/dyn/x?y=1" | jfield path | tr '\n' ' ')
code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/dyn/x?y=1")
[ "$out" = "/dyn/x " ] && [ "$code" = 200 ] && record dynamic 0 "path /dyn/x, 200" || record dynamic 1 "got '$out' code $code"

# 6. 50 MB chunked upload through both hops, sha256 at node
head -c "$BYTES" /dev/urandom > "$WORK/up.bin"
want=$(sha256sum < "$WORK/up.bin" | cut -d' ' -f1)
resp=$(curl -s -X POST -H 'Transfer-Encoding: chunked' -T - "$BASE/upload" < "$WORK/up.bin")
got=$(echo "$resp" | jfield sha256); bytes=$(echo "$resp" | jfield bytes)
[ "$got" = "$want" ] && [ "$bytes" = "$BYTES" ] && record upload-chunked 0 "$bytes bytes, sha256 ok at node" \
    || record upload-chunked 1 "response '$resp'"
rm -f "$WORK/up.bin" "$WORK/post.bin"

# 7. X-Forwarded-For as node sees it: proxy adds the client (127.0.0.2), httpd appends the proxy (127.0.0.1)
out=$(curl -s --interface 127.0.0.2 "$BASE/xff" | sed -n 's/.*"xff":"\([^"]*\)".*/\1/p')
[ "$out" = "127.0.0.2, 127.0.0.1" ] && record xff 0 "$out" || record xff 1 "got '$out', want '127.0.0.2, 127.0.0.1'"

# 8. error passthrough: httpd's own 404, a CGI's 500 with its body
out=$(curl -s -o "$WORK/e404" -w '%{http_code}' "$BASE/static/nonexistent")
grep -q 'Not Found' "$WORK/e404" && out="$out nf"
out2=$(curl -s -w ' %{http_code}' "$BASE/cgi-bin/fail.cgi" | tr '\n' ' ')
[ "$out" = "404 nf" ] && [ "$out2" = "cgi boom  500" ] && record error-passthrough 0 "404 page, cgi 500 body kept" \
    || record error-passthrough 1 "404: '$out'; cgi: '$out2'"

# 9. slow CGI: 3 s, must come back (timeout server 10s)
start=$(date +%s.%N)
body=$(curl -s -w ' %{http_code}' "$BASE/cgi-bin/slow.cgi" | tr '\n' ' ')
el=$(awk "BEGIN{printf \"%.1f\", $(date +%s.%N) - $start}")
[ "$body" = "slow cgi done  200" ] && awk "BEGIN{exit !($el >= 2.9)}" \
    && record slow-cgi 0 "200 after ${el}s" || record slow-cgi 1 "got '$body' after ${el}s"

# 10. light load: wrk2 against the dynamic path (proxy -> httpd -> node)
"$WRK2" -t2 -c20 -d${LOAD_SECS}s -R"$LOAD_RATE" --latency "$BASE/dyn/load" > "$WORK/wrk.out" 2>&1
sock=$(sed -n 's/^ *Socket errors: //p' "$WORK/wrk.out")
non2=$(sed -n 's/^Non-2xx or 3xx responses: //p' "$WORK/wrk.out")
reqs=$(sed -n 's/^ *\([0-9]*\) requests in.*/\1/p' "$WORK/wrk.out")
p99=$(sed -n 's/^ *99\.000% *//p' "$WORK/wrk.out" | head -1)
if [ -z "$sock" ] && [ -z "$non2" ] && [ "${reqs:-0}" -gt 0 ]; then record load 0 "$reqs requests, 0 socket errors, 0 non-2xx (p99 $p99, informational)"
else record load 1 "socket errors '$sock', non-2xx '$non2', requests '$reqs' (p99 $p99)"; fi

# ---- results ---------------------------------------------------------------
echo
echo "RESULTS ($PROXY)"
printf '%s\n' "${RESULTS[@]}"
echo "$FAILS failed"
[ "$FAILS" = 0 ] && rm -rf "$WORK" || echo "work dir kept: $WORK"
[ "$FAILS" = 0 ]
