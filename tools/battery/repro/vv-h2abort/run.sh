#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
# VV-12: a backend restart while h2 streams are in flight on it takes down the whole client h2
# connection on Alcyon (sibling streams to other backends included); HAProxy completes every stream.
#   run.sh BIN PORT [CONNS] [CORES]     e.g. run.sh ./alcyon 19780 10 50-51
# Uses PORT..PORT+3 (frontend, bigapp, unused, slowbe). Prints one line per h2 client connection.
set -u
export PYTHONDONTWRITEBYTECODE=1
BIN=$1; P=$2; N=${3:-10}; CORES=${4:-48-49}; HERE=$(cd "$(dirname "$0")" && pwd)
D=$(mktemp -d /tmp/vv-h2abort-XXXX)
openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=blog.local -days 2 \
  -keyout "$D/key.pem" -out "$D/crt.pem" >/dev/null 2>&1
cat "$D/crt.pem" "$D/key.pem" > "$D/chain.pem"
cat > "$D/proxy.cfg" <<EOC
global
    nbthread 2
defaults
    mode http
    log stdout format raw local0
    timeout connect 1s
    timeout client 30s
    timeout server 30s
frontend fe_h2
    log global
    option httplog
    bind 127.0.0.1:$P ssl crt $D/chain.pem alpn h2
    use_backend be_slow if { path_beg /s }
    default_backend be_big
backend be_big
    server big 127.0.0.1:$((P + 1))
backend be_slow
    server slow 127.0.0.1:$((P + 3))
EOC
sed 's/}, 60000);/}, 1000);/' "$HERE/../vv-h2mux/bigapp.js" > "$D/bigapp1s.js"
node "$D/bigapp1s.js" $((P + 1)) "$D/bigapp.log" & A=$!
taskset -c "$CORES" "$BIN" -f "$D/proxy.cfg" > "$D/proxy.log" 2>&1 & X=$!
sleep 1.5
python3 "$HERE/probe.py" "$P" "$D/bigapp.log" $((P + 3)) "$N"
sleep 1.2
kill "$X" "$A"; wait 2>/dev/null
echo "-- bigapp: $(tail -1 "$D/bigapp.log")"
echo "-- proxy log lines: $(grep -c '' "$D/proxy.log"), not 200:"
grep -vE ' 200 [0-9]+ |^\[NOTICE\]' "$D/proxy.log" | head -12
echo "files in $D"
