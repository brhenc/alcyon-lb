#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
# VV-10 / VV-11: h2 clients over TLS, large-body node backend (bigapp.js).
#   run.sh BIN PORT [CORES]     e.g. run.sh ./ibex 19744 48-49
# VV-10: backend connections opened for sequential h2 client connections (reuse_h2.py).
# VV-11: round time of 1, 2 and 4 concurrent 256 KB uploads on one h2 connection (uploads_h2.py).
set -u
BIN=$1; PORT=$2; CORES=${3:-48-49}; BE=$((PORT + 1)); HERE=$(cd "$(dirname "$0")" && pwd)
D=$(mktemp -d /tmp/vv-h2mux-XXXX)
openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=blog.local -days 2 \
  -keyout "$D/key.pem" -out "$D/crt.pem" >/dev/null 2>&1
cat "$D/crt.pem" "$D/key.pem" > "$D/chain.pem"
cat > "$D/proxy.cfg" <<EOF
global
    nbthread 2
defaults
    mode http
    timeout connect 1s
    timeout client 30s
    timeout server 30s
frontend fe_h2
    bind 127.0.0.1:$PORT ssl crt $D/chain.pem alpn h2
    default_backend be_big
backend be_big
    server big 127.0.0.1:$BE
EOF
sed 's/}, 60000);/}, 1000);/' "$HERE/bigapp.js" > "$D/bigapp1s.js"
node "$D/bigapp1s.js" "$BE" "$D/bigapp.log" & A=$!
taskset -c "$CORES" "$BIN" -f "$D/proxy.cfg" > "$D/proxy.log" 2>&1 & X=$!
sleep 1.5
echo "== VV-10 backend reuse"
python3 "$HERE/reuse_h2.py" "$PORT" "$D/bigapp.log"
for k in 1 2 4; do
  echo "== VV-11 $k concurrent 256 KB uploads, 8 rounds"
  python3 "$HERE/uploads_h2.py" "$PORT" "$D/bigapp.log" "$k" | grep -E '^round|WU conn'
done
kill "$X" "$A"; wait 2>/dev/null
echo "files in $D"
