#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
# VV-13: a client that aborts while the proxy is still connecting (server port closed, retries)
# is logged as b/<NOSRV> by Alcyon, b/s by HAProxy.     vv13.sh BIN [PORT=19899]
# Also: e2e/ holds the 2026-10-17 re-verification inputs for FZ-5/6/7 and RV-33
# (python3 fuzz/e2e.py tools/battery/repro/vv-1017/e2e BIN; every case SAME on 945ae6be).
set -u
BIN=$1; P=${2:-19899}; D=$(mktemp -d /tmp/vv13-XXXX)
cat > "$D/p.cfg" <<EOC
global
    nbthread 1
defaults
    mode http
    log stdout format raw local0
    option httplog
    timeout client 1s
    timeout server 1s
    timeout connect 1s
frontend f
    log global
    bind 127.0.0.1:$P
    default_backend b
backend b
    server s 127.0.0.1:$((P - 1))
EOC
"$BIN" -f "$D/p.cfg" > "$D/log" 2>&1 & X=$!
sleep 0.8
for w in 0.1 0.3 1.5 2.5; do
  python3 -c "
import socket,sys;c=socket.create_connection(('127.0.0.1',int(sys.argv[2])));c.settimeout(float(sys.argv[1]))
c.sendall(b'GET /x HTTP/1.1\r\nHost: x\r\n\r\n')
try: c.recv(200)
except Exception: pass
c.close()" "$w" "$P"
done
sleep 3.5; kill "$X"; wait 2>/dev/null
grep -vE '^\[NOTICE\]|^$' "$D/log" | sed -E 's/^127\.0\.0\.1:[0-9]+ \[[^]]+\] //'
