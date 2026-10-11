#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
# T305 item 9: h2 request with body + trailers, backend answers before reading the body.
# Two streams on one h2c connection; both must get their response.  h2t.sh BIN PORT
BIN=$1; PORT=$2; BE=$((PORT+50)); D=$(mktemp -d /tmp/vv-h2t-XXXX)
python3 - "$BE" <<'EOF' &
import socket, sys, threading, time
ls = socket.socket(); ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
ls.bind(("127.0.0.1", int(sys.argv[1]))); ls.listen(16)
def h(c):
    c.settimeout(5); b = b""
    try:
        while True:
            while b"\r\n\r\n" not in b:
                d = c.recv(65536)
                if not d: return
                b += d
            head, b = b.split(b"\r\n\r\n", 1)
            c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")   # answer at once
            if b"chunked" in head.lower():
                while not b.endswith(b"\r\n\r\n") or b"\r\n0\r\n" not in b and not b.startswith(b"0\r\n"):
                    d = c.recv(65536)
                    if not d: return
                    b += d
                b = b""
    except OSError: pass
    finally: c.close()
while True:
    c, _ = ls.accept(); threading.Thread(target=h, args=(c,), daemon=True).start()
EOF
BEPID=$!
cat > $D/h2t$PORT.cfg <<EOF
global
    nbthread 1
defaults
    mode http
    timeout connect 1s
    timeout client 5s
    timeout server 5s
frontend fe
    bind 127.0.0.1:$PORT proto h2
    default_backend b
backend b
    server s1 127.0.0.1:$BE
EOF
$BIN -f $D/h2t$PORT.cfg >/dev/null 2>&1 & PX=$!
sleep 0.6
head -c 300000 /dev/zero > $D/body.bin
timeout 15 nghttp -nv -d $D/body.bin --trailer 'x-t: 1' http://127.0.0.1:$PORT/a http://127.0.0.1:$PORT/b 2>&1 \
  | grep -E 'recv HEADERS|:status|recv (RST_STREAM|GOAWAY)|error_code|END_STREAM' | sed 's/^\[ *[0-9.]*\] //' | sort | uniq -c
echo "nghttp rc=${PIPESTATUS[0]}"
kill $PX $BEPID; wait 2>/dev/null
