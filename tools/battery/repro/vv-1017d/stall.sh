#!/bin/bash
# stall.sh BIN NAME: proxy logs every request to stderr; stderr is a pipe nobody reads.
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
# T342b: run as stall.sh BIN NAME (port 19920, socket under /tmp/vv-s); prints alive after SIGUSR2.
B=$1; N=$2; D=$(mktemp -d /tmp/vv-stall-XXXX); S=/tmp/vv-s; mkdir -p $S
printf 'global\n    nbthread 2\n    log stderr format raw local0\n    stats socket %s/%s.sock level admin\ndefaults\n    mode http\n    log global\n    option httplog\n    timeout connect 1s\n    timeout client 5s\n    timeout server 5s\nfrontend f\n    bind 127.0.0.1:19920\n    http-request return status 200 content-type text/plain string ok\n' $S $N > $D/stall-$N.cfg
mkfifo $S/fifo-$N 2>/dev/null
sleep 300 < $S/fifo-$N & R=$!          # holds the read end open, never reads
$B -f $D/stall-$N.cfg > $D/stall-$N.out 2> $S/fifo-$N & X=$!
sleep 1
python3 - <<'PY'
import socket,time
ok=bad=0; t=time.time()
for i in range(3000):
    try:
        c=socket.create_connection(("127.0.0.1",19920),timeout=2); c.sendall(b"GET /%d HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"%i)
        r=c.recv(100); c.close(); ok += r.startswith(b"HTTP/1.1 200"); bad += not r.startswith(b"HTTP/1.1 200")
    except Exception: bad+=1
print("3000 requests: ok=%d bad=%d in %.1f s"%(ok,bad,time.time()-t))
PY
kill -USR2 $X; sleep 1
echo "alive after: $(kill -0 $X 2>/dev/null && echo yes || echo NO)"
python3 -c "
import socket,sys;s=socket.socket(socket.AF_UNIX);s.connect(sys.argv[1]);s.sendall(b'show info\n');b=b''
while True:
  d=s.recv(65536)
  if not d:break
  b+=d
print([l for l in b.decode().splitlines() if l.startswith('DroppedLogs')])" $S/$N.sock 2>&1
echo "stdout: $(grep -ciE 'panic|abort' $D/stall-$N.out) panic/abort lines"
kill $X $R 2>/dev/null; wait 2>/dev/null; rm -f $S/fifo-$N
