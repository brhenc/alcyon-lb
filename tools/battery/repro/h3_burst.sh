#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
#
# T523 (M2 slice 3): 200 HTTP/3 connections opened at once, one GET / each, through a
# Python ThreadingHTTPServer backend (listen backlog 5, as the M2 plan's be.py), on Alcyon and
# on HAProxy with QUIC, alternately, RUNS times at each nbthread; a fresh proxy and backend
# per run. Prints one line per run: ok/fail of the 200 (each waits for its handshake, then
# sends its request and gives it 10 s: the M2 plan's idle_h3.py, aioquic) and the
# connections the backend accepted.
#
#   tools/battery/repro/h3_burst.sh <alcyon-binary> [runs=3] [nbthread ...=1 16]
#
# HAProxy 3.5-dev7 QUIC (HAPROXY_QUIC overrides): 200/200 every run, about 120 backend
# connections for 200 requests (every HTTP/3 stream is "not first" and reuses an idle one).
# Alcyon before T523: 143-198/200 at nbthread 1, 196-200 at 16, one backend connection per
# request; the burst overflowed the backend's accept queue (TcpExtListenOverflows) and a
# dropped SYN cost a connect timeout and a retry, past the client's 10 s.
# Why a battery script and not the integration suite: the failure needs a backend whose
# accept queue overflows, and how many SYNs a burst drops depends on host load; HAProxy's
# own p99 went from 1.9 s to 4.4 s between two quiet runs. The deterministic part (an
# HTTP/3 request reuses an idle server connection) is tests/it/h3_backend_reuse.rs.
# Takes about 2 s a run. Uses ports 61531-61533 and /tmp/h3_burst.$$.
set -u
ALCYON=${1:?usage: h3_burst.sh <alcyon-binary> [runs] [nbthread ...]}
RUNS=${2:-3}
shift; shift 2>/dev/null
NTS=${*:-1 16}
HAP=${HAPROXY_QUIC:-$HOME/reference/haproxy-quic/haproxy}
HERE=$(cd "$(dirname "$0")" && pwd) || exit 1
CRT=$HERE/../../../examples/certs/localhost.pem
D=/tmp/h3_burst.$$
mkdir -p "$D" || exit 1
BE=61531
cat > "$D/be.py" <<'EOF'
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
log = open(sys.argv[2], "a", buffering=1)
class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *a): pass
    def do_GET(self):
        self.send_response(200); self.send_header("Content-Length", "6"); self.end_headers(); self.wfile.write(b"hello\n")
class S(ThreadingHTTPServer):
    daemon_threads = True
    def get_request(self):
        s, a = super().get_request(); log.write("accept\n"); return s, a
S(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
EOF
cat > "$D/client.py" <<'EOF'
import asyncio, ssl, sys
from aioquic.asyncio import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import HeadersReceived, DataReceived
from aioquic.quic.configuration import QuicConfiguration
PORT, N = int(sys.argv[1]), int(sys.argv[2]); ok = fail = 0
class P(QuicConnectionProtocol):
    def __init__(self, *a, **k):
        super().__init__(*a, **k); self.h3 = H3Connection(self._quic); self.done = asyncio.get_event_loop().create_future(); self.status = None
    def quic_event_received(self, e):
        for ev in self.h3.handle_event(e):
            if isinstance(ev, HeadersReceived): self.status = dict(ev.headers).get(b":status")
            if isinstance(ev, DataReceived) and ev.stream_ended and not self.done.done(): self.done.set_result(self.status)
async def one():
    global ok, fail
    cfg = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN); cfg.verify_mode = ssl.CERT_NONE
    try:
        async with connect("127.0.0.1", PORT, configuration=cfg, create_protocol=P) as p:
            sid = p._quic.get_next_available_stream_id()
            p.h3.send_headers(sid, [(b":method", b"GET"), (b":scheme", b"https"), (b":authority", b"localhost"), (b":path", b"/")], end_stream=True)
            p.transmit()
            if await asyncio.wait_for(p.done, 10) == b"200": ok += 1
            else: fail += 1
    except BaseException:
        fail += 1
async def main():
    await asyncio.gather(*[one() for _ in range(N)])
    print(f"ready ok={ok} fail={fail}", flush=True)
asyncio.run(main())
EOF
for nt in $NTS; do
  for r in $(seq 1 "$RUNS"); do
    for who in alcyon haproxy; do
      if [ "$who" = alcyon ]; then BIN=$ALCYON; FE=61532; else BIN=$HAP; FE=61533; fi
      : > "$D/acc"
      python3 "$D/be.py" $BE "$D/acc" 2>/dev/null & B=$!
      printf 'global\n  nbthread %s\ndefaults\n  mode http\n  timeout connect 3s\n  timeout client 15s\n  timeout server 15s\nfrontend fe\n  bind quic4@127.0.0.1:%s ssl crt %s alpn h3\n  default_backend be\nbackend be\n  server s1 127.0.0.1:%s\n' \
        "$nt" "$FE" "$CRT" "$BE" > "$D/$who.cfg"
      sleep 0.3
      "$BIN" -f "$D/$who.cfg" > "$D/$who.log" 2>&1 & P=$!
      sleep 0.7
      RES=$(timeout 60 python3 "$D/client.py" "$FE" 200 2>&1 | grep -m1 '^ready')
      echo "$who nbthread=$nt run=$r: ${RES:-no result} backend_accepts=$(wc -l < "$D/acc")"
      kill -USR1 $P 2>/dev/null; sleep 0.3; kill $P 2>/dev/null; wait $P 2>/dev/null
      kill $B 2>/dev/null; wait $B 2>/dev/null
    done
  done
done
rm -rf "$D"
