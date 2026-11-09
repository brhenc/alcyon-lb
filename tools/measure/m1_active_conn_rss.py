#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
"""M1: RSS per active connection with a 1 MB body in flight (T180). 1k conns.

Each client sets a 4 KB receive buffer, sends GET /1m and does NOT read: the 1 MB
response stays in flight, buffered by the proxy (slow client, fast origin; the origin is
a HAProxy, so a slow *server* case is not covered). RSS delta / N after 3 s.
    tools/measure/m1_active_conn_rss.py [N=1000]
"""
import socket
import sys
import time
import m1lib as m

N = int(sys.argv[1]) if len(sys.argv) > 1 else 1000
REQ = b"GET /1m HTTP/1.1\r\nHost: m1\r\n\r\n"


def once(kind, origin_port):
    port = m.free_port()
    p = m.start(kind, m.write_file(f"active-{kind}.cfg", m.proxy_cfg(port, origin_port, 1, N + 1000)), port)
    socks = []
    try:
        time.sleep(1)
        r0 = m.rss_kb(p.pid)
        for _ in range(N):
            s = socket.socket()
            s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
            s.connect(("127.0.0.1", port))
            s.sendall(REQ)
            socks.append(s)
        time.sleep(3)
        r1 = m.rss_kb(p.pid)
        return {"bytes_per_conn": (r1 - r0) * 1024 / N, "rss0_kb": r0, "rss1_kb": r1}
    finally:
        for s in socks:
            s.close()
        m.stop(p)


if __name__ == "__main__":
    print(m.header("m1_active_conn_rss"), f"N={N}")
    m.wait_load()
    o, op = m.start_origin()
    try:
        for kind in ("alcyon", "haproxy"):
            med, rs = m.median_of(lambda: once(kind, op))
            m.emit(param="active_rss", kind=kind, n=N, **med, runs=[r["bytes_per_conn"] for r in rs])
    finally:
        m.stop(o)
