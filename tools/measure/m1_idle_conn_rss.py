#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
"""M1: RSS per idle keep-alive client connection (T180). 10k idle conns, RSS delta / 10k.

Each client connection does one GET /small through the proxy and is then left idle
(keep-alive). Proxy and origin share the config in m1lib. Binaries: IBEX, HAPROXY env.
    tools/measure/m1_idle_conn_rss.py [N=10000]
"""
import socket
import sys
import time
import m1lib as m

N = int(sys.argv[1]) if len(sys.argv) > 1 else 10000
REQ = b"GET /small HTTP/1.1\r\nHost: m1\r\n\r\n"


def once(kind, origin_port):
    port = m.free_port()
    p = m.start(kind, m.write_file(f"idle-{kind}.cfg", m.proxy_cfg(port, origin_port, 1, N + 1000)), port)
    socks = []
    try:
        time.sleep(1)
        r0 = m.rss_kb(p.pid)
        for _ in range(N):
            s = socket.create_connection(("127.0.0.1", port))
            s.sendall(REQ)
            buf = b""
            while not buf.endswith(b"ok"):
                d = s.recv(4096)
                if not d:
                    raise RuntimeError("closed")
                buf += d
            socks.append(s)
        time.sleep(2)
        r1 = m.rss_kb(p.pid)
        return {"bytes_per_conn": (r1 - r0) * 1024 / N, "rss0_kb": r0, "rss1_kb": r1, "fds": m.nfds(p.pid)}
    finally:
        for s in socks:
            s.close()
        m.stop(p)


if __name__ == "__main__":
    print(m.header("m1_idle_conn_rss"), f"N={N}")
    m.wait_load()
    o, op = m.start_origin()
    try:
        for kind in ("ibex", "haproxy"):
            med, rs = m.median_of(lambda: once(kind, op))
            m.emit(param="idle_rss", kind=kind, n=N, **med, runs=[r["bytes_per_conn"] for r in rs])
    finally:
        m.stop(o)
