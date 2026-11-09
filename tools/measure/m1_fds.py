#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
"""M1: file descriptors per connection (T180). client -> proxy -> origin, keep-alive.

Opens N client connections, each does one GET /small and stays open; fd delta of the
proxy process / N (expected 2: the client side and its own server side).
    tools/measure/m1_fds.py [N=100]
"""
import socket
import sys
import time
import m1lib as m

N = int(sys.argv[1]) if len(sys.argv) > 1 else 100
REQ = b"GET /small HTTP/1.1\r\nHost: m1\r\n\r\n"


def once(kind, origin_port):
    port = m.free_port()
    p = m.start(kind, m.write_file(f"fds-{kind}.cfg", m.proxy_cfg(port, origin_port, 1, 10000)), port)
    socks = []
    try:
        time.sleep(1)
        f0 = m.nfds(p.pid)
        for _ in range(N):
            s = socket.create_connection(("127.0.0.1", port))
            s.sendall(REQ)
            buf = b""
            while not buf.endswith(b"ok"):
                buf += s.recv(4096)
            socks.append(s)
        time.sleep(1)
        return {"fds_per_conn": (m.nfds(p.pid) - f0) / N, "fd0": f0}
    finally:
        for s in socks:
            s.close()
        m.stop(p)


if __name__ == "__main__":
    print(m.header("m1_fds"), f"N={N}")
    o, op = m.start_origin()
    try:
        for kind in ("alcyon", "haproxy"):
            med, rs = m.median_of(lambda: once(kind, op))
            m.emit(param="fds", kind=kind, n=N, **med)
    finally:
        m.stop(o)
