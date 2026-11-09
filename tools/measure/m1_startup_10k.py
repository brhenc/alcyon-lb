#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
"""M1: startup time with 10k backends (T180): wall time from exec to the first accepted
connection (polled every 1 ms). Config as tools/measure/startup_rss.py (1 server each).
    tools/measure/m1_startup_10k.py [BACKENDS=10000]
"""
import sys
import time
import m1lib as m

N = int(sys.argv[1]) if len(sys.argv) > 1 else 10000


def cfg(port):
    out = ["global", "    nbthread 1", "    maxconn 1000", "defaults", "    mode http",
           "    timeout connect 5s", "    timeout client 5s", "    timeout server 5s",
           "frontend fe", f"    bind 127.0.0.1:{port}", "    default_backend b0"]
    for i in range(N):
        out += [f"backend b{i}", f"    server s{i} 127.0.0.1:{20000 + i % 1000}"]
    return "\n".join(out) + "\n"


def once(kind):
    port = m.free_port()
    path = m.write_file(f"startup-{kind}.cfg", cfg(port))
    t0 = time.time()
    p = m.start(kind, path, port, wait=False)
    try:
        t1 = m.wait_listen(p, port)
        return {"seconds": t1 - t0}
    finally:
        m.stop(p)


if __name__ == "__main__":
    print(m.header("m1_startup_10k"), f"backends={N}")
    m.wait_load()
    for kind in ("alcyon", "haproxy"):
        med, rs = m.median_of(lambda: once(kind))
        m.emit(param="startup", kind=kind, backends=N, **med, runs=[r["seconds"] for r in rs])
