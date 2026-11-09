#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
"""M1: throughput, 1 and 50 conns, small and 64 KB bodies (T180).

wrk is NOT installed here, so the client is m1lib.load(): N keep-alive connections spread
over up to 12 worker processes, closed loop, 1 s warm-up + 5 s window. Both proxies run
nbthread 1 so the proxy, not the Python client, is the bottleneck; the origin is a
4-thread HAProxy. If rps is identical for both proxies the client is the limit.
    tools/measure/m1_throughput.py
"""
import m1lib as m

if __name__ == "__main__":
    print(m.header("m1_throughput"))
    m.wait_load()
    o, op = m.start_origin()
    try:
        for conns in (1, 50):
            for path in ("/small", "/64k"):
                for kind in ("alcyon", "haproxy"):
                    port = m.free_port()
                    p = m.start(kind, m.write_file(f"tp-{kind}.cfg", m.proxy_cfg(port, op, 1)), port)
                    try:
                        med, rs = m.median_of(lambda: m.load(port, path, conns))
                        m.emit(param="throughput", kind=kind, conns=conns, path=path, rps=med["rps"],
                               runs=[round(r["rps"]) for r in rs])
                    finally:
                        m.stop(p)
    finally:
        m.stop(o)
