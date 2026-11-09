#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
"""M1: added latency p50/p99 at 50% of max throughput (T180).

wrk2 / wrk -R are NOT installed, so the client is m1lib.load(rate=R): an open-loop
constant-rate Python client (latency measured from each request's scheduled send time, so
queueing counts), 50 keep-alive conns, GET /small. Max = closed-loop rps of the slower
proxy (nbthread 1); R = 50% of that, the same absolute R for both proxies. 'Added' latency
is the proxy's p50/p99 minus the p50/p99 of the same client going straight to the origin
at rate R.
    tools/measure/m1_latency.py
"""
import m1lib as m

if __name__ == "__main__":
    print(m.header("m1_latency"))
    m.wait_load()
    o, op = m.start_origin()
    try:
        ports, procs, mx = {}, {}, {}
        for kind in ("alcyon", "haproxy"):
            ports[kind] = m.free_port()
            procs[kind] = m.start(kind, m.write_file(f"lat-{kind}.cfg", m.proxy_cfg(ports[kind], op, 1)), ports[kind])
            mx[kind] = m.median_of(lambda: m.load(ports[kind], "/small", 50), 1)[0]["rps"]
        rate = int(min(mx.values()) / 2)
        m.emit(param="latency_max", alcyon_rps=mx["alcyon"], haproxy_rps=mx["haproxy"], rate=rate)
        base, _ = m.median_of(lambda: m.load(op, "/small", 50, rate=rate))
        m.emit(param="latency_direct_origin", rate=rate, **base)
        for kind in ("alcyon", "haproxy"):
            med, rs = m.median_of(lambda: m.load(ports[kind], "/small", 50, rate=rate))
            m.emit(param="latency", kind=kind, rate=rate, **med, added_p50_us=med["p50_us"] - base["p50_us"],
                   added_p99_us=med["p99_us"] - base["p99_us"], p99_runs=[round(r["p99_us"]) for r in rs])
        for p in procs.values():
            m.stop(p)
    finally:
        m.stop(o)
