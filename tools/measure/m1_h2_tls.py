#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
"""M1: CPU per request for h2, and TLS handshakes/s (T180).

h2load is NOT installed. h2: 'curl --http2 --parallel' (curl + nghttp2) sends 4 x 25000
requests for /small over TLS (ALPN h2, multiplexed, 100 streams) to a proxy with
nbthread 1; proxy CPU (utime+stime from /proc/<pid>/stat) / requests = us per request.
TLS: 'openssl s_time -new -tls1_3' x 4 for 5 s each (full handshakes, ECDSA P-256 cert);
proxy CPU / handshakes = us per handshake, and handshakes per CPU-second.
    tools/measure/m1_h2_tls.py
"""
import re
import subprocess
import time
import m1lib as m

PROCS, PER = 4, 25000


def h2(kind, op, pem):
    port = m.free_port()
    cfg = m.proxy_cfg(port, op, 1, bind_extra=f"ssl crt {pem} alpn h2,http/1.1")
    p = m.start(kind, m.write_file(f"h2-{kind}.cfg", cfg), port)
    try:
        time.sleep(0.5)
        c0 = m.cpu_s(p.pid)
        cs = [subprocess.Popen(["curl", "-sk", "--http2", "--parallel", "--parallel-max", "100",
                                "--parallel-immediate", "-o", "/dev/null", "-w", "%{http_code} %{http_version}\n",
                                f"https://127.0.0.1:{port}/small?[1-{PER}]"], stdout=subprocess.PIPE)
              for _ in range(PROCS)]
        ok, vers = 0, set()
        for c in cs:
            for line in c.communicate()[0].decode().splitlines():
                code, ver = line.split()
                ok += code == "200"
                vers.add(ver)
        cpu = m.cpu_s(p.pid) - c0
        if ok == 0:
            raise RuntimeError("no successful h2 request")
        return {"us_per_req": cpu / ok * 1e6, "ok": ok, "all_h2": int(vers == {"2"})}
    finally:
        m.stop(p)


def tls(kind, op, pem):
    port = m.free_port()
    cfg = m.proxy_cfg(port, op, 1, bind_extra=f"ssl crt {pem}")
    p = m.start(kind, m.write_file(f"tls-{kind}.cfg", cfg), port)
    try:
        time.sleep(0.5)
        c0 = m.cpu_s(p.pid)
        cs = [subprocess.Popen(["openssl", "s_time", "-connect", f"127.0.0.1:{port}", "-new", "-tls1_3", "-time", "5"],
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT) for _ in range(PROCS)]
        n = 0
        for c in cs:
            out = c.communicate()[0].decode()
            mt = re.findall(r"(\d+) connections in", out)
            n += int(mt[-1]) if mt else 0
        cpu = m.cpu_s(p.pid) - c0
        if n == 0:
            raise RuntimeError("no handshakes")
        return {"us_per_handshake": cpu / n * 1e6, "handshakes_per_cpu_s": n / cpu, "handshakes": n}
    finally:
        m.stop(p)


if __name__ == "__main__":
    print(m.header("m1_h2_tls"))
    m.wait_load()
    pem = m.make_cert()
    o, op = m.start_origin()
    try:
        for kind in ("alcyon", "haproxy"):
            med, rs = m.median_of(lambda: h2(kind, op, pem))
            m.emit(param="h2_cpu", kind=kind, **med)
        for kind in ("alcyon", "haproxy"):
            med, rs = m.median_of(lambda: tls(kind, op, pem))
            m.emit(param="tls_handshake", kind=kind, **med)
    finally:
        m.stop(o)
