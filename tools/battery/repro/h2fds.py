#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
"""MY-1 follow-up: one HTTP/2 connection with N streams in flight.  Lab only (127.0.0.1).
    h2fds.py <h2c port> <streams> label=binary ...
Each stream is GET /?t=3000 (haterm answers after 3 s), so all N stay open together.  Prints the
server's SETTINGS, how many HEADERS came back within 5 s and when, the proxy's fds and the
established backend connections before and 1 s into the burst, and RSS."""
import socket, sys, time
sys.path.insert(0, "/root/battery"); sys.path.insert(0, "/root/battery/repro")
from clients import PREFACE, settings, h2_request
from labproxy import start_haterm, start_proxy, stop, fds, be_conns, rss_cpu

PORT, N = int(sys.argv[1]), int(sys.argv[2])
SPECS = [s.split("=", 1) for s in sys.argv[3:]]
SET = {1: "HEADER_TABLE_SIZE", 2: "ENABLE_PUSH", 3: "MAX_CONCURRENT_STREAMS", 4: "INITIAL_WINDOW_SIZE", 5: "MAX_FRAME_SIZE", 6: "MAX_HEADER_LIST_SIZE"}
CFG = f"""global
    nbthread 4
    maxconn 2000
defaults
    mode http
    timeout connect 5s
    timeout client 30s
    timeout server 30s
    timeout http-request 5s
frontend f
    bind 127.0.0.1:{PORT} proto h2
    default_backend b
backend b
    server s1 127.0.0.1:8890
"""

def one(label, binary):
    p = start_proxy(binary, CFG, PORT, f"h2fds-{label}")
    if not p: return
    try:
        f0, b0, r0 = fds(p.pid), be_conns(8890), rss_cpu(p.pid)[0]
        s = socket.create_connection(("127.0.0.1", PORT)); s.sendall(PREFACE + settings()); time.sleep(0.2)
        t0 = time.time(); s.sendall(b"".join(h2_request(1 + 2 * k, b"/?t=3000") for k in range(N)))
        s.settimeout(0.1); buf = b""; headers = {}; srv = {}; mid = None; rsts = {}
        while time.time() - t0 < 6:
            if mid is None and time.time() - t0 >= 1: mid = (fds(p.pid), be_conns(8890), rss_cpu(p.pid)[0])
            try:
                d = s.recv(65536)
                if not d: break
                buf += d
            except socket.timeout: pass
            while len(buf) >= 9:
                ln = int.from_bytes(buf[:3], "big"); t = buf[3]; sid = int.from_bytes(buf[5:9], "big") & 0x7fffffff
                if len(buf) < 9 + ln: break
                pl = buf[9:9 + ln]; buf = buf[9 + ln:]
                if t == 4 and sid == 0:
                    for i in range(0, len(pl) - 5, 6): srv[SET.get(int.from_bytes(pl[i:i+2], "big"), int.from_bytes(pl[i:i+2], "big"))] = int.from_bytes(pl[i+2:i+6], "big")
                elif t == 1: headers[sid] = round(time.time() - t0, 2)
                elif t == 3: rsts[sid] = int.from_bytes(pl[:4], "big")
        s.close(); time.sleep(0.5)
        ts = sorted(headers.values())
        print(f"{label:9s} {N} streams on one connection: HEADERS back {len(headers)}/{N} within 6 s "
              f"(first {ts[0] if ts else '-'} s, last {ts[-1] if ts else '-'} s), RST_STREAM {len(rsts)} {dict(list(rsts.items())[:3])}; "
              f"server SETTINGS {srv}")
        print(f"          fds {f0} -> {mid and mid[0]} (at 1 s) -> {fds(p.pid)} after; backend conns {b0} -> {mid and mid[1]} -> {be_conns(8890)}; "
              f"RSS {r0} -> {mid and mid[2]} -> {rss_cpu(p.pid)[0]} MB", flush=True)
    finally:
        stop(p)

ht = start_haterm(8890)
try:
    for label, binary in SPECS: one(label, binary)
finally:
    stop(ht)
