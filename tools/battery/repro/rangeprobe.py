#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
"""Per-request latency of the h1_range shape on one connection, for several proxies.
Usage (on the battery host, haterm on 127.0.0.1:8888 already running):
  rangeprobe.py <h1 port> <label=binary> [label=binary ...]
Shapes: 1m+range (the battery's h1_range request), 1m plain, 1k+range, 1m+10KB junk header."""
import os, re, socket, statistics, subprocess, sys, time

PORT = int(sys.argv[1])
CFG = """global
    nbthread 4
    maxconn 2000
defaults
    mode http
    timeout connect 5s
    timeout client 30s
    timeout server 30s
    timeout http-request 5s
frontend f
    bind 127.0.0.1:%d
    default_backend b
backend b
    server s1 127.0.0.1:8888
""" % PORT
RANGE = b"Range: bytes=" + b",".join(b"%d-%d" % (k, k + 1000) for k in range(0, 2000, 2)) + b"\r\n"
JUNK = b"X-Pad: " + b"a" * len(RANGE) + b"\r\n"
SHAPES = [("1m+range", b"/?s=1m", RANGE), ("1m plain", b"/?s=1m", b""),
          ("1k+range", b"/?s=1k", RANGE), ("1m+junk10k", b"/?s=1m", JUNK)]
N = int(os.environ.get("N", "20"))


def req(path, extra):
    return b"GET " + path + b" HTTP/1.1\r\nHost: battery\r\n" + extra + b"\r\n"


def read_resp(s):
    buf = b""
    while b"\r\n\r\n" not in buf:
        d = s.recv(65536)
        if not d: return None, 0
        buf += d
    head, rest = buf.split(b"\r\n\r\n", 1)
    m = re.search(rb"content-length:\s*(\d+)", head.lower())
    n = int(m.group(1)) if m else 0
    while len(rest) < n:
        d = s.recv(65536)
        if not d: return head, len(rest)
        rest += d
    return head, len(rest)


def wait_port(port):
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", port), 0.2).close(); return True
        except OSError: time.sleep(0.05)
    return False


for spec in sys.argv[2:]:
    label, binary = spec.split("=", 1)
    cfg = f"/tmp/rangeprobe-{label}.cfg"
    open(cfg, "w").write(CFG)
    log = open(f"/tmp/rangeprobe-{label}.log", "w")
    p = subprocess.Popen(["taskset", "-c", "0-3", binary, "-f", cfg], stdout=log, stderr=subprocess.STDOUT)
    try:
        if not wait_port(PORT):
            print(label, "did not listen"); continue
        print(f"== {label} ({binary}) pid {p.pid}")
        for name, path, extra in SHAPES:
            s = socket.create_connection(("127.0.0.1", PORT)); s.settimeout(10)
            lat, status, size = [], None, None
            for i in range(N):
                t = time.perf_counter()
                s.sendall(req(path, extra))
                head, got = read_resp(s)
                lat.append((time.perf_counter() - t) * 1000)
                if head is None:
                    status = "EOF"; break
                status, size = head.split(b"\r\n")[0].decode(), got
            s.close()
            print(f"  {name:11s} {status} body {size} B: median {statistics.median(lat):.2f} ms, max {max(lat):.2f} ms, first {lat[0]:.2f} ms, n={len(lat)}")
    finally:
        p.terminate(); p.wait(5); log.close()
        print("  proxy exit", p.returncode, "panics", open(f"/tmp/rangeprobe-{label}.log").read().count("panic"))
