#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

"""Malloc-per-request counter on the shipped (release) binary, with ratchet pins (Z1).

    python3 harness/malloc_per_request.py [--binary PATH] [--table-only]
    python3 -m unittest harness/test_malloc_per_request.py     (skips without a release binary)

Why this and not the in-process counters: crates/alcyon-rt/tests/request_allocations.rs and
tools/allocprofile count with alcyon-alloc's counting allocator around an in-process engine.
They cannot see what the real `alcyon` binary allocates (its own accept/session path, the log
sink, libc callers, rustls), and the user's requirement (tradeoff.md §6.13) is about the
binary. So this builds tools/allocshim/shim.c (an LD_PRELOAD interposer on malloc, calloc,
realloc and the aligned calls), starts the real binary under it with `nbthread 1`, warms up
(3 keep-alive requests, 3 `Connection: close` connections), and takes the counter delta over
one request. Each delta is measured 3 times and the minimum is kept (a real allocation is
deterministic; a stray timer is not).

Count = malloc + calloc + realloc calls (+ aligned allocations, 0 so far). The pin is a
ratchet: a count above its pin fails; a count below it passes and says "lower the pin" --
lowering it is part of the commit that removed the allocation. Bytes are printed, not pinned.

Ports: 47440 (backend), 47441 (frontend), 47442 (UDP log sink), inside the 47400-47599
range reserved for tests. Everything started here is killed by PID.
"""
from __future__ import annotations

import argparse
import os
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
BACKEND_PORT, FRONT_PORT, LOG_PORT = 47440, 47441, 47442

# (config, shape) -> (keep-alive pin, new-connection pin). Measured 2026-10-18 on f1f6e951
# (the plan-2100 table, §2.1, reproduced). The ratchet: counts may go down, never up.
PINS = {
    ("bare", "min"): (2, 2),    # GET / HTTP/1.1 + Host
    ("bare", "ab"): (5, 5),     # HTTP/1.0 + Connection: Keep-Alive (ab -k)
    ("blog", "curl"): (62, 64), # log + httplog + forwardfor + acl + set-header x2
}

REQ = {
    "min": (b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"),
    "ab": (b"GET / HTTP/1.0\r\nConnection: Keep-Alive\r\nHost: 127.0.0.1\r\n"
           b"User-Agent: ApacheBench/2.3\r\nAccept: */*\r\n\r\n",
           b"GET / HTTP/1.0\r\nHost: 127.0.0.1\r\nUser-Agent: ApacheBench/2.3\r\nAccept: */*\r\n\r\n"),
    "curl": (b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: curl/8.9.1\r\nAccept: */*\r\n\r\n",
             b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: curl/8.9.1\r\nAccept: */*\r\n"
             b"Connection: close\r\n\r\n"),
}

CFG = {
    "bare": """global
    nbthread 1
defaults
    mode http
    timeout connect 5s
    timeout client 30s
    timeout server 30s
frontend fe
    bind 127.0.0.1:{front}
    default_backend be
backend be
    server s1 127.0.0.1:{back}
""",
    "blog": """global
    nbthread 1
    log 127.0.0.1:{log} local0
defaults
    mode http
    log global
    option httplog
    option forwardfor
    timeout connect 5s
    timeout client 30s
    timeout server 30s
frontend fe
    bind 127.0.0.1:{front}
    acl is_static path_beg /static
    http-request set-header X-Forwarded-Proto http
    use_backend be if is_static
    default_backend be
backend be
    http-response set-header X-Served-By alcyon
    server s1 127.0.0.1:{back}
""",
}

RESP = b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nContent-Type: text/plain\r\n\r\nhello\n"


class Backend:
    """A 6-byte-reply HTTP backend in a thread of this (uninstrumented) process."""

    def __init__(self):
        self.srv = socket.socket()
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", BACKEND_PORT))
        self.srv.listen(16)
        self.stop = False
        threading.Thread(target=self.accept, daemon=True).start()

    def accept(self):
        while not self.stop:
            try:
                c, _ = self.srv.accept()
            except OSError:
                return
            threading.Thread(target=self.serve, args=(c,), daemon=True).start()

    def serve(self, s):
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        buf = b""
        try:
            while True:
                d = s.recv(65536)
                if not d:
                    return
                buf += d
                while b"\r\n\r\n" in buf:
                    _, buf = buf.split(b"\r\n\r\n", 1)
                    s.sendall(RESP)
        except OSError:
            pass
        finally:
            s.close()

    def close(self):
        self.stop = True
        try:
            self.srv.shutdown(socket.SHUT_RDWR)  # wakes the thread blocked in accept()
        except OSError:
            pass
        self.srv.close()


def build_shim(workdir: str) -> str:
    so = os.path.join(workdir, "shim.so")
    subprocess.check_call(["cc", "-O2", "-shared", "-fPIC", "-o", so,
                           os.path.join(ROOT, "tools", "allocshim", "shim.c"), "-ldl", "-lpthread"])
    return so


def counts(path: str) -> dict:
    time.sleep(0.25)  # the shim dumps every 20 ms
    out = {}
    with open(path) as f:
        for line in f:
            k, v = line.split()
            out[k] = int(v)
    return out


def total(d: dict) -> int:
    return d["malloc"] + d["calloc"] + d["realloc"] + d["align"]


def read_resp(s: socket.socket) -> None:
    d = b""
    while b"hello\n" not in d:
        x = s.recv(65536)
        if not x:
            break
        d += x


def measure(binary: str, so: str, workdir: str, config: str, shape: str):
    """Return ((ka_count, ka_bytes), (close_count, close_bytes)) for one config and shape."""
    cfg = os.path.join(workdir, f"{config}.cfg")
    with open(cfg, "w") as f:
        f.write(CFG[config].format(front=FRONT_PORT, back=BACKEND_PORT, log=LOG_PORT))
    out = os.path.join(workdir, f"{config}-{shape}.cnt")
    env = dict(os.environ, LD_PRELOAD=so, ALLOCSHIM_OUT=out)
    ka_req, close_req = REQ[shape]
    be = Backend()
    sink = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sink.bind(("127.0.0.1", LOG_PORT))
    sink.setblocking(False)
    p = subprocess.Popen([binary, "-f", cfg], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", FRONT_PORT), timeout=1).close()
                break
            except OSError:
                time.sleep(0.1)
        else:
            raise RuntimeError("alcyon did not start")
        a = socket.create_connection(("127.0.0.1", FRONT_PORT))
        a.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        def ka():
            a.sendall(ka_req)
            read_resp(a)

        def closed():
            c = socket.create_connection(("127.0.0.1", FRONT_PORT))
            c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            c.sendall(close_req)
            read_resp(c)
            c.close()

        for _ in range(3):
            ka()
            closed()
        time.sleep(0.3)
        res = []
        for fn in (ka, closed):
            best = None
            for _ in range(3):
                before = counts(out)
                fn()
                time.sleep(0.2)  # the close path finishes after the client has the reply
                after = counts(out)
                n, b = total(after) - total(before), after["bytes"] - before["bytes"]
                if best is None or n < best[0]:
                    best = (n, b)
            res.append(best)
        a.close()
        return tuple(res)
    finally:
        p.send_signal(signal.SIGTERM)
        try:
            p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            os.kill(p.pid, signal.SIGKILL)
            p.wait()
        be.close()
        sink.close()


def run(binary: str):
    """Measure every pinned (config, shape); return the rows (config, shape, kind, n, bytes, pin)."""
    rows = []
    with tempfile.TemporaryDirectory(prefix="mpr-") as wd:
        so = build_shim(wd)
        for (config, shape), pins in PINS.items():
            ka, cl = measure(binary, so, wd, config, shape)
            rows.append((config, shape, "keep-alive", ka[0], ka[1], pins[0]))
            rows.append((config, shape, "close", cl[0], cl[1], pins[1]))
    return rows


def verdict(rows):
    """Return (failures, notes): a count above its pin fails, below it asks for a lower pin."""
    fails = [r for r in rows if r[3] > r[5]]
    notes = [r for r in rows if r[3] < r[5]]
    return fails, notes


def default_binary() -> str:
    t = os.environ.get("CARGO_TARGET_DIR", os.path.join(ROOT, "target"))
    return os.path.join(t, "release", "alcyon")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", default=os.environ.get("ALCYON_BIN") or default_binary())
    ap.add_argument("--table-only", action="store_true", help="print the table, always exit 0")
    args = ap.parse_args()
    rows = run(args.binary)
    print(f"{'config':6} {'shape':5} {'kind':10} {'allocs':>6} {'bytes':>6} {'pin':>4}")
    for c, s, k, n, b, pin in rows:
        print(f"{c:6} {s:5} {k:10} {n:6} {b:6} {pin:4}")
    fails, notes = verdict(rows)
    for c, s, k, n, _, pin in notes:
        print(f"LOWER THE PIN: {c}/{s} {k} measured {n} < pin {pin}", file=sys.stderr)
    for c, s, k, n, _, pin in fails:
        print(f"FAIL: {c}/{s} {k} allocated {n} times per request, pin is {pin}", file=sys.stderr)
    return 0 if args.table_only or not fails else 1


if __name__ == "__main__":
    sys.exit(main())
