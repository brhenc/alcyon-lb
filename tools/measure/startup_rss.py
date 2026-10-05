#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
"""Startup RSS of Ibex and HAProxy on N backends of one server each (T175).

Milestone M1: "RSS at startup, 10 / 1k / 10k backends <= 1.5x HAProxy".

    tools/measure/startup_rss.py [--ibex PATH] [--haproxy PATH] [--backends 10,1000,10000]
                                 [--nbthread 1,16] [--no-haproxy]

Starts each binary in the foreground on a generated config (`global maxconn 1000`,
`nbthread T`, one frontend, N backends `server sK 127.0.0.1:port`), waits until it
listens, sleeps 1 s, reads VmRSS from /proc/<pid>/status, stops it (SIGUSR1, then
SIGTERM), and prints a table with the ratio. Use a release build of ibex
(default: $CARGO_TARGET_DIR/release/ibex, else target/release/ibex).
Exit status 1 when the worst ratio exceeds 1.5.
"""
import argparse
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def default_ibex():
    tgt = os.environ.get("CARGO_TARGET_DIR", os.path.join(ROOT, "target"))
    return os.path.join(tgt, "release", "ibex")


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def config(backends, nbthread, port):
    out = [
        "global",
        f"    nbthread {nbthread}",
        "    maxconn 1000",
        "defaults",
        "    mode http",
        "    timeout connect 5s",
        "    timeout client 5s",
        "    timeout server 5s",
        "frontend fe",
        f"    bind 127.0.0.1:{port}",
        "    default_backend b0",
    ]
    for i in range(backends):
        out.append(f"backend b{i}")
        out.append(f"    server s{i} 127.0.0.1:{20000 + i % 1000}")
    return "\n".join(out) + "\n"


def rss_kb(binary, backends, nbthread, extra):
    port = free_port()
    fd, path = tempfile.mkstemp(prefix="startup-rss-", suffix=".cfg")
    with os.fdopen(fd, "w") as f:
        f.write(config(backends, nbthread, port))
    proc = subprocess.Popen([binary, *extra, "-f", path],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.time() + 120
        while True:
            if proc.poll() is not None:
                raise RuntimeError(f"{binary} exited with {proc.returncode}")
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                break
            except OSError:
                if time.time() > deadline:
                    raise RuntimeError(f"{binary} did not listen on {port}")
                time.sleep(0.05)
        time.sleep(1.0)
        with open(f"/proc/{proc.pid}/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1])
        raise RuntimeError("no VmRSS")
    finally:
        for sig in (signal.SIGUSR1, signal.SIGTERM, signal.SIGKILL):
            if proc.poll() is not None:
                break
            proc.send_signal(sig)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
        os.unlink(path)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--ibex", default=default_ibex())
    ap.add_argument("--haproxy", default="/home/bhenc/reference/haproxy/haproxy")
    ap.add_argument("--backends", default="10,1000,10000")
    ap.add_argument("--nbthread", default="1,16")
    ap.add_argument("--no-haproxy", action="store_true")
    a = ap.parse_args()
    print(f"{'backends':>8} {'nbthread':>8} {'ibex MB':>9} {'haproxy MB':>11} {'ratio':>6}")
    worst = 0.0
    for t in [int(x) for x in a.nbthread.split(",")]:
        for n in [int(x) for x in a.backends.split(",")]:
            i = rss_kb(a.ibex, n, t, [])
            h = None if a.no_haproxy else rss_kb(a.haproxy, n, t, ["-db"])
            ratio = f"{i / h:6.2f}" if h else f"{'-':>6}"
            if h:
                worst = max(worst, i / h)
            hs = f"{h / 1024:11.1f}" if h else f"{'-':>11}"
            print(f"{n:>8} {t:>8} {i / 1024:9.1f} {hs} {ratio}", flush=True)
    if worst:
        print(f"worst ratio {worst:.2f} (M1 bound 1.50)")
        return 0 if worst <= 1.5 else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
