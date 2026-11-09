#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
"""M1: backend connections opened per second under uneven load (T214).

The scenario of crates/alcyon-rt/tests/idle_pool_shared.rs (T159 B): `http-reuse always`, one
server, one request per client connection, so which worker thread a client lands on is up to
the listener (uneven by construction); a backend that counts the connections it accepts.
    tools/measure/m1_uneven_load.py [--threads 4,16] [--seconds 10] [--runs 3]

Scenarios, each on a fresh proxy:
  seq    40 client connections one after the other, 20 ms apart (T159 B test: HAProxy 1)
  wrk    wrk2 -t2 -c100 -R1000 `Connection: close` on /slow, --seconds: conns accepted per second
  burst  cycles of {16 concurrent /slow (50 ms) clients, 20 sequential clients 10 ms apart}
         for --seconds; backend connections accepted per second and in total
Alcyon and HAProxy runs are interleaved; ratio = alcyon / haproxy.
"""
import argparse
import os
import re
import socket
import subprocess
import statistics
import threading
import time
import m1lib as m
from m1_reload import next_port

m.free_port = next_port
WRK2 = os.path.expanduser(os.environ.get("WRK2", "~/.local/bin/wrk2"))


class Backend:
    def __init__(self):
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", next_port()))
        self.sock.listen(1024)
        self.port = self.sock.getsockname()[1]
        self.count = 0
        self.lock = threading.Lock()
        threading.Thread(target=self.accept, daemon=True).start()

    def accept(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            with self.lock:
                self.count += 1
            threading.Thread(target=self.serve, args=(c,), daemon=True).start()

    def serve(self, c):
        buf = b""
        try:
            while True:
                d = c.recv(4096)
                if not d:
                    return
                buf += d
                while b"\r\n\r\n" in buf:
                    head, buf = buf.split(b"\r\n\r\n", 1)
                    if head.startswith(b"GET /slow"):
                        time.sleep(0.05)
                    c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
        except OSError:
            pass
        finally:
            c.close()

    def close(self):
        self.sock.close()


def request(port, path):
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    s.sendall(f"GET {path} HTTP/1.1\r\nHost: x\r\n\r\n".encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        d = s.recv(4096)
        if not d:
            break
        buf += d
    s.close()
    return buf.startswith(b"HTTP/1.1 200")


def cfg(port, be_port, nbthread):
    return f"""global
    nbthread {nbthread}
defaults
    mode http
    timeout connect 2s
    timeout client 30s
    timeout server 30s
listen l
    bind 127.0.0.1:{port}
    http-reuse always
    server s 127.0.0.1:{be_port}
"""


def once(kind, nbthread, seconds):
    be = Backend()
    port = next_port()
    p = m.start(kind, m.write_file(f"uneven-{kind}.cfg", cfg(port, be.port, nbthread)), port)
    try:
        time.sleep(1)  # every worker has bound its own socket
        for _ in range(40):
            request(port, "/")
            time.sleep(0.02)
        with be.lock:
            seq = be.count
        c0, t0, reqs, bad = be.count, time.monotonic(), 0, 0
        while time.monotonic() - t0 < seconds:
            res = []
            ts = [threading.Thread(target=lambda: res.append(request(port, "/slow"))) for _ in range(16)]
            [t.start() for t in ts]
            [t.join() for t in ts]
            time.sleep(0.1)
            for _ in range(20):
                res.append(request(port, "/"))
                time.sleep(0.01)
            time.sleep(0.1)
            reqs += len(res)
            bad += res.count(False)
        el = time.monotonic() - t0
        n = be.count - c0
        # wrk2, one request per client connection, 50 ms answers: ~50 concurrent clients
        # landing wherever the listener puts them
        wc0, wt0 = be.count, time.monotonic()
        w = subprocess.run([WRK2, "-t2", "-c100", "-R1000", "-d", f"{int(seconds)}s", "--timeout", "5s",
                            "-H", "Connection: close", f"http://127.0.0.1:{port}/slow"],
                           capture_output=True, text=True).stdout
        wel = time.monotonic() - wt0
        wn = be.count - wc0
        mt = re.search(r"(\d+) requests in", w)
        wreq = int(mt.group(1)) if mt else 0
        mt = re.search(r"Socket errors: connect (\d+), read (\d+), write (\d+), timeout (\d+)", w)
        werr = sum(int(x) for x in mt.groups()) if mt else 0
        return {"wrk_conns": wn, "wrk_conns_per_s": wn / wel, "wrk_requests": wreq, "wrk_errors": werr,
                "seq_conns": seq, "burst_conns": n, "burst_conns_per_s": n / el,
                "requests": reqs, "failed": bad, "conns_per_request": n / reqs}
    finally:
        m.stop(p)
        be.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--threads", default="4,16")
    ap.add_argument("--seconds", type=float, default=10)
    ap.add_argument("--runs", type=int, default=3)
    a = ap.parse_args()
    print(m.header("m1_uneven_load"), f"seconds={a.seconds}", flush=True)
    m.wait_load(limit=16, patience=30)
    for nt in [int(x) for x in a.threads.split(",")]:
        res = {"alcyon": [], "haproxy": []}
        for run in range(a.runs):
            for kind in ("alcyon", "haproxy"):
                r = once(kind, nt, a.seconds)
                res[kind].append(r)
                m.emit(param="uneven", nbthread=nt, kind=kind, run=run, **r)
        med = {k: {f: statistics.median(r[f] for r in rs) for f in rs[0]} for k, rs in res.items()}
        m.emit(param="uneven-median", nbthread=nt, alcyon=med["alcyon"], haproxy=med["haproxy"],
               ratio_burst_conns_per_s=med["alcyon"]["burst_conns_per_s"] / med["haproxy"]["burst_conns_per_s"],
               ratio_wrk_conns_per_s=med["alcyon"]["wrk_conns_per_s"] / med["haproxy"]["wrk_conns_per_s"])


if __name__ == "__main__":
    main()
