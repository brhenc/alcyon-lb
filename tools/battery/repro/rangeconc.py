#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
"""h1_range at 64 connections with a fresh proxy per repetition: per-connection request counts,
latency percentiles, proxy CPU and backend connection churn (haterm CumConns via its stats socket).
Usage (battery host): rangeconc.py <h1 port> <secs> <reps> label=binary [label=binary ...]
Starts its own haterm on 127.0.0.1:8888 with a stats socket at /tmp/rangeconc-haterm.sock."""
import asyncio, os, re, socket, statistics, subprocess, sys, time

PORT, SECS, REPS = int(sys.argv[1]), float(sys.argv[2]), int(sys.argv[3])
CONNS = int(os.environ.get("CONNS", "64"))
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
REQ = b"GET /?s=1m HTTP/1.1\r\nHost: battery\r\n" + RANGE + b"\r\n"
TICK = os.sysconf("SC_CLK_TCK")


def haterm_cli(cmd):
    c = socket.socket(socket.AF_UNIX); c.settimeout(2); c.connect("/tmp/rangeconc-haterm.sock"); c.sendall(cmd + b"\n")
    out = b""
    while True:
        d = c.recv(65536)
        if not d: break
        out += d
    c.close(); return out.decode()


def cumconns():
    m = re.search(r"^CumConns: (\d+)", haterm_cli(b"show info"), re.M); return int(m.group(1)) if m else -1


def cpu_ticks(pid):
    f = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split(); return int(f[11]) + int(f[12])


async def worker(i, end, counts, lats):
    loop = asyncio.get_running_loop()
    s = socket.socket(); s.setblocking(False)
    await loop.sock_connect(s, ("127.0.0.1", PORT))
    try:
        while time.monotonic() < end:
            t = time.perf_counter()
            await loop.sock_sendall(s, REQ)
            buf = b""
            while b"\r\n\r\n" not in buf:
                d = await asyncio.wait_for(loop.sock_recv(s, 65536), 10)
                if not d: return
                buf += d
            head, rest = buf.split(b"\r\n\r\n", 1)
            n = int(re.search(rb"content-length:\s*(\d+)", head.lower()).group(1))
            while len(rest) < n:
                d = await asyncio.wait_for(loop.sock_recv(s, 65536), 10)
                if not d: return
                rest += d
            lats.append((time.perf_counter() - t) * 1000); counts[i] += 1
            await asyncio.sleep(0.01)
    finally:
        s.close()


async def sampler(pid, end, samples):
    t0, c0 = time.monotonic(), cpu_ticks(pid)
    while time.monotonic() < end:
        await asyncio.sleep(1)
        t1, c1 = time.monotonic(), cpu_ticks(pid)
        est = int(subprocess.run("ss -Htn state established '( dport = :8888 )' | wc -l", shell=True, capture_output=True, text=True).stdout or 0)
        samples.append((100 * (c1 - c0) / TICK / (t1 - t0), est)); t0, c0 = t1, c1


async def one(pid):
    end = time.monotonic() + SECS
    counts, lats, samples = [0] * CONNS, [], []
    await asyncio.gather(sampler(pid, end, samples), *[worker(i, end, counts, lats) for i in range(CONNS)])
    return counts, lats, samples


def wait_port(port):
    for _ in range(100):
        try: socket.create_connection(("127.0.0.1", port), 0.2).close(); return True
        except OSError: time.sleep(0.05)
    return False


ht = subprocess.Popen(["taskset", "-c", "16-31", "/root/ibex-test/haterm", "-L", "127.0.0.1:8888", "-G", "nbthread 8",
                       "-G", "stats socket /tmp/rangeconc-haterm.sock mode 666"], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
try:
    wait_port(8888); time.sleep(0.5)
    os.sched_setaffinity(0, range(32, 48))
    specs = [s.split("=", 1) for s in sys.argv[4:]]
    for rep in range(REPS):
        for label, binary in specs:
            cfg = f"/tmp/rangeconc-{label}.cfg"; open(cfg, "w").write(CFG)
            log = open(f"/tmp/rangeconc-{label}.log", "a")
            p = subprocess.Popen(["taskset", "-c", "0-3", binary, "-f", cfg], stdout=log, stderr=subprocess.STDOUT)
            try:
                if not wait_port(PORT): print(label, "did not listen"); continue
                time.sleep(0.3); b0 = cumconns()
                counts, lats, samples = asyncio.run(one(p.pid))
                b1 = cumconns(); lats.sort(); n = len(lats)
                q = lambda f: lats[min(n - 1, int(f * n))] if n else 0
                cs = sorted(counts)
                print(f"{label:9s} rep {rep}: {n:6d} resp ({n / SECS:6.0f}/s), cpu avg {statistics.mean(s[0] for s in samples):5.0f} %, "
                      f"lat p50 {q(.5):6.1f} p90 {q(.9):6.1f} p99 {q(.99):6.1f} max {lats[-1] if n else 0:7.1f} ms, "
                      f"per-conn min/med/max {cs[0]}/{cs[len(cs) // 2]}/{cs[-1]}, slow conns(<half median) {sum(1 for c in cs if c < cs[len(cs) // 2] / 2)}, "
                      f"backend conns +{b1 - b0} (concurrent max {max(s[1] for s in samples)})", flush=True)
            finally:
                p.terminate(); p.wait(5); log.close()
finally:
    ht.terminate(); ht.wait(5)
    print("haterm stopped; panics:", sum(open(f"/tmp/rangeconc-{l}.log").read().count("panic") for l, _ in specs))
