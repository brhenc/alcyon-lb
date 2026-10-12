#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
"""T318 malloc_trim probe: does giving the heap back after a burst stall legit traffic, and can a
client make the proxy trim over and over?  Shape: HELD slow clients keep a request buffer each (the
heap stays large), then ROUNDS pulses of BURST short connections each followed by GAP seconds of
quiet (longer than the 500 ms trim threshold), so every pulse ends in a trim while the heap is
still big.  A legit keep-alive client sends one GET every few ms the whole time and records each
latency; RSS is sampled every 50 ms (a drop between samples is the trim signature).  Lab only.
    trimprobe.py <port> label=binary ...
    env HELD=2000 BURST=300 ROUNDS=20 GAP=0.7 LEGIT_MS=5"""
import os, resource, socket, sys, threading, time
sys.path.insert(0, "/root/battery"); sys.path.insert(0, "/root/battery/repro")
from labproxy import start_haterm, start_proxy, stop, fds, rss_cpu

PORT = int(sys.argv[1]); SPECS = [s.split("=", 1) for s in sys.argv[2:]]
HELD = int(os.environ.get("HELD", "2000")); BURST = int(os.environ.get("BURST", "300"))
ROUNDS = int(os.environ.get("ROUNDS", "20")); GAP = float(os.environ.get("GAP", "0.7"))
LEGIT_MS = float(os.environ.get("LEGIT_MS", "5")); BE = 8893
resource.setrlimit(resource.RLIMIT_NOFILE, (65536, 65536))
CFG = f"""global
    nbthread 4
    maxconn 20000
defaults
    mode http
    timeout connect 5s
    timeout client 60s
    timeout server 60s
    timeout http-request 60s
    timeout http-keep-alive 60s
frontend f
    bind 127.0.0.1:{PORT}
    default_backend b
backend b
    server s1 127.0.0.1:{BE}
"""
GET = b"GET /?s=1k HTTP/1.1\r\nHost: lab\r\n\r\n"
PARTIAL = b"GET / HTTP/1.1\r\nHost: lab\r\nX-Slow: 1"  # no end of headers: the proxy keeps the buffer

def one_get(s):
    s.sendall(GET); got = b""
    while b"\r\n\r\n" not in got: got += s.recv(65536)
    head, body = got.split(b"\r\n\r\n", 1)
    cl = int([l for l in head.split(b"\r\n") if l.lower().startswith(b"content-length:")][0].split(b":")[1])
    while len(body) < cl: body += s.recv(65536)

class Legit(threading.Thread):
    """One keep-alive connection, a GET every LEGIT_MS; (t, latency ms) per request."""
    def __init__(self): super().__init__(daemon=True); self.lat = []; self.run_ = True; self.phase = "base"
    def run(self):
        s = socket.create_connection(("127.0.0.1", PORT)); s.settimeout(10)
        while self.run_:
            t0 = time.time()
            try: one_get(s)
            except OSError as e: self.lat.append((t0, 9999.0, self.phase)); s = socket.create_connection(("127.0.0.1", PORT)); s.settimeout(10); continue
            self.lat.append((t0, (time.time() - t0) * 1000, self.phase)); time.sleep(LEGIT_MS / 1000)

class Sampler(threading.Thread):
    def __init__(self, pid): super().__init__(daemon=True); self.pid = pid; self.rows = []; self.run_ = True
    def run(self):
        while self.run_:
            r, c = rss_cpu(self.pid); self.rows.append((time.time(), r, c)); time.sleep(0.05)

def burst(n):
    """n short connections, one GET each, 8 at a time, all closed at the end."""
    errs = [0]
    def w(k):
        for _ in range(k):
            try:
                s = socket.create_connection(("127.0.0.1", PORT)); s.settimeout(5); one_get(s); s.close()
            except OSError: errs[0] += 1
    ts = [threading.Thread(target=w, args=(n // 8,)) for _ in range(8)]
    for t in ts: t.start()
    for t in ts: t.join()
    return errs[0]

def pct(v, p):
    v = sorted(v); return v[min(len(v) - 1, int(len(v) * p))] if v else 0.0

def report(label, phase, lat, rows, t_a, t_b):
    l = [x[1] for x in lat if x[2] == phase]; r = [x for x in rows if t_a <= x[0] <= t_b]
    drops = sum(1 for a, b in zip(r, r[1:]) if a[1] - b[1] >= 1)
    rss = [x[1] for x in r] or [0]; cpu = (r[-1][2] - r[0][2]) if len(r) > 1 else 0.0
    print(f"  {label:8s} {phase:7s} legit n={len(l):5d} p50 {pct(l, .5):6.2f} p99 {pct(l, .99):7.2f} max {max(l) if l else 0:8.2f} ms, "
          f">20ms {sum(1 for x in l if x > 20):3d} >100ms {sum(1 for x in l if x > 100):3d}; RSS {min(rss)}-{max(rss)} MB, drops>=1MB {drops}; "
          f"CPU {cpu:.1f} s over {t_b - t_a:.1f} s", flush=True)

def one(label, binary):
    p = start_proxy(binary, CFG, PORT, f"trim-{label}")
    if not p: return
    held = []; lg = Legit(); sm = Sampler(p.pid)
    try:
        time.sleep(0.3); lg.start(); sm.start()
        t0 = time.time(); time.sleep(2.0); t1 = time.time()
        lg.phase = "held"
        for _ in range(HELD):
            try: s = socket.create_connection(("127.0.0.1", PORT)); s.sendall(PARTIAL); held.append(s)
            except OSError: break
        time.sleep(1.5); t2 = time.time()
        lg.phase = "pulses"; errs = 0
        for _ in range(ROUNDS):
            errs += burst(BURST); time.sleep(GAP)
        t3 = time.time()
        lg.phase = "after"
        for s in held: s.close()
        held = []; time.sleep(2.0); t4 = time.time()
        lg.run_ = False; sm.run_ = False; lg.join(2); sm.join(1)
        print(f"{label}: held {HELD} slow clients, {ROUNDS} pulses of {BURST} conns + {GAP} s quiet, burst errors {errs}, fds now {fds(p.pid)}, alive {p.poll() is None}")
        report(label, "base", lg.lat, sm.rows, t0, t1); report(label, "held", lg.lat, sm.rows, t1, t2)
        report(label, "pulses", lg.lat, sm.rows, t2, t3); report(label, "after", lg.lat, sm.rows, t3, t4)
        # per-pulse worst legit latency and the RSS low point, to see whether every quiet period costs something
        pl = [x for x in lg.lat if x[2] == "pulses"]; per = []
        for k in range(ROUNDS):
            a = t2 + k * (t3 - t2) / ROUNDS; b = a + (t3 - t2) / ROUNDS
            w = [x[1] for x in pl if a <= x[0] < b]; rr = [x[1] for x in sm.rows if a <= x[0] < b]
            per.append(f"{max(w) if w else 0:.0f}/{min(rr) if rr else 0}-{max(rr) if rr else 0}")
        print(f"  {label:8s} per pulse worst legit ms / RSS min-max MB: {' '.join(per)}", flush=True)
    finally:
        lg.run_ = False; sm.run_ = False
        for s in held: s.close()
        stop(p)

ht = start_haterm(BE)
try:
    for label, binary in SPECS: one(label, binary)
finally:
    stop(ht)
