#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
"""MY-3 / T288 functional probe: h2c clients ask for a 10 MB object, storm WINDOW_UPDATE +1 frames
and (half of them) never read.  Watches when the proxy closes each connection, its RSS and CPU
per second while the storm is stalled, and the CPU it spends when the sockets finally vanish.
Lab only (127.0.0.1); starts its own haterm on 127.0.0.1:8888.
    my3probe.py <h2c port> <timeout client secs> <conns> label=binary ...
Connection i never reads when i is even (so conns=1 is a single non-reader).  A run lasts until
every connection is closed by the proxy, or 4 x timeout + 1 s after the proxy first stops reading
a connection (CAP env, default 60 s, is the absolute cap), then the survivors are closed with
SO_LINGER 0 and the proxy is sampled for 3 more seconds.  Expected after T288: non-readers closed
at about 2 x timeout client."""
import os, select, socket, struct, subprocess, sys, time
sys.path.insert(0, "/root/battery")
from clients import PREFACE, settings, frame, h2_request

PORT, TMO, CONNS = int(sys.argv[1]), float(sys.argv[2]), int(sys.argv[3])
CAP = float(os.environ.get("CAP", "60"))  # absolute cap in seconds
SPECS = [s.split("=", 1) for s in sys.argv[4:]]
CFG = f"""global
    nbthread 4
    maxconn 2000
defaults
    mode http
    timeout connect 5s
    timeout client {int(TMO)}s
    timeout server 30s
    timeout http-request 5s
frontend f
    bind 127.0.0.1:{PORT} proto h2
    default_backend b
backend b
    server s1 127.0.0.1:8888
"""
TICK = os.sysconf("SC_CLK_TCK")
STORM = (frame(8, 0, 1, struct.pack(">I", 1)) + frame(8, 0, 0, struct.pack(">I", 1))) * 500
HUP = select.POLLRDHUP | select.POLLHUP | select.POLLERR

def stat(pid):
    rss = int([l for l in open(f"/proc/{pid}/status") if l.startswith("VmRSS")][0].split()[1]) // 1024
    f = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()
    return rss, (int(f[11]) + int(f[12])) / TICK

def wait_port(port, secs=5):
    t0 = time.time()
    while time.time() - t0 < secs:
        try: socket.create_connection(("127.0.0.1", port), 0.2).close(); return True
        except OSError: time.sleep(0.05)
    return False

def one(label, pid):
    conns = []
    for i in range(CONNS):
        s = socket.create_connection(("127.0.0.1", PORT)); s.setblocking(False)
        s.sendall(PREFACE + settings()); conns.append({"s": s, "reads": i % 2 == 1, "sent": 0, "rx": 0, "closed": None, "stalled": 0})
    time.sleep(0.2)
    for c in conns: c["s"].send(h2_request(1, b"/?s=10m"))
    t0 = time.time(); last = stat(pid); rows = []; deadline = CAP; first_stall = None
    while time.time() - t0 < deadline and any(c["closed"] is None for c in conns):
        if first_stall is None and any(c["stalled"] > 50 for c in conns):
            first_stall = time.time() - t0; deadline = min(CAP, first_stall + 4 * TMO + 1)
        for c in conns:
            if c["closed"] is not None: continue
            s = c["s"]
            try:
                c["sent"] += s.send(STORM); c["stalled"] = 0
            except BlockingIOError: c["stalled"] += 1
            except OSError as e: c["closed"] = (round(time.time() - t0, 1), f"{e.strerror}")
            if c["closed"] is None and c["reads"]:
                try:
                    while True:
                        d = s.recv(65536)
                        if not d: c["closed"] = (round(time.time() - t0, 1), "EOF"); break
                        c["rx"] += len(d)
                except BlockingIOError: pass
                except OSError as e: c["closed"] = (round(time.time() - t0, 1), f"{e.strerror}")
            if c["closed"] is None:
                p = select.poll(); p.register(s, HUP)
                if p.poll(0): c["closed"] = (round(time.time() - t0, 1), "HUP")
        time.sleep(0.002)
        if time.time() - t0 >= len(rows) + 1:
            cur = stat(pid)
            rows.append((cur[0], round((cur[1] - last[1]) * 100), sum(1 for c in conns if c["closed"] is None),
                         sum(1 for c in conns if c["closed"] is None and c["stalled"] > 50)))
            last = cur
    hold_cpu = stat(pid)[1]
    open_left = [c for c in conns if c["closed"] is None]
    for c in open_left:
        c["s"].setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    for c in conns: c["s"].close()
    t1 = time.time(); after = []; last = stat(pid)
    while time.time() - t1 < 3:
        time.sleep(1); cur = stat(pid); after.append((cur[0], round((cur[1] - last[1]) * 100))); last = cur
    closes = [c["closed"] for c in conns]
    nr = [c["closed"][0] for c in conns if not c["reads"] and c["closed"]]
    rd = [c["closed"][0] for c in conns if c["reads"] and c["closed"]]
    print(f"{label:9s} timeout {TMO:g}s conns {CONNS}: non-readers closed at {nr or 'never'} s, readers at {rd or 'never'} s; "
          f"first stall at {first_stall and round(first_stall, 1)} s, {len(open_left)} still open at {deadline:.0f} s (we RST them); sent {sum(c['sent'] for c in conns)/1e6:.1f} MB, "
          f"received {sum(c['rx'] for c in conns)/1e6:.1f} MB; RSS peak {max(r[0] for r in rows) if rows else 0} MB, "
          f"CPU-s during hold {sum(r[1] for r in rows)/100:.2f}, CPU-s in 3 s after close {sum(a[1] for a in after)/100:.2f}, RSS after {after[-1][0]} MB", flush=True)
    print(f"          per second (rss MB, cpu %, open, stalled): {rows}")
    print(f"          after close (rss MB, cpu %): {after}", flush=True)

ht = subprocess.Popen(["taskset", "-c", "16-31", os.environ.get("ALCYON_LAB_DIR", "/root/alcyon-test") + "/haterm", "-L", "127.0.0.1:8888", "-G", "nbthread 8"],
                      stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
try:
    if not wait_port(8888): print("haterm did not listen"); sys.exit(1)
    time.sleep(0.3); os.sched_setaffinity(0, range(32, 48))
    for label, binary in SPECS:
        cfg = f"/tmp/my3probe-{label}.cfg"; open(cfg, "w").write(CFG)
        log = open(f"/tmp/my3probe-{label}.log", "a")
        p = subprocess.Popen(["taskset", "-c", "0-3", binary, "-f", cfg], stdout=log, stderr=subprocess.STDOUT)
        try:
            if not wait_port(PORT): print(label, "did not listen"); continue
            time.sleep(0.3); one(label, p.pid)
        finally:
            p.terminate(); p.wait(5); log.close()
finally:
    ht.terminate(); ht.wait(5)
    print("haterm stopped; panics:", sum(open(f"/tmp/my3probe-{l}.log").read().count("panic") for l, _ in SPECS))
