#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
"""T300 item 1: per-stream client timers on one HTTP/2 connection.  Lab only (127.0.0.1).
    t300probe.py <h2c port> label=binary ...
Config: timeout client 4s, timeout server 30s.  Stream 1: GET /?t=7000 (haterm answers after 7 s).
Stream 3: POST with Content-Length 100 whose body never comes.  Expected from HAProxy: stream 3 is
ended at about 4 s (timeout client) and stream 1 is still delivered at about 7 s.  Prints every
frame per stream with its time, the httplog lines, and the connection's end.
Second shape (--long): stream 1 streams a 50 MB response that the client reads slowly while
stream 3 stalls its upload; the stalled upload must still time out at about 4 s."""
import socket, struct, sys, time
sys.path.insert(0, "/root/battery"); sys.path.insert(0, "/root/battery/repro")
from clients import PREFACE, settings, frame, hpack_lit
from labproxy import start_haterm, start_proxy, stop, UdpLog

PORT = int(sys.argv[1]); LONG = "--long" in sys.argv
SPECS = [s.split("=", 1) for s in sys.argv[2:] if "=" in s]
NAMES = {0: "DATA", 1: "HEADERS", 3: "RST_STREAM", 4: "SETTINGS", 6: "PING", 7: "GOAWAY", 8: "WINDOW_UPDATE"}

def hdrs(method_idx, path, extra=b"", end=True):
    # :method via static index (2 = GET, 3 = POST), :scheme http (6), :path literal, :authority literal
    blk = bytes([0x80 | method_idx]) + b"\x86" + b"\x44" + hpack_lit(path) + b"\x41" + hpack_lit(b"battery") + extra
    return blk

def req(sid, method_idx, path, extra=b"", end_stream=True):
    return frame(1, 0x4 | (0x1 if end_stream else 0), sid, hdrs(method_idx, path, extra))

def one(label, binary):
    log = UdpLog()
    cfg = f"""global
    nbthread 4
defaults
    mode http
    log 127.0.0.1:{log.port} local0
    option httplog
    timeout connect 5s
    timeout client 4s
    timeout server 30s
    timeout http-request 10s
frontend f
    bind 127.0.0.1:{PORT} proto h2
    default_backend b
backend b
    server s1 127.0.0.1:8890
"""
    p = start_proxy(binary, cfg, PORT, f"t300-{label}")
    if not p: return
    try:
        s = socket.create_connection(("127.0.0.1", PORT)); s.sendall(PREFACE + settings())
        time.sleep(0.2)
        t0 = time.time()
        slow = b"/?s=50m" if LONG else b"/?t=7000"
        cl = b"\x0f\x0d" + hpack_lit(b"100")  # content-length: 100 (static index 28, literal without indexing)
        s.sendall(req(1, 2, slow) + req(3, 3, b"/upload", cl, end_stream=False))
        s.settimeout(0.1); events = {}; buf = b""; end = None; rx = 0; lastread = t0
        while time.time() - t0 < 12 and end is None:
            if LONG and time.time() - lastread < 0.5:
                time.sleep(0.05); continue  # read slowly: a burst every 0.5 s
            try:
                d = s.recv(65536 if not LONG else 16384)
                if not d: end = ("EOF", round(time.time() - t0, 1)); break
                buf += d; rx += len(d); lastread = time.time()
            except socket.timeout: continue
            except OSError as e: end = (f"{e.strerror}", round(time.time() - t0, 1)); break
            while len(buf) >= 9:
                ln = int.from_bytes(buf[:3], "big"); t = buf[3]; fl = buf[4]; sid = int.from_bytes(buf[5:9], "big") & 0x7fffffff
                if len(buf) < 9 + ln: break
                pl = buf[9:9 + ln]; buf = buf[9 + ln:]
                k = (sid, NAMES.get(t, t)); extra = ""
                if t == 3: extra = f" err={int.from_bytes(pl[:4], 'big')}"
                if t == 7: extra = f" last={int.from_bytes(pl[:4], 'big')} err={int.from_bytes(pl[4:8], 'big')}"
                if t == 1: extra = f" status~{pl[:2].hex()}"
                if t == 0 and k in events: events[k][1] += ln; continue
                events[k] = [round(time.time() - t0, 1), ln, extra, fl]
        s.close()
        print(f"{label}: connection end {end or 'still open at 12 s'}; received {rx} bytes")
        for (sid, name), (t, ln, extra, fl) in sorted(events.items(), key=lambda kv: kv[1][0]):
            print(f"   {t:5.1f}s stream {sid} {name} len={ln} flags={fl:#x}{extra}")
        time.sleep(0.5)
        for t, l in log.lines(t0): print(f"   log {t:5.1f}s {l[-110:]}")
    finally:
        stop(p)

ht = start_haterm(8890)
try:
    for label, binary in SPECS: one(label, binary)
finally:
    stop(ht)
