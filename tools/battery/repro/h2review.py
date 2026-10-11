#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
"""Single-connection h2 probes for the 2026-10-10 production-review items (#1 DATA beyond the
receive window, #2 SETTINGS_MAX_FRAME_SIZE=0, #11 rapid reset beside a slow POST, #12 sending
after GOAWAY without reading).  Lab only (127.0.0.1).
    h2review.py <h2c port> <proxy pid> <item> [seconds=15]
Samples the proxy's RSS (MB) and CPU (% of one core) once a second while the probe runs, then
prints the bytes the probe managed to send and what came back."""
import os, socket, struct, sys, time
sys.path.insert(0, "/root/battery")
from clients import PREFACE, settings, frame, h2_request, hpack_lit, rst, try_drain

port, pid, item = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
secs = float(sys.argv[4]) if len(sys.argv) > 4 else 15
TICK = os.sysconf("SC_CLK_TCK")

def stat():
    rss = int([l for l in open(f"/proc/{pid}/status") if l.startswith("VmRSS")][0].split()[1]) // 1024
    f = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()
    return rss, (int(f[11]) + int(f[12])) / TICK

def run(prelude, repeat, read=True):
    s = socket.create_connection(("127.0.0.1", port)); s.setblocking(False)
    def send(b):
        tot = 0
        while tot < len(b):
            try: tot += s.send(b[tot:])
            except BlockingIOError: time.sleep(0.001)
        return tot
    sent = 0; sent += send(PREFACE + settings()); time.sleep(0.2); sent += send(prelude)
    t0 = time.time(); last = stat(); rows = []; closed = None; rx = 0; stalled = 0
    while time.time() - t0 < secs and not closed:
        try:
            n = s.send(repeat)
            if n == 0: stalled += 1
            sent += n
        except BlockingIOError:
            stalled += 1; time.sleep(0.001)
        except OSError as e:
            closed = f"{e} at {time.time()-t0:.1f}s"
        if read:
            try:
                while True:
                    d = s.recv(65536)
                    if not d: closed = closed or f"EOF at {time.time()-t0:.1f}s"; break
                    rx += len(d)
            except BlockingIOError: pass
            except OSError as e: closed = closed or f"{e} at {time.time()-t0:.1f}s"
        if time.time() - t0 >= len(rows) + 1:
            cur = stat(); rows.append((cur[0], round((cur[1] - last[1]) * 100))); last = cur
    s.close()
    print(f"  sent {sent/1e6:.1f} MB, received {rx/1e6:.2f} MB, closed: {closed or 'no'}")
    print(f"  proxy RSS MB per second: {[r[0] for r in rows]}")
    print(f"  proxy CPU % per second:  {[r[1] for r in rows]}")
    time.sleep(2); print(f"  2 s later: RSS {stat()[0]} MB")

if item == "1":   # stream 1 to the slow backend, DATA on a POST stream 3 ignoring every window
    print("#1 DATA beyond the receive window:")
    run(h2_request(1, b"/drip") + frame(1, 0x4, 3, b"\x83\x86\x84\x41" + hpack_lit(b"battery")),
        frame(0, 0, 3, b"x" * 16384) * 8)
elif item == "2":  # SETTINGS_MAX_FRAME_SIZE=0 then a request with a body to send back
    print("#2 SETTINGS_MAX_FRAME_SIZE=0:")
    run(settings([(5, 0)]) + h2_request(1, b"/?s=1m"), frame(6, 0, 0, b"12345678"))
elif item == "11": # slow POST on stream 1 (never finished) + HEADERS/RST pairs at line rate
    print("#11 rapid reset beside a slow POST:")
    pairs = b"".join(h2_request(3 + 2 * k, b"/?s=1m") + rst(3 + 2 * k) for k in range(100))
    run(frame(1, 0x4, 1, b"\x83\x86\x84\x41" + hpack_lit(b"battery")) + frame(0, 0, 1, b"y" * 100), pairs)
elif item == "12": # provoke a GOAWAY, then keep sending frames without ever reading
    print("#12 send after GOAWAY without reading:")
    run(frame(9, 0, 1, b"\x00"), frame(6, 0, 0, b"12345678") * 100, read=False)
