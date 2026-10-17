#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
"""T342a: h2 client opens a 2^31-1 window, GETs a big body and reads nothing; print proxy RSS.
   norecv.py PORT PROXY_PID SIZE SECONDS"""
import os, struct, sys, time
PORT, PID, SIZE, SECS = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), float(sys.argv[4])
sys.argv = [sys.argv[0], PORT, "/dev/null"]
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "vv-h2abort"))
import h2c as u
def rss(): return int([l for l in open("/proc/%d/status" % PID) if l.startswith("VmRSS")][0].split()[1])
r0 = rss()
c = u.Conn(iws=2**31 - 1)
c.send(8, 0, 0, struct.pack(">I", 2**31 - 1 - 65535))
c.open(b"GET", b"/big/%d" % SIZE)
peak = r0; t0 = time.time()
while time.time() - t0 < SECS:
    time.sleep(0.25); peak = max(peak, rss())
print("rss before %d kB, peak while not reading %d kB, delta %+d kB" % (r0, peak, peak - r0))
c.s.close()
