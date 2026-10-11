#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
"""Does the proxy run h2 streams of one connection concurrently?  Lab only (127.0.0.1).
    h2concurrency.py <h2c port> [streams=10]
Opens one connection, sends <streams> GET /drip (the battery's dripping backend: headers at
once, then 1 byte/s) and counts the HEADERS frames that come back within 3 s.  Also prints the
server's SETTINGS."""
import socket, struct, sys, time
sys.path.insert(0, "/root/battery")
from clients import PREFACE, settings, h2_request
port, n = int(sys.argv[1]), int(sys.argv[2]) if len(sys.argv) > 2 else 10
SET = {1: "HEADER_TABLE_SIZE", 2: "ENABLE_PUSH", 3: "MAX_CONCURRENT_STREAMS", 4: "INITIAL_WINDOW_SIZE", 5: "MAX_FRAME_SIZE", 6: "MAX_HEADER_LIST_SIZE"}
s = socket.create_connection(("127.0.0.1", port)); s.sendall(PREFACE + settings())
s.sendall(b"".join(h2_request(1 + 2 * k, b"/drip") for k in range(n)))
s.settimeout(0.2); buf = b""; t0 = time.time(); headers = {}; data = {}; srv_settings = {}
while time.time() - t0 < 3:
    try:
        d = s.recv(65536)
        if not d: break
        buf += d
    except socket.timeout:
        pass
    while len(buf) >= 9:
        ln = int.from_bytes(buf[:3], "big"); t = buf[3]; sid = int.from_bytes(buf[5:9], "big") & 0x7fffffff
        if len(buf) < 9 + ln: break
        pl = buf[9:9 + ln]; buf = buf[9 + ln:]
        if t == 4 and sid == 0 and ln:
            for o in range(0, ln, 6):
                k, v = struct.unpack(">HI", pl[o:o + 6]); srv_settings[SET.get(k, k)] = v
        elif t == 1: headers[sid] = round(time.time() - t0, 3)
        elif t == 0: data[sid] = data.get(sid, 0) + ln
print(f"server SETTINGS: {srv_settings}")
print(f"{n} streams sent on one connection; HEADERS received within 3 s: {len(headers)} (stream -> t): {dict(sorted(headers.items()))}")
print(f"DATA bytes per stream: {dict(sorted(data.items()))}")
s.close()
