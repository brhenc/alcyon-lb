#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
"""be.py <ip> <port>: keep-alive HTTP backend answering its own address in the body.

dns_battery.py's traffic cases start two of these (copied from the T481 oracle rig, T630)."""
import socket, sys, threading
ip, port = sys.argv[1], int(sys.argv[2])
def conn(c):
    with c:
        buf = b""
        while True:
            d = c.recv(4096)
            if not d:
                return
            buf += d
            while b"\r\n\r\n" in buf:
                _, buf = buf.split(b"\r\n\r\n", 1)
                body = ("backend %s:%d\n" % (ip, port)).encode()
                c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: keep-alive\r\n\r\n" % len(body) + body)
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((ip, port)); s.listen(16)
while True:
    c, _ = s.accept()
    threading.Thread(target=conn, args=(c,), daemon=True).start()
