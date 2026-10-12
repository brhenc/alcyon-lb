#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
"""Keep-alive HTTP/1.1 backend, answers every request 200 "ok" after 50 ms.  slowbe.py PORT"""
import socket, sys, threading, time

def h(c):
    b = b""
    try:
        while True:
            while b"\r\n\r\n" not in b:
                d = c.recv(4096)
                if not d:
                    return
                b += d
            b = b.split(b"\r\n\r\n", 1)[1]
            time.sleep(0.05)
            c.sendall(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok")
    except OSError:
        pass
    finally:
        c.close()

s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(sys.argv[1]))); s.listen(64)
while True:
    c, _ = s.accept()
    threading.Thread(target=h, args=(c,), daemon=True).start()
