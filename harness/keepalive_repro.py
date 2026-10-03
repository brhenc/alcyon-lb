#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

"""Keep-alive repro: 3 requests on one client connection, two backend styles.
usage: ka_repro.py <proxy-binary> [runs]"""
import socket, subprocess, sys, tempfile, threading, time
BIN = sys.argv[1]; RUNS = int(sys.argv[2]) if len(sys.argv) > 2 else 5
def port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p
def backend(style):
    ls = socket.socket(); ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("127.0.0.1", 0)); ls.listen(64)
    def serve(c):
        c.recv(65536)
        if style == "close-header":
            c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        else:  # "fin": Content-Length response, no Connection header, then close (HTTP/1.0-ish server)
            c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        c.close()
    def loop():
        while True:
            c, _ = ls.accept(); threading.Thread(target=serve, args=(c,), daemon=True).start()
    threading.Thread(target=loop, daemon=True).start()
    return ls.getsockname()[1]
def once(fe):
    c = socket.create_connection(("127.0.0.1", fe), timeout=3); got = 0
    for i in range(3):
        try:
            c.sendall(b"GET /%d HTTP/1.1\r\nHost: x\r\n\r\n" % i)
            d = b""
            while b"\r\n\r\n" not in d or not d.endswith(b"ok"):
                x = c.recv(65536)
                if not x: break
                d += x
            if d.startswith(b"HTTP/1.1 200") and d.endswith(b"ok") and b"onnection: close" not in d: got += 1
            else: break
        except OSError: break
    c.close(); return got
for style in ("close-header", "fin"):
    be = backend(style); fe = port()
    cfg = tempfile.NamedTemporaryFile("w", suffix=".cfg", delete=False)
    cfg.write(f"defaults\n mode http\n timeout connect 2s\n timeout client 5s\n timeout server 5s\n"
              f"frontend fe\n bind 127.0.0.1:{fe}\n http-response set-header X-Seen yes\n default_backend be\n"
              f"backend be\n server s1 127.0.0.1:{be}\n"); cfg.close()
    p = subprocess.Popen([BIN, "-f", cfg.name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.5)
    print(f"{style:13s}", [f"{once(fe)}/3" for _ in range(RUNS)])
    p.kill(); p.wait()
