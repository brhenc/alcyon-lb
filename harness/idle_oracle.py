# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
"""Idle server connections kept after N concurrent requests.

Starts a backend that answers every request (keep-alive) and counts its open connections,
runs the proxy binary given with a config built from the arguments, opens N client
connections, sends one request on each and reads the response while all stay open, then
closes them all and reports the backend's open connections over the next seconds.

usage: harness/idle_oracle.py BINARY N MAXCONN [extra global lines...]
"""
import os, socket, subprocess, sys, tempfile, threading, time

binary, n, maxconn = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
extra = sys.argv[4:]
open_conns = 0
lock = threading.Lock()

srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 0)); srv.listen(1024)
sport = srv.getsockname()[1]

def handle(c):
    global open_conns
    with lock: open_conns += 1
    buf = b""
    try:
        while True:
            d = c.recv(65536)
            if not d: break
            buf += d
            while b"\r\n\r\n" in buf:
                _, buf = buf.split(b"\r\n\r\n", 1)
                c.sendall(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok")
    except OSError:
        pass
    with lock: open_conns -= 1
    c.close()

def accept():
    while True:
        c, _ = srv.accept(); threading.Thread(target=handle, args=(c,), daemon=True).start()
threading.Thread(target=accept, daemon=True).start()

fe = socket.socket(); fe.bind(("127.0.0.1", 0)); fport = fe.getsockname()[1]; fe.close()
cfg = "global\n  nbthread 1\n  maxconn %d\n%s\ndefaults\n  mode http\n  timeout client 10s\n  timeout server 10s\n  timeout connect 2s\nfrontend f\n  bind 127.0.0.1:%d\n  default_backend b\nbackend b\n  server s 127.0.0.1:%d\n" % (
    maxconn, "".join("  %s\n" % e for e in extra), fport, sport)
f = tempfile.NamedTemporaryFile("w", suffix=".cfg", delete=False); f.write(cfg); f.close()
p = subprocess.Popen([binary, "-f", f.name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(0.5)
try:
    clients = []
    for i in range(n):
        c = socket.create_connection(("127.0.0.1", fport)); c.settimeout(5)
        c.sendall(b"GET / HTTP/1.1\r\nhost: x\r\n\r\n")
        clients.append(c)
    for c in clients:
        d = b""
        while not d.endswith(b"ok"): d += c.recv(65536)
    with lock: during = open_conns
    for c in clients: c.close()
    out = ["during=%d" % during]
    t0 = time.time()
    for t in (0.5, 3, 6, 11, 16):
        time.sleep(max(0, t0 + t - time.time()))
        with lock: out.append("+%gs=%d" % (t, open_conns))
    print(os.path.basename(binary), "N=%d maxconn=%d %s:" % (n, maxconn, " ".join(extra)), " ".join(out))
finally:
    p.terminate(); p.wait(); os.unlink(f.name)
