# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
# Backend connection reuse across client connections, HTTP/1.1 clients, plain.
#   reuse.py BIN PORT REUSE_MODE(default|never|safe|aggressive|always)
import socket, subprocess, sys, threading, time
BIN, PORT, MODE = sys.argv[1], int(sys.argv[2]), sys.argv[3]
BE = PORT + 50
n = {"conns": 0, "reqs": 0}
def be():
    ls = socket.socket(); ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("127.0.0.1", BE)); ls.listen(64)
    while True:
        c, _ = ls.accept(); n["conns"] += 1
        threading.Thread(target=serve, args=(c,), daemon=True).start()
def serve(c):
    b = b""
    try:
        while True:
            while b"\r\n\r\n" not in b:
                d = c.recv(65536)
                if not d: return
                b += d
            _, b = b.split(b"\r\n\r\n", 1); n["reqs"] += 1
            c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
    except OSError: pass
threading.Thread(target=be, daemon=True).start()
reuse = "" if MODE == "default" else f"    http-reuse {MODE}\n"
cf = f"/tmp/vv-reuse-{PORT}.cfg"
open(cf, "w").write(f"global\n    nbthread 1\ndefaults\n    mode http\n    timeout connect 1s\n    timeout client 5s\n    timeout server 5s\nfrontend fe\n    bind 127.0.0.1:{PORT}\n    default_backend b\nbackend b\n{reuse}    server s1 127.0.0.1:{BE}\n")
p = subprocess.Popen([BIN, "-f", cf], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); time.sleep(0.5)
def client(k):
    s = socket.create_connection(("127.0.0.1", PORT)); s.settimeout(3)
    for i in range(k):
        s.sendall(b"GET /%d HTTP/1.1\r\nHost: x\r\n\r\n" % i); o = b""
        while not o.endswith(b"ok"): o += s.recv(4096)
    s.close()
out = []
for label, k in (("seq 10 clients x 1 req", 1), ("seq 10 clients x 3 req", 3)):
    c0, r0 = n["conns"], n["reqs"]
    for _ in range(10):
        client(k); time.sleep(0.05)
    time.sleep(0.2)
    out.append(f"{label}: backend conns +{n['conns'] - c0} reqs +{n['reqs'] - r0}")
print(f"{MODE:10s} " + " | ".join(out)); p.terminate(); p.wait()
