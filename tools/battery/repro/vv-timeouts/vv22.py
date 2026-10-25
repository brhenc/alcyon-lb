#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
"""VV-22: `timeout client` fires while the proxy is still connecting to the server.

vv22.py IBEX [HAPROXY]
The server 10.9.9.9 is unreachable (connects time out). One GET per case; prints the status, the time it
took, and the log line. HAProxy waits for the connect retries and answers 503 `sC--`. Ibex answers
400 `cH--` at `timeout client` whenever timeout connect x (retries + 1) > timeout client.
Port 19970, slow backend (2 s) on 127.0.0.1:19972."""
import socket, subprocess, sys, tempfile, threading, time

IB = sys.argv[1]; HA = sys.argv[2] if len(sys.argv) > 2 else "/home/bhenc/reference/haproxy/haproxy"
P = 19970

def slow_backend(port, delay):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port)); s.listen(8)
    def one(c):
        c.recv(4096); time.sleep(delay)
        c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"); c.close()
    def loop():
        while True:
            c, _ = s.accept(); threading.Thread(target=one, args=(c,), daemon=True).start()
    threading.Thread(target=loop, daemon=True).start()

def cfg(client, connect, server, extra=""):
    return ("global\n    log stdout format raw local0\ndefaults\n    mode http\n    log global\n    option httplog\n"
            "    timeout connect %s\n    timeout client %s\n    timeout server %s\nlisten l\n    bind 127.0.0.1:%d\n%s"
            % (connect, client, server, P, extra))

CASES = [
    ("unreachable, client 2s, connect 1s, retries 3", cfg("2s", "1s", "5s", "    server s1 10.9.9.9:80\n")),
    ("unreachable, client 1s, connect 3s, retries 3", cfg("1s", "3s", "5s", "    server s1 10.9.9.9:80\n")),
    ("unreachable, client 5s, connect 1s, retries 3 (no overlap)", cfg("5s", "1s", "5s", "    server s1 10.9.9.9:80\n")),
    ("unreachable, client 2s, connect 1s, retries 0 (no overlap)", cfg("2s", "1s", "5s", "    retries 0\n    server s1 10.9.9.9:80\n")),
    ("slow backend 2s, client 1s, server 5s (control)", cfg("1s", "1s", "5s", "    server s1 127.0.0.1:19972\n")),
]

slow_backend(19972, 2.0)
d = tempfile.mkdtemp(prefix="vv22-")
for name, conf in CASES:
    f = d + "/c.cfg"; open(f, "w").write(conf)
    print(name)
    for tag, b in (("ibex", IB), ("haproxy", HA)):
        p = subprocess.Popen(["taskset", "-c", "48-51", b, "-f", f], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        time.sleep(0.4)
        t = time.time()
        try:
            s = socket.create_connection(("127.0.0.1", P), 2); s.settimeout(20)
            s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            r = s.recv(300).split(b"\r\n")[0].decode() or "empty"
        except Exception as e:
            r = type(e).__name__
        el = time.time() - t
        time.sleep(0.2); p.terminate()
        o = p.communicate()[0].decode(errors="replace").splitlines()
        lg = [l.split(" l ", 1)[-1] for l in o if '"GET' in l]
        print("   %-7s %5.2fs %-34s %s" % (tag, el, r, lg[-1] if lg else "(no log line)"))
