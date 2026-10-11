#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
"""TCP mode: clients that connect and close without sending a byte.  Lab only (127.0.0.1).
    tcpprobe.py <port> <conns> label=binary ...
Two configs: plain `mode tcp` + default_backend, and `tcp-request inspect-delay 2s` with
`tcp-request content accept if { req.len gt 0 }`.  Opens <conns> connections, closes each at once
(half with RST), and reports the backend connections haterm saw (CumConns via its stats socket),
the proxy's fds and RSS after 3 s, and the proxy's CPU-seconds."""
import re, socket, struct, sys, time
sys.path.insert(0, "/root/battery/repro")
from labproxy import start_haterm, start_proxy, stop, fds, rss_cpu, be_conns

PORT, CONNS = int(sys.argv[1]), int(sys.argv[2])
SPECS = [s.split("=", 1) for s in sys.argv[3:]]
SOCK = "/tmp/tcpprobe-haterm.sock"
CFGS = {
    "plain": "",
    "inspect": "    tcp-request inspect-delay 2s\n    tcp-request content accept if { req.len gt 0 }\n",
}

def cli(cmd):
    c = socket.socket(socket.AF_UNIX); c.settimeout(2); c.connect(SOCK); c.sendall(cmd + b"\n")
    out = b""
    while True:
        try: d = c.recv(65536)
        except socket.timeout: break
        if not d: break
        out += d
    c.close(); return out.decode(errors="replace")

def cumconns():
    m = re.search(r"^CumConns: (\d+)", cli(b"show info"), re.M); return int(m.group(1)) if m else -1

def one(label, binary, kind):
    cfg = f"""global
    nbthread 4
    maxconn 2000
defaults
    mode tcp
    timeout connect 5s
    timeout client 3s
    timeout server 3s
frontend f
    bind 127.0.0.1:{PORT}
{CFGS[kind]}    default_backend b
backend b
    server s1 127.0.0.1:8890
"""
    p = start_proxy(binary, cfg, PORT, f"tcp-{label}-{kind}")
    if not p: return
    try:
        b0 = cumconns(); f0 = fds(p.pid); c0 = rss_cpu(p.pid)[1]
        for i in range(CONNS):
            s = socket.create_connection(("127.0.0.1", PORT))
            if i % 2: s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            s.close()
        time.sleep(3)
        b1 = cumconns(); r, c1 = rss_cpu(p.pid)
        print(f"{label:9s} {kind:8s} {CONNS} connect+close (half RST), no bytes: backend conns +{b1 - b0}, "
              f"proxy fds {f0} -> {fds(p.pid)}, backend established now {be_conns(8890)}, RSS {r} MB, CPU-s {c1 - c0:.2f}", flush=True)
    finally:
        stop(p)

ht = start_haterm(8890, extra=("-G", f"stats socket {SOCK} mode 666"))
try:
    for kind in CFGS:
        for label, binary in SPECS: one(label, binary, kind)
finally:
    stop(ht)
