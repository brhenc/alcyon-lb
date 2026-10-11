#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
"""T305 item 1 / item 7: http-request reject, http-request silent-drop (with rst-ttl), http-response
silent-drop, tcp-request connection/content silent-drop rst-ttl, on h1 and h2c.  Lab only (127.0.0.1).
    rejectprobe.py <h1 port> <h2c port> label=binary ...
For each rule: start the proxy with that rule, send one request, report the bytes received, how the
connection ended (EOF / RST / still open) and when, the httplog line, whether the backend was
contacted, and the IP TTL of the RST the proxy sent (read from a raw socket on lo; silent-drop sets
TTL 1 by default, rst-ttl N sets N).  Needs root for the raw socket."""
import socket, struct, sys, threading, time
sys.path.insert(0, "/root/battery"); sys.path.insert(0, "/root/battery/repro")
from clients import PREFACE, settings, h2_request
import labproxy
from labproxy import start_haterm, start_proxy, stop, UdpLog, ended_how, be_conns, h2_frames

H1, H2 = int(sys.argv[1]), int(sys.argv[2])
SPECS = [s.split("=", 1) for s in sys.argv[3:] if "=" in s]
ONLY = [a for a in sys.argv[3:] if "=" not in a]
RULES = [
    ("http-request reject",                          "fe", "GET /x"),
    ("http-request silent-drop",                     "fe", "GET /x"),
    ("http-request silent-drop rst-ttl 7",           "fe", "GET /x"),
    ("http-response silent-drop",                    "fe", "GET /x"),
    ("http-response silent-drop rst-ttl 7",          "fe", "GET /x"),
    ("tcp-request connection silent-drop",           "fe", "GET /x"),
    ("tcp-request connection silent-drop rst-ttl 9", "fe", "GET /x"),
    ("tcp-request content silent-drop rst-ttl 11",   "fe", "GET /x"),
]

class RstSniffer:
    """Records (ttl, src port) of TCP packets with RST set sent from the proxy's ports on lo."""
    def __init__(self, ports):
        self.ports = set(ports); self.seen = []
        self.s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800)); self.s.bind(("lo", 0)); self.s.settimeout(0.2)
        threading.Thread(target=self._rx, daemon=True).start()
    def _rx(self):
        while True:
            try: pkt = self.s.recv(65535)
            except socket.timeout: continue
            except OSError: return
            ip = pkt[14:]
            if len(ip) < 40 or ip[9] != 6: continue
            ihl = (ip[0] & 0xf) * 4; ttl = ip[8]; tcp = ip[ihl:]
            sport = int.from_bytes(tcp[0:2], "big"); flags = tcp[13]
            if sport in self.ports and flags & 0x04: self.seen.append((ttl, sport, time.time()))
    def rsts(self, since): return [(ttl, sp) for ttl, sp, ts in self.seen if ts >= since]

def one(label, binary, rule, scope, sniff):
    log = UdpLog()
    cfg = f"""global
    nbthread 4
defaults
    mode http
    log 127.0.0.1:{log.port} local0
    option httplog
    timeout connect 5s
    timeout client 3s
    timeout server 3s
    timeout http-request 3s
frontend f
    bind 127.0.0.1:{H1}
    bind 127.0.0.1:{H2} proto h2
    {rule}
    default_backend b
backend b
    server s1 127.0.0.1:8890
"""
    tag = f"rej-{label}-{len(log.lines())}"
    p = start_proxy(binary, cfg, H1, tag)
    if not p: print(f"{label:9s} {rule:48s} config refused: {open(f'/tmp/probe-{tag}.log').read().strip().splitlines()[-1][:120]}"); return
    try:
        for proto, port in (("h1", H1), ("h2", H2)):
            t0 = time.time(); b0 = be_conns(8890)
            s = socket.create_connection(("127.0.0.1", port))
            if proto == "h1": s.sendall(b"GET /x HTTP/1.1\r\nHost: battery\r\n\r\n")
            else: s.sendall(PREFACE + settings() + h2_request(1, b"/x"))
            n, how, t = ended_how(s, 5)
            s.close(); time.sleep(0.3)
            rst = sniff.rsts(t0)
            fr = (" " + h2_frames(bytes(labproxy.LAST_BYTES))) if proto == "h2" else ""
            print(f"{label:9s} {rule:48s} {proto}: {n:4d} B back{fr}, {how:4s} at {t:4.2f}s, RST ttl {sorted(set(r[0] for r in rst)) or '-'}, "
                  f"log: {' | '.join(l[-60:] for _, l in log.lines() if l) or '-'}", flush=True)
            log.buf.clear()
    finally:
        stop(p)

ht = start_haterm(8890)
sniff = RstSniffer([H1, H2])
try:
    for rule, scope, _ in RULES:
        if ONLY and not any(o in rule for o in ONLY): continue
        for label, binary in SPECS: one(label, binary, rule, scope, sniff)
finally:
    stop(ht)
