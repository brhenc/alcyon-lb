#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
"""Scripted DNS server for the V&V resolver battery (UDP + TCP on one port number).

vvdns.py PORT ZONE.json LOG

Built on the T481 oracle's fakedns.py, with hostile modes added. The zone file is re-read on every
query, so a battery can change answers while the proxy runs. Per name:
  "a": [ip...], "aaaa": [ip...], "ttl": N, "rcode": "nx|refused|servfail", "nodata": true,
  "silent": true, "delay": secs, "cname": "name", "tc_udp": true (TC over UDP, no records),
  "tc_keep": true (TC over UDP, the records kept),
  hostile modes, each sent BEFORE the honest answer (or instead of it with "only": true):
  "spoof_port": ip   right id, right name, from another source port
  "wrong_name": ip   right id, another question name, from the right port
  "wrong_type": ip   right id, right name, an A query answered with an AAAA record (ip is v6)
  "wrong_id": ip     id + 1, right name
  "garbage": kind    "short" (5 bytes), "loop" (answer owner is a self-pointing compression pointer),
                     "ancount" (header claims 200 answers, carries 1), "qd0" (no question),
                     "qd2" (two questions), "rdlen" (A record with rdlength 64)
  "many_a": N        the honest answer carries N A records 10.77.x.y (oversize over UDP)
  "flood": N         N unsolicited replies with random ids (never the query's), right name, address 10.6.6.6
  "srv": [[prio, weight, port, target]...]  SRV answer (qtype SRV or ANY)
  "srv_ar": true     with an additional A/AAAA record per target, from the target's own "a"/"aaaa"
  "extra_ar": {name: ip}  additional A records for names that are no target (hostile)
Unknown names: NXDOMAIN. One log line per query: t qtype qname id proto edns=size sport=port.
"""
import json, os, random, socket, struct, sys, threading, time

T0 = time.time()
port, zone_path, log_path = int(sys.argv[1]), sys.argv[2], sys.argv[3]
logf = open(log_path, "a", buffering=1)
lock = threading.Lock()
QT = {1: "A", 28: "AAAA", 33: "SRV", 5: "CNAME", 255: "ANY"}

def log(s):
    with lock:
        logf.write("%.2f %s\n" % (time.time() - T0, s))

def zone():
    try:
        with open(zone_path) as f:
            return json.load(f)
    except Exception as e:
        log("zone-error %s" % e)
        return {}

def read_name(buf, off):
    labels = []
    while True:
        l = buf[off]; off += 1
        if l == 0:
            break
        if l & 0xC0:
            raise ValueError("compression in question")
        labels.append(buf[off:off + l].decode()); off += l
    return ".".join(labels), off

def enc_name(name):
    out = b""
    for lab in name.rstrip(".").split("."):
        if lab:
            out += bytes([len(lab)]) + lab.encode()
    return out + b"\x00"

def rr(owner, rtype, ttl, rdata):
    return owner + struct.pack("!HHIH", rtype, 1, ttl, len(rdata)) + rdata

def a_rr(ip, ttl=60, owner=b"\xc0\x0c"):
    if ":" in ip:
        return rr(owner, 28, ttl, socket.inet_pton(socket.AF_INET6, ip))
    return rr(owner, 1, ttl, socket.inet_pton(socket.AF_INET, ip))

def reply(qid, question, answers, rcode=0, tc=0, qd=1, an=None, extra=b"", ar=()):
    hdr = struct.pack("!HHHHHH", qid, 0x8180 | tc | rcode, qd, len(answers) if an is None else an, 0, len(ar))
    return hdr + question + b"".join(answers) + extra + b"".join(ar)

def srv_rr(prio, weight, port, target, ttl, owner):
    return rr(owner, 33, ttl, struct.pack("!HHH", prio, weight, port) + enc_name(target))

def parse(req):
    qid = struct.unpack("!H", req[:2])[0]
    qname, off = read_name(req, 12)
    qtype = struct.unpack("!H", req[off:off + 2])[0]
    end = off + 4
    edns = "-"
    if struct.unpack("!H", req[10:12])[0]:
        try:
            if req[end] == 0 and struct.unpack("!H", req[end + 1:end + 3])[0] == 41:
                edns = str(struct.unpack("!H", req[end + 3:end + 5])[0])
        except Exception:
            edns = "?"
    return qid, qname, qtype, req[12:end], edns

def hostile(spec, qid, qname, qtype, question):
    """Replies sent before the honest one: list of (bytes, from_other_port)."""
    out = []
    if spec.get("spoof_port"):
        out.append((reply(qid, question, [a_rr(spec["spoof_port"])]), True))
    if spec.get("wrong_name"):
        q2 = enc_name("evil." + qname) + question[-4:]
        out.append((reply(qid, q2, [a_rr(spec["wrong_name"])]), False))
    if spec.get("wrong_type") and qtype == 1:
        out.append((reply(qid, question, [a_rr(spec["wrong_type"])]), False))
    if spec.get("wrong_id"):
        out.append((reply((qid + 1) & 0xFFFF, question, [a_rr(spec["wrong_id"])]), False))
    g = spec.get("garbage")
    if g == "short":
        out.append((struct.pack("!HHB", qid, 0x8180, 1), False))
    elif g == "loop":
        # owner name = pointer to itself (offset of the answer)
        p = 12 + len(question)
        out.append((reply(qid, question, [rr(struct.pack("!H", 0xC000 | p), 1, 60, b"\x0a\x06\x06\x06")]), False))
    elif g == "ancount":
        out.append((reply(qid, question, [a_rr("10.6.6.6")], an=200), False))
    elif g == "qd0":
        out.append((struct.pack("!HHHHHH", qid, 0x8180, 0, 1, 0, 0) + a_rr("10.6.6.6", owner=enc_name(qname)), False))
    elif g == "qd2":
        out.append((reply(qid, question + question, [a_rr("10.6.6.6")], qd=2), False))
    elif g == "rdlen":
        out.append((reply(qid, question, [rr(b"\xc0\x0c", 1, 60, b"\x0a\x06\x06\x06" + b"\x00" * 60)]), False))
    for _ in range(spec.get("flood", 0)):
        # never the query's own id: an accepted flood reply is then a defect, not a lucky guess
        out.append((reply((qid + random.randrange(1, 65536)) & 0xFFFF, question, [a_rr("10.6.6.6")]), False))
    return out

def honest(spec, z, qid, qtype, question, proto):
    if spec.get("silent") or spec.get("only"):
        return None
    rcode = {"nx": 3, "refused": 5, "servfail": 2, None: 0}[spec.get("rcode")]
    answers, ar = [], []
    ttl = spec.get("ttl", 60)
    if rcode == 0 and not spec.get("nodata"):
        owner, tgt = b"\xc0\x0c", spec
        if spec.get("cname"):
            answers.append(rr(owner, 5, ttl, enc_name(spec["cname"])))
            owner = enc_name(spec["cname"])
            tgt = z.get(spec["cname"], {})
        if qtype in (1, 255):
            answers += [a_rr(ip, ttl, owner) for ip in tgt.get("a", [])]
            n = tgt.get("many_a", 0)
            answers += [a_rr("10.77.%d.%d" % (i // 250, i % 250 + 1), ttl, owner) for i in range(n)]
        if qtype in (28, 255):
            answers += [a_rr(ip, ttl, owner) for ip in tgt.get("aaaa", [])]
        if qtype in (33, 255):
            for prio, weight, sport, target in tgt.get("srv", []):
                answers.append(srv_rr(prio, weight, sport, target, ttl, owner))
                if tgt.get("srv_ar"):
                    t = z.get(target, {})
                    ar += [a_rr(ip, ttl, enc_name(target)) for ip in t.get("a", []) + t.get("aaaa", [])]
            ar += [a_rr(ip, ttl, enc_name(n)) for n, ip in tgt.get("extra_ar", {}).items()]
    tc = 0
    if proto == "udp" and spec.get("tc_udp"):
        tc, answers, ar = 0x0200, [], []
    elif proto == "udp" and spec.get("tc_keep"):
        tc = 0x0200
    return reply(qid, question, answers, rcode, tc, ar=ar)

def handle(req, proto, sport, send, send_other):
    qid, qname, qtype, question, edns = parse(req)
    log("%s %s id=%d %s edns=%s sport=%d" % (QT.get(qtype, qtype), qname, qid, proto, edns, sport))
    z = zone()
    spec = z.get(qname.lower(), {"rcode": "nx"})
    if spec.get("delay"):
        time.sleep(spec["delay"])
    if proto == "udp":
        for pkt, other in hostile(spec, qid, qname, qtype, question):
            (send_other if other else send)(pkt)
    r = honest(spec, z, qid, qtype, question, proto)
    if r is not None:
        send(r)

def udp():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", port))
    other = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    other.bind(("127.0.0.1", 0))
    while True:
        d, a = s.recvfrom(65535)
        try:
            handle(d, "udp", a[1], lambda p: s.sendto(p, a), lambda p: other.sendto(p, a))
        except Exception as e:
            log("bad-query %r" % e)

def tcp_conn(c, a):
    with c:
        while True:
            h = c.recv(2)
            if len(h) < 2:
                return
            n = struct.unpack("!H", h)[0]
            d = b""
            while len(d) < n:
                p = c.recv(n - len(d))
                if not p:
                    return
                d += p
            try:
                handle(d, "tcp", a[1], lambda p: c.sendall(struct.pack("!H", len(p)) + p), None)
            except Exception as e:
                log("bad-query %r" % e); return

def tcp():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port)); s.listen(8)
    while True:
        c, a = s.accept()
        threading.Thread(target=tcp_conn, args=(c, a), daemon=True).start()

threading.Thread(target=tcp, daemon=True).start()
log("start port=%d pid=%d" % (port, os.getpid()))
udp()
