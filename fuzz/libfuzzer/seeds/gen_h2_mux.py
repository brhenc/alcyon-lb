#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
"""h2_mux seeds: one selector byte, then frames after the client preface."""
import hashlib, os, random, struct, sys
out = sys.argv[1]
random.seed(1011)
def fr(t, fl, sid, pl=b""): return struct.pack(">I", len(pl))[1:] + bytes([t, fl]) + struct.pack(">I", sid) + pl
def settings(*kv): return fr(4, 0, 0, b"".join(struct.pack(">HI", k, v) for k, v in kv))
ACK = fr(4, 1, 0)
def lit(n, v, idx=False):  # literal without (0x00) or with (0x40) indexing, new name
    return (b"\x40" if idx else b"\x00") + bytes([len(n)]) + n + bytes([len(v)]) + v
def req(method=b"GET", path=b"/", auth=b"example.com", extra=(), idx=False):
    h = b""
    st = {b"GET": b"\x82", b"POST": b"\x83"}
    h += st.get(method, lit(b":method", method))
    h += b"\x86"  # :scheme http
    h += b"\x84" if path == b"/" else lit(b":path", path)
    h += lit(b":authority", auth, idx)
    for n, v in extra: h += lit(n, v, idx)
    return h
H, D, PRIO, RST, SET, PUSH, PING, GOAWAY, WU, CONT = range(10)
ES, EH, PAD, PRI = 1, 4, 8, 0x20
seeds = {}
def add(name, body, sels=(0x3f, 0x00, 0x80, 0x01)):
    for s in sels: seeds[f"{name}-{s:02x}"] = bytes([s]) + body
pre = settings((3, 100), (4, 65535), (6, 16384)) + ACK
add("get", pre + fr(H, EH | ES, 1, req()))
add("get-indexed", pre + fr(H, EH | ES, 1, req(idx=True)) + fr(H, EH | ES, 3, b"\x82\x86\x84\xbe"))
add("post-body", pre + fr(H, EH, 1, req(b"POST", b"/upload", extra=[(b"content-length", b"11")])) + fr(D, 0, 1, b"hello ") + fr(D, ES, 1, b"world"))
add("post-trailers", pre + fr(H, EH, 1, req(b"POST", b"/t", extra=[(b"te", b"trailers")])) + fr(D, 0, 1, b"x" * 100) + fr(H, EH | ES, 1, lit(b"x-trailer", b"1")))
add("continuation", pre + fr(H, 0, 1, req()[:5]) + fr(CONT, 0, 1, req()[5:9]) + fr(CONT, EH | ES, 1, req()[9:]))
add("continuation-long", pre + fr(H, 0, 1, req()) + b"".join(fr(CONT, 0, 1, lit(b"x-a%d" % i, b"v" * 50)) for i in range(40)) + fr(CONT, EH | ES, 1, b""))
add("padded", pre + fr(H, EH | ES | PAD, 1, b"\x05" + req() + b"\0" * 5) + fr(H, EH | PAD, 3, b"\x00" + req(b"POST")) + fr(D, ES | PAD, 3, b"\x03abc\0\0\0"))
add("priority-flag", pre + fr(H, EH | ES | PRI, 1, struct.pack(">IB", 0, 15) + req()) + fr(PRIO, 0, 3, struct.pack(">IB", 1, 200)))
many = b"".join(fr(H, EH | ES, 1 + 2 * i, req(path=b"/p%d" % i)) for i in range(120))
add("many-streams", pre + many)
held = b"".join(fr(H, EH, 1 + 2 * i, req(b"POST")) for i in range(110))
add("held-posts", pre + held)
myr = b"".join(fr(H, EH | ES, 1 + 2 * i, req(path=b"/r%d" % i)) + fr(RST, 0, 1 + 2 * i, struct.pack(">I", 8)) for i in range(150))
add("madeyoureset", pre + myr)
myr2 = b"".join(fr(H, EH, 1 + 2 * i, req(b"POST")) + fr(WU, 0, 1 + 2 * i, struct.pack(">I", 0)) for i in range(60))
add("madeyoureset-wu0", pre + myr2)
add("rst-idle", pre + fr(RST, 0, 7, struct.pack(">I", 0)) + fr(H, EH | ES, 5, req()))
add("window", pre + fr(WU, 0, 0, struct.pack(">I", 0x7fffffff)) + fr(WU, 0, 0, struct.pack(">I", 1)) + fr(H, EH | ES, 1, req()) + fr(WU, 0, 1, struct.pack(">I", 1000)))
add("window-small", settings((4, 1), (5, 16384)) + ACK + fr(H, EH | ES, 1, req()) + b"".join(fr(WU, 0, 1, struct.pack(">I", 1)) for _ in range(30)))
add("settings-change", pre + fr(H, EH | ES, 1, req()) + settings((4, 0)) + settings((4, 2**31 - 1)) + settings((1, 0)) + settings((2, 0), (8, 1)))
add("ping-goaway", pre + fr(PING, 0, 0, b"12345678") + fr(PING, 1, 0, b"abcdefgh") + fr(H, EH | ES, 1, req()) + fr(GOAWAY, 0, 0, struct.pack(">II", 1, 0) + b"bye"))
add("table-size", pre + fr(H, EH | ES, 1, b"\x20" + req(idx=True)) + fr(H, EH | ES, 3, b"\x3f\xe1\x1f" + req(idx=True)) + fr(H, EH | ES, 5, b"\xbe\x82"))
add("big-header", pre + fr(H, EH | ES, 1, req(extra=[(b"cookie", b"a=" + b"b" * 120)] * 60)))
add("unknown-frames", pre + fr(0x20, 0xff, 0, b"zz") + fr(H, EH | ES, 1, req()) + fr(0xfa, 0, 1, b"x" * 10))
add("push-from-client", pre + fr(PUSH, EH, 1, struct.pack(">I", 2) + req()))
add("even-stream", pre + fr(H, EH | ES, 2, req()))
add("decreasing-ids", pre + fr(H, EH | ES, 5, req()) + fr(H, EH | ES, 3, req()))
add("data-closed", pre + fr(H, EH | ES, 1, req()) + fr(D, 0, 1, b"late"))
add("content-length-mismatch", pre + fr(H, EH, 1, req(b"POST", extra=[(b"content-length", b"3")])) + fr(D, ES, 1, b"toolong"))
add("connect", pre + fr(H, EH, 1, b"\x00\x07:method\x07CONNECT" + lit(b":authority", b"h:443")) + fr(D, 0, 1, b"tunnel"))
add("ext-connect", settings((8, 1)) + ACK + fr(H, EH, 1, b"\x00\x07:method\x07CONNECT" + lit(b":protocol", b"websocket") + b"\x86" + lit(b":path", b"/ws") + lit(b":authority", b"a")))
add("uppercase-header", pre + fr(H, EH | ES, 1, req(extra=[(b"X-Upper", b"1")])))
add("conn-specific", pre + fr(H, EH | ES, 1, req(extra=[(b"connection", b"keep-alive"), (b"transfer-encoding", b"chunked")])))
add("rapid-settings", pre + b"".join(settings((1, i)) for i in range(50)))
add("ping-flood", pre + b"".join(fr(PING, 0, 0, struct.pack(">Q", i)) for i in range(200)))
add("empty-data-flood", pre + fr(H, EH, 1, req(b"POST")) + b"".join(fr(D, 0, 1) for _ in range(200)))
add("continuation-flood", pre + fr(H, 0, 1, req()) + b"".join(fr(CONT, 0, 1, b"") for _ in range(300)))
for k in range(40):  # random mixes of valid frames
    body = pre
    for _ in range(random.randint(3, 40)):
        sid = random.choice([1, 3, 5, 7, 9, 11])
        t = random.choice([H, H, D, RST, WU, PRIO, PING, SET, CONT])
        if t == H: body += fr(H, EH | random.choice([0, ES]), sid, req(random.choice([b"GET", b"POST"]), b"/m%d" % k))
        elif t == D: body += fr(D, random.choice([0, ES]), sid, os.urandom(random.randint(0, 64)))
        elif t == RST: body += fr(RST, 0, sid, struct.pack(">I", random.choice([0, 1, 7, 8])))
        elif t == WU: body += fr(WU, 0, random.choice([0, sid]), struct.pack(">I", random.choice([1, 100, 65535, 2**31 - 1])))
        elif t == PRIO: body += fr(PRIO, 0, sid, struct.pack(">IB", random.choice([0, 1, sid]), 16))
        elif t == PING: body += fr(PING, 0, 0, os.urandom(8))
        elif t == SET: body += settings((random.choice([1, 3, 4, 5, 6]), random.choice([0, 1, 100, 16384, 65535])))
        else: body += fr(CONT, EH, sid, lit(b"x", b"y"))
    add(f"mix{k}", body, sels=(random.randrange(256),))
# T449: fields the HTTP/1 head cannot carry (CR LF in a value, a pseudo-header, a trailer, a
# value split by CONTINUATION, a name with uppercase): each is a stream error.
for k, v in [(b"crlf", b"b\r\nx-injected: 1"), (b"nul", b"b\0e")]:
    add("bad-value-" + k.decode(), pre + fr(H, EH | ES, 1, req(extra=[(b"x-a", v)])))
    add("bad-path-" + k.decode(), pre + fr(H, EH | ES, 1, req(path=b"/" + v)))
    add("bad-trailer-" + k.decode(), pre + fr(H, EH, 1, req(b"POST")) + fr(D, 0, 1, b"abc") + fr(H, EH | ES, 1, lit(b"x-t", v)))
    blk = req(extra=[(b"x-a", v)])
    add("bad-cont-" + k.decode(), pre + fr(H, 0, 1, blk[:-len(v) + 1]) + fr(CONT, EH | ES, 1, blk[-len(v) + 1:]))
add("bad-name-upper", pre + fr(H, EH | ES, 1, req(extra=[(b"X-a", b"1")])))
add("bad-method-space", pre + fr(H, EH | ES, 1, req(b"GE T")))
os.makedirs(out, exist_ok=True)
for name, data in seeds.items():
    open(os.path.join(out, hashlib.sha1(data).hexdigest()), "wb").write(data)
print(len(seeds), "seeds")
