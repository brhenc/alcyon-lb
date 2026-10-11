#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
"""HTTP/2 multiplexing traffic for the soak, standard library only (raw frames, HPACK literals).

  h2mux.py DURATION_S LOGDIR NAME PORT

Over TLS with ALPN h2 to 127.0.0.1:PORT (SNI blog.local), runs three threads until DURATION:
  mux   new connection, 10 rounds of 20 concurrent streams (one round per second), then GOAWAY:
        8 x GET /p (small, default backend), 4 x GET /big/65536, 2 x GET /big/262144
        cancelled with RST_STREAM(CANCEL) after their first DATA, 4 x POST /up 32 KB,
        2 x POST /up 256 KB (sent under the peer's flow control)
  slow  x2, connection with SETTINGS_INITIAL_WINDOW_SIZE 4096 and 4 x GET /big/1048576,
        stream windows opened by 4 KB per stream every 100 ms (about 40 KB/s per stream),
        3 rounds per connection
Every 10 s one line to LOGDIR/h2mux-NAME.log:
  ts ok= bad= cancel= rst= goaway= err= conns= maxlat= [first bad reasons]
"""
import os, socket, ssl, struct, sys, threading, time

DUR, LOGDIR, NAME, PORT = int(sys.argv[1]), sys.argv[2], sys.argv[3], int(sys.argv[4])
END = time.time() + DUR
ST = {"ok": 0, "bad": 0, "cancel": 0, "rst": 0, "goaway": 0, "err": 0, "conns": 0, "maxlat": 0.0}
REASONS = []
LOCK = threading.Lock()
STATIC_STATUS = {8: "200", 9: "204", 10: "206", 11: "304", 12: "400", 13: "404", 14: "500"}


def bump(k, v=1):
    with LOCK:
        ST[k] += v


def bad(reason):
    with LOCK:
        ST["bad"] += 1
        if len(REASONS) < 5:
            REASONS.append(reason)


def hint(n, prefix_bits, flags=0):
    mx = (1 << prefix_bits) - 1
    if n < mx:
        return bytes([flags | n])
    out = [flags | mx]
    n -= mx
    while n >= 128:
        out.append((n & 127) | 128)
        n >>= 7
    out.append(n)
    return bytes(out)


def hpack(headers):
    b = b""
    for k, v in headers:  # literal, never indexed, new name, no Huffman
        b += b"\x10" + hint(len(k), 7) + k + hint(len(v), 7) + v
    return b


def status_of(block):
    if not block:
        return "?"
    c = block[0]
    if c & 0x80:
        return STATIC_STATUS.get(c & 0x7F, "idx%d" % (c & 0x7F))
    # literal with indexed name :status (8..14), 4-bit (0x0X/0x1X) or 6-bit (0x4X) prefix
    if c & 0xC0 == 0x40:
        idx, rest = c & 0x3F, block[1:]
    else:
        idx, rest = c & 0x0F, block[1:]
    if idx in range(8, 15) and rest:
        ln, huff = rest[0] & 0x7F, rest[0] & 0x80
        val = rest[1:1 + ln]
        return "huff" if huff else val.decode(errors="replace")
    return "lit?"


class Conn:
    def __init__(self, iws=65535):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["h2"])
        raw = socket.create_connection(("127.0.0.1", PORT), timeout=10)
        self.s = ctx.wrap_socket(raw, server_hostname="blog.local")
        if self.s.selected_alpn_protocol() != "h2":
            raise RuntimeError("alpn %r" % self.s.selected_alpn_protocol())
        bump("conns")
        self.buf = b""
        self.peer_iws = 65535
        self.send_conn = 65535
        self.send_win = {}
        self.next_id = 1
        self.goaway = False
        self.s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
                       + self.frame(4, 0, 0, struct.pack(">HI", 2, 0) + struct.pack(">HI", 4, iws)))

    @staticmethod
    def frame(t, fl, sid, p=b""):
        return struct.pack(">I", len(p))[1:] + bytes([t, fl]) + struct.pack(">I", sid) + p

    def send(self, t, fl, sid, p=b""):
        self.s.sendall(self.frame(t, fl, sid, p))

    def recv_frame(self, timeout):
        self.s.settimeout(timeout)
        try:
            while len(self.buf) < 9 or len(self.buf) < 9 + int.from_bytes(self.buf[:3], "big"):
                d = self.s.recv(65536)
                if not d:
                    raise EOFError("closed by peer")
                self.buf += d
        except (socket.timeout, ssl.SSLWantReadError):
            return None
        n = int.from_bytes(self.buf[:3], "big")
        t, fl = self.buf[3], self.buf[4]
        sid = int.from_bytes(self.buf[5:9], "big") & 0x7FFFFFFF
        p = self.buf[9:9 + n]
        self.buf = self.buf[9 + n:]
        if t == 4 and not fl & 1:  # SETTINGS
            for i in range(0, len(p) - 5, 6):
                k, v = struct.unpack(">HI", p[i:i + 6])
                if k == 4:
                    delta = v - self.peer_iws
                    self.peer_iws = v
                    for s in self.send_win:
                        self.send_win[s] += delta
            self.send(4, 1, 0)
        elif t == 6 and not fl & 1:  # PING
            self.send(6, 1, 0, p)
        elif t == 8:  # WINDOW_UPDATE
            inc = int.from_bytes(p[:4], "big") & 0x7FFFFFFF
            if sid == 0:
                self.send_conn += inc
            elif sid in self.send_win:
                self.send_win[sid] += inc
        elif t == 7:
            self.goaway = True
            bump("goaway")
        return t, fl, sid, p

    def open(self, method, path, body_len=0):
        sid = self.next_id
        self.next_id += 2
        h = [(b":method", method), (b":scheme", b"https"), (b":authority", b"blog.local"), (b":path", path)]
        if body_len:
            h.append((b"content-length", str(body_len).encode()))
        self.send_win[sid] = self.peer_iws
        self.send(1, 0x4 | (0 if body_len else 0x1), sid, hpack(h))
        return sid

    def close(self):
        try:
            self.send(7, 0, 0, struct.pack(">II", self.next_id - 2 if self.next_id > 1 else 0, 0))
            self.s.close()
        except OSError:
            pass


def run_round(c, specs, slow=False, deadline=40):
    """specs: list of dicts kind/method/path/body/expect/cancel. Returns when all streams end."""
    st = {}
    for sp in specs:
        sid = c.open(sp["method"], sp["path"], sp.get("body", 0))
        st[sid] = dict(sp, t0=time.time(), status=None, got=0, data=b"", done=False, left=sp.get("body", 0))
    t_end = time.time() + deadline
    last_grant = time.time()
    while not all(s["done"] for s in st.values()):
        if time.time() > t_end:
            for sid, s in st.items():
                if not s["done"]:
                    bad("timeout %s %s got=%d status=%s" % (s["method"].decode(), s["path"].decode(), s["got"], s["status"]))
                    s["done"] = True
            return
        if c.goaway and c.next_id > 1:
            pass
        # uploads under the peer's windows
        blocked = False
        for sid, s in st.items():
            while s["left"] and not s["done"]:
                n = min(16384, s["left"], c.send_conn, c.send_win.get(sid, 0))
                if n <= 0:
                    blocked = True
                    break
                s["left"] -= n
                c.send_conn -= n
                c.send_win[sid] -= n
                c.send(0, 0x1 if not s["left"] else 0, sid, b"u" * n)
        if slow and time.time() - last_grant >= 0.1:
            last_grant = time.time()
            for sid, s in st.items():
                if not s["done"]:
                    c.send(8, 0, sid, struct.pack(">I", 4096))
        f = c.recv_frame(0.05 if (blocked or slow) else 0.5)
        if f is None:
            continue
        t, fl, sid, p = f
        s = st.get(sid)
        if t == 0:
            n = len(p)
            if n:
                c.send(8, 0, 0, struct.pack(">I", n))  # connection window: always at once
                if not slow and s and not s["done"] and not fl & 1:
                    c.send(8, 0, sid, struct.pack(">I", n))
            if s and not s["done"]:
                if fl & 0x8:  # padded
                    p = p[1:len(p) - p[0]]
                s["got"] += len(p)
                if s["method"] == b"POST":
                    s["data"] += p
                if s.get("cancel"):
                    c.send(3, 0, sid, struct.pack(">I", 8))
                    s["done"] = True
                    bump("cancel")
                    continue
                if fl & 1:
                    finish(s)
        elif t == 1 and s and not s["done"]:
            blk = p
            if fl & 0x8:
                blk = blk[1:len(blk) - blk[0]]
            if fl & 0x20:
                blk = blk[5:]
            if s["status"] is None:
                s["status"] = status_of(blk)
            if fl & 1:
                finish(s)
        elif t == 3 and s and not s["done"]:
            s["done"] = True
            bump("rst")
            bad("rst %s %s code=%d got=%d" % (s["method"].decode(), s["path"].decode(),
                                              int.from_bytes(p[:4], "big"), s["got"]))


def finish(s):
    s["done"] = True
    lat = time.time() - s["t0"]
    with LOCK:
        ST["maxlat"] = max(ST["maxlat"], lat)
    ok = s["status"] == "200"
    if ok and "expect" in s:
        ok = s["got"] == s["expect"]
    if ok and s["method"] == b"POST":
        ok = s["data"] == b"got %d" % s["body"]
    if ok:
        bump("ok")
    else:
        bad("%s %s status=%s got=%d data=%r" % (s["method"].decode(), s["path"].decode(), s["status"], s["got"], s["data"][:20]))


def mux_specs(r):
    sp = [dict(method=b"GET", path=b"/p?r=%d&i=%d" % (r, i)) for i in range(8)]
    sp += [dict(method=b"GET", path=b"/big/65536", expect=65536) for _ in range(4)]
    sp += [dict(method=b"GET", path=b"/big/262144", cancel=True) for _ in range(2)]
    sp += [dict(method=b"POST", path=b"/up", body=32768) for _ in range(4)]
    sp += [dict(method=b"POST", path=b"/up", body=262144) for _ in range(2)]
    return sp


def worker(kind):
    while time.time() < END:
        c = None
        try:
            if kind == "mux":
                c = Conn()
                for r in range(10):
                    if time.time() >= END or c.goaway:
                        break
                    t0 = time.time()
                    run_round(c, mux_specs(r))
                    time.sleep(max(0.0, 1.0 - (time.time() - t0)))  # one round per second
            else:
                c = Conn(iws=4096)
                for r in range(3):
                    if time.time() >= END or c.goaway:
                        break
                    run_round(c, [dict(method=b"GET", path=b"/big/1048576", expect=1048576) for _ in range(4)],
                              slow=True, deadline=90)
        except Exception as e:  # noqa: BLE001 - every failure is counted and logged
            bump("err")
            with LOCK:
                if len(REASONS) < 5:
                    REASONS.append("%s %s: %s" % (kind, type(e).__name__, e))
            time.sleep(1)
        finally:
            if c:
                c.close()
        time.sleep(0.5)


def logger():
    path = os.path.join(LOGDIR, "h2mux-%s.log" % NAME)
    while time.time() < END + 5:
        time.sleep(10)
        with LOCK:
            line = "%d %s %s\n" % (time.time(), " ".join(
                "%s=%s" % (k, ("%.2f" % v) if k == "maxlat" else v) for k, v in ST.items()),
                "| " + " ; ".join(REASONS) if REASONS else "")
            for k in ST:
                ST[k] = 0 if k != "maxlat" else 0.0
            REASONS.clear()
        with open(path, "a") as f:
            f.write(line)


ths = [threading.Thread(target=worker, args=(k,), daemon=True) for k in ("mux", "slow", "slow")]
lg = threading.Thread(target=logger, daemon=True)
for t in ths + [lg]:
    t.start()
for t in ths:
    t.join()
lg.join()
