#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
"""T313 rx budget, worst-case shape: per h2 connection one POST stream pushes up to 88 x 16 KB DATA
that the backend never consumes (the backend is a listener whose accept queue is full, so the proxy's
connect hangs for timeout connect), then 99 more POST streams send one 16 KB frame each.  Flow control
is respected: a frame goes out only when both the connection and the stream window allow it, so the
proxy decides how much it buffers.  N connections are built one after the other and all kept open.
Lab only (127.0.0.1).
    h2rxbudget.py <h2c port> <conns> label=binary ...
Prints per label: bytes the proxy accepted on the big stream and in total per connection, how long
the windows stalled, proxy RSS idle -> all connections up -> after close, fds, and RSS per connection."""
import os, select, socket, struct, sys, time
sys.path.insert(0, "/root/battery"); sys.path.insert(0, "/root/battery/repro")
from clients import PREFACE, settings, frame, hpack_lit
from labproxy import start_proxy, stop, fds, rss_cpu

PORT, N = int(sys.argv[1]), int(sys.argv[2])
SPECS = [s.split("=", 1) for s in sys.argv[3:]]
BIG_FRAMES, SMALL_STREAMS, FRAME = 88, 99, 16384
BACKEND = 8891
STALL = float(os.environ.get("STALL", "2"))  # max seconds to wait for a window update on the big stream
CFG = f"""global
    nbthread 4
    maxconn 2000
defaults
    mode http
    timeout connect 60s
    timeout client 60s
    timeout server 60s
    timeout http-request 60s
frontend f
    bind 127.0.0.1:{PORT} proto h2
    default_backend b
backend b
    server s1 127.0.0.1:{BACKEND}
"""

def hung_backend():
    """A listener nobody accepts from, with its accept queue already full: connects to it hang."""
    ls = socket.socket(); ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("127.0.0.1", BACKEND)); ls.listen(0)
    fillers = []
    for _ in range(4):
        try:
            c = socket.create_connection(("127.0.0.1", BACKEND), timeout=0.5); fillers.append(c)
        except OSError:
            break
    return ls, fillers

def post_headers(sid):
    return frame(1, 0x4, sid, b"\x83\x86\x84\x41" + hpack_lit(b"battery"))

class Conn:
    def __init__(self):
        self.s = socket.create_connection(("127.0.0.1", PORT)); self.s.settimeout(0.05)
        self.s.sendall(PREFACE + settings([(4, 1 << 24)]))  # our own rx window is wide; irrelevant here
        self.conn_win = 65535; self.init_win = 65535; self.stream_win = {}; self.buf = b""
        self.rst = {}; self.goaway = None; self.stall = 0.0; self.accepted = {}; self.stalled_out = False
        self.pump(0.3)

    def send(self, b):
        """sendall; a send timeout means the proxy stopped reading the socket (TCP backpressure), end the conn."""
        try: self.s.sendall(b)
        except socket.timeout: self.goaway = self.goaway or "TCPBLOCK"
        except OSError: self.goaway = self.goaway or "ERR"

    def pump(self, secs):
        end = time.time() + secs; first = True
        while first or time.time() < end:  # at least one non-blocking poll, so pump(0) drains what is there
            first = False
            try:
                if select.select([self.s], [], [], max(0.0, end - time.time()))[0]:
                    d = self.s.recv(65536)
                    if not d: self.goaway = self.goaway or "EOF"; return
                    self.buf += d
            except socket.timeout: pass
            except OSError: self.goaway = self.goaway or "ERR"; return
            while len(self.buf) >= 9:
                ln = int.from_bytes(self.buf[:3], "big"); t = self.buf[3]; fl = self.buf[4]; sid = int.from_bytes(self.buf[5:9], "big") & 0x7fffffff
                if len(self.buf) < 9 + ln: break
                pl = self.buf[9:9 + ln]; self.buf = self.buf[9 + ln:]
                if t == 4 and sid == 0:
                    for i in range(0, len(pl) - 5, 6):
                        k, v = struct.unpack(">HI", pl[i:i + 6])
                        if k == 4: self.init_win = v
                    if not fl & 0x1: self.send(frame(4, 0x1, 0))
                elif t == 8:
                    inc = int.from_bytes(pl[:4], "big") & 0x7fffffff
                    if sid == 0: self.conn_win += inc
                    else: self.stream_win[sid] = self.stream_win.get(sid, self.init_win) + inc
                elif t == 3: self.rst[sid] = int.from_bytes(pl[:4], "big")
                elif t == 7: self.goaway = int.from_bytes(pl[4:8], "big")
                elif t == 6 and not fl & 0x1: self.send(frame(6, 0x1, 0, pl))

    def send_data(self, sid, nframes, max_stall=STALL):
        """Send up to nframes DATA frames of FRAME bytes on sid, each only when the windows allow."""
        self.stream_win.setdefault(sid, self.init_win); sent = 0
        while sent < nframes and self.goaway is None and sid not in self.rst:
            if self.conn_win >= FRAME and self.stream_win[sid] >= FRAME:
                self.send(frame(0, 0, sid, b"x" * FRAME)); self.conn_win -= FRAME; self.stream_win[sid] -= FRAME
                if self.goaway is not None: break
                sent += 1; self.accepted[sid] = self.accepted.get(sid, 0) + FRAME; self.pump(0.0)
            else:
                t0 = time.time(); w0 = (self.conn_win, self.stream_win[sid])
                while time.time() - t0 < max_stall and (self.conn_win, self.stream_win[sid]) == w0 and self.goaway is None:
                    self.pump(0.05)
                self.stall += time.time() - t0
                if (self.conn_win, self.stream_win[sid]) == w0:
                    if self.conn_win < FRAME: self.stalled_out = True  # the connection window is dead, do not wait again
                    break
        return sent

    def build(self):
        self.send(post_headers(1)); self.pump(0.05)
        big = self.send_data(1, BIG_FRAMES)
        small = 0
        for k in range(SMALL_STREAMS):
            sid = 3 + 2 * k
            if self.goaway is not None: break
            self.send(post_headers(sid)); self.pump(0.0)
            small += self.send_data(sid, 1, max_stall=0.0 if self.stalled_out else 0.5)
        self.pump(0.2)
        return big, small

def one(label, binary):
    p = start_proxy(binary, CFG, PORT, f"rxbudget-{label}")
    if not p: return
    conns = []
    try:
        time.sleep(0.5); r_idle, f_idle = rss_cpu(p.pid)[0], fds(p.pid)
        t0 = time.time(); bigs = []; smalls = []; stalls = []; rsts = 0; goaways = 0; ends = {}
        for i in range(N):
            c = Conn(); big, small = c.build(); conns.append(c)
            bigs.append(big); smalls.append(small); stalls.append(round(c.stall, 1)); rsts += len(c.rst); goaways += c.goaway is not None
            if c.goaway is not None: ends[str(c.goaway)] = ends.get(str(c.goaway), 0) + 1
        time.sleep(1.0)
        r_up, f_up = rss_cpu(p.pid)[0], fds(p.pid)
        tot = [(b * FRAME + s_ * FRAME) / 1048576 for b, s_ in zip(bigs, smalls)]
        print(f"{label:9s} {N} conns built in {time.time() - t0:.1f} s: big stream accepted {min(bigs)}-{max(bigs)} of {BIG_FRAMES} frames, "
              f"small streams accepted {min(smalls)}-{max(smalls)} of {SMALL_STREAMS}; accepted per conn {min(tot):.2f}-{max(tot):.2f} MB; "
              f"window stalls per conn {min(stalls)}-{max(stalls)} s; RST_STREAM {rsts}, GOAWAY/closed {goaways} {ends if ends else ''}; init window {conns[0].init_win}")
        print(f"          RSS idle {r_idle} -> up {r_up} MB = {(r_up - r_idle) * 1024 / N:.0f} KB per connection; fds {f_idle} -> {f_up}", flush=True)
        for c in conns:
            try: c.s.close()
            except OSError: pass
        conns = []
        time.sleep(2.0)
        print(f"          after close +2 s: RSS {rss_cpu(p.pid)[0]} MB, fds {fds(p.pid)}, alive {p.poll() is None}", flush=True)
    finally:
        for c in conns:
            try: c.s.close()
            except OSError: pass
        stop(p)

ls, fillers = hung_backend()
try:
    for label, binary in SPECS: one(label, binary)
finally:
    for c in fillers: c.close()
    ls.close()
