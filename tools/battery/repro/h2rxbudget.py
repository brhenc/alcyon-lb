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
    env STALL=2 (window wait s), HOLD_SECS=0 (keep the attack connections open that long after the build),
    LEGIT=1 (h1 keep-alive client on port+1 at 50 req/s through haterm, and a new-client curl --max-time 3
    every 5 s; counts per phase), CLI=1 (dump `show sess` / `show fd` while held to /tmp/rxb-<label>-*.txt),
    BACKEND_MODE=hung (accept queue full, connects hang) | accept (accepts and drains, never answers) |
    noread (accepts, never reads)
Prints per label: bytes the proxy accepted on the big stream and in total per connection, how long
the windows stalled, proxy RSS idle -> all connections up -> after close, fds, and RSS per connection."""
import os, select, socket, struct, subprocess, sys, threading, time
sys.path.insert(0, "/root/battery"); sys.path.insert(0, "/root/battery/repro")
from clients import PREFACE, settings, frame, hpack_lit
from labproxy import start_haterm, start_proxy, stop, fds, rss_cpu

PORT, N = int(sys.argv[1]), int(sys.argv[2])
SPECS = [s.split("=", 1) for s in sys.argv[3:]]
BIG_FRAMES, SMALL_STREAMS, FRAME = 88, 99, 16384
BACKEND = 8891
STALL = float(os.environ.get("STALL", "2"))  # max seconds to wait for a window update on the big stream
HOLD_SECS = float(os.environ.get("HOLD_SECS", "0")); LEGIT = bool(os.environ.get("LEGIT")); CLI = bool(os.environ.get("CLI"))
BACKEND_MODE = os.environ.get("BACKEND_MODE", "hung"); HATERM = 8893
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
    bind 127.0.0.1:{PORT + 1}
    use_backend slow if {{ path_beg /slow }}
    default_backend b
backend slow
    server s1 127.0.0.1:{BACKEND}
backend b
    server s1 127.0.0.1:{HATERM}
"""
CFG = CFG.replace("global\n", "global\n    stats socket /tmp/rxb-{label}.sock mode 600 level admin\n") if CLI else CFG

def hung_backend():
    """hung: a listener nobody accepts from, with its accept queue already full, so connects hang.
    accept: accepts every connection, drains what arrives, never answers.  noread: accepts, never reads."""
    ls = socket.socket(); ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("127.0.0.1", BACKEND))
    fillers = []
    if BACKEND_MODE != "hung":
        ls.listen(1024)
        def acceptor():
            while True:
                try: c, _ = ls.accept()
                except OSError: return
                fillers.append(c)
                if BACKEND_MODE == "accept":
                    def drain(c):
                        try:
                            while c.recv(65536): pass
                        except OSError: pass
                    threading.Thread(target=drain, args=(c,), daemon=True).start()
        threading.Thread(target=acceptor, daemon=True).start()
        return ls, fillers
    ls.listen(0)
    for _ in range(4):
        try:
            c = socket.create_connection(("127.0.0.1", BACKEND), timeout=0.5); fillers.append(c)
        except OSError:
            break
    return ls, fillers

def post_headers(sid):  # :method POST, :scheme http, :path /slow (literal), :authority battery
    return frame(1, 0x4, sid, b"\x83\x86\x04" + hpack_lit(b"/slow") + b"\x41" + hpack_lit(b"battery"))

class Legit(threading.Thread):
    """h1 keep-alive client on PORT+1, one GET every 20 ms; per phase: ok / 503 / other status / errors, p99."""
    def __init__(self): super().__init__(daemon=True); self.rows = []; self.run_ = True; self.phase = "idle"
    def run(self):
        s = None
        while self.run_:
            t0 = time.time()
            try:
                if s is None: s = socket.create_connection(("127.0.0.1", PORT + 1)); s.settimeout(3)
                s.sendall(b"GET /?s=1k HTTP/1.1\r\nHost: lab\r\n\r\n"); got = b""
                while b"\r\n\r\n" not in got: got += s.recv(65536)
                head, body = got.split(b"\r\n\r\n", 1); code = head.split()[1].decode()
                cl = int([l for l in head.split(b"\r\n") if l.lower().startswith(b"content-length:")][0].split(b":")[1])
                while len(body) < cl: body += s.recv(65536)
                if b"connection: close" in head.lower(): s.close(); s = None
                self.rows.append((self.phase, code, (time.time() - t0) * 1000))
            except OSError as e:
                self.rows.append((self.phase, "err", (time.time() - t0) * 1000))
                try: s.close()
                except Exception: pass
                s = None; time.sleep(0.2)
            time.sleep(0.02)
    def summary(self, phase):
        r = [x for x in self.rows if x[0] == phase]
        if not r: return f"{phase}: no samples"
        lat = sorted(x[2] for x in r); codes = {}
        for x in r: codes[x[1]] = codes.get(x[1], 0) + 1
        return f"{phase}: n={len(r)} {codes} p99 {lat[min(len(lat) - 1, int(len(lat) * .99))]:.1f} ms max {lat[-1]:.0f} ms"

class NewClient(threading.Thread):
    """curl --max-time 3 to the h1 port every 5 s; records (phase, http code or curl rc)."""
    def __init__(self): super().__init__(daemon=True); self.rows = []; self.run_ = True; self.phase = "idle"
    def run(self):
        while self.run_:
            r = subprocess.run(["curl", "-s", "-o", "/dev/null", "--max-time", "3", "-w", "%{http_code}", f"http://127.0.0.1:{PORT + 1}/?s=1k"], capture_output=True, text=True)
            self.rows.append((self.phase, r.stdout.strip() if r.returncode == 0 else f"curl{r.returncode}"))
            for _ in range(50):
                if not self.run_: break
                time.sleep(0.1)
    def summary(self, phase):
        return f"new client {phase}: " + " ".join(x[1] for x in self.rows if x[0] == phase)

def cli_dump(label):
    out = {}
    for cmd in ("show sess", "show fd", "show info"):
        try:
            c = socket.socket(socket.AF_UNIX); c.settimeout(5); c.connect(f"/tmp/rxb-{label}.sock"); c.sendall(cmd.encode() + b"\n"); buf = b""
            while True:
                d = c.recv(1 << 20)
                if not d: break
                buf += d
            c.close(); out[cmd] = buf.decode(errors="replace")
        except OSError as e: out[cmd] = f"ERR {e}"
        open(f"/tmp/rxb-{label}-{cmd.split()[1]}.txt", "w").write(out[cmd])
    sess = [l for l in out["show sess"].splitlines() if l.strip() and not l.startswith("Total")]
    fd = [l for l in out["show fd"].splitlines() if l.strip()]
    be = [l for l in fd if "/slow" in l or "slow/" in l or "be=" in l and "slow" in l]
    cur = [l for l in out["show info"].splitlines() if l.startswith(("CurrConns", "CurrSslConns", "Maxsock"))]
    print(f"          cli: show sess {len(sess)} lines (streams/sessions), show fd {len(fd)} lines, of which backend slow {len(be)}; {' '.join(cur)}; raw in /tmp/rxb-{label}-*.txt", flush=True)
    kernel_skmem()

def kernel_skmem():
    """Kernel socket memory held on the proxy's client-side sockets (sport = h2c port): what the proxy has not read."""
    r = subprocess.run(["ss", "-tmn", "state", "established", f"( sport = :{PORT} )"], capture_output=True, text=True).stdout
    import re
    rq = sum(int(x) for x in re.findall(r"^\s*(\d+)\s+\d+\s+127", r, re.M))
    rmem = sum(int(x) for x in re.findall(r"skmem:\(r(\d+),", r))
    n = len(re.findall(r"skmem:", r))
    print(f"          kernel: {n} client sockets on the proxy side, Recv-Q total {rq / 1048576:.2f} MB, skmem rmem_alloc total {rmem / 1048576:.2f} MB (unread by the proxy)", flush=True)

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
    p = start_proxy(binary, CFG.replace("{label}", label), PORT, f"rxbudget-{label}")
    if not p: return
    conns = []; lg = nc = None
    try:
        time.sleep(0.5); r_idle, f_idle = rss_cpu(p.pid)[0], fds(p.pid)
        if LEGIT:
            lg = Legit(); nc = NewClient(); lg.start(); nc.start(); time.sleep(2.0); lg.phase = nc.phase = "build"
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
        if CLI: cli_dump(label)
        else: kernel_skmem()
        if HOLD_SECS:
            if LEGIT: lg.phase = nc.phase = "hold"
            t1 = time.time()
            while time.time() - t1 < HOLD_SECS:
                for c in conns: c.pump(0.01)
                time.sleep(0.5)
            print(f"          held {HOLD_SECS:.0f} s: RSS {rss_cpu(p.pid)[0]} MB, fds {fds(p.pid)}, conns closed by proxy {sum(1 for c in conns if c.goaway is not None)}", flush=True)
        if LEGIT:
            lg.phase = nc.phase = "after"
            for ph in ("idle", "build", "hold"): print("          legit " + lg.summary(ph) + "; " + nc.summary(ph), flush=True)
        for c in conns:
            try: c.s.close()
            except OSError: pass
        conns = []
        time.sleep(2.0)
        print(f"          after close +2 s: RSS {rss_cpu(p.pid)[0]} MB, fds {fds(p.pid)}, alive {p.poll() is None}", flush=True)
    finally:
        if lg: lg.run_ = False
        if nc: nc.run_ = False
        for c in conns:
            try: c.s.close()
            except OSError: pass
        stop(p)

ls, fillers = hung_backend()
ht = start_haterm(HATERM)
try:
    for label, binary in SPECS: one(label, binary)
finally:
    for c in list(fillers): c.close()
    ls.close(); stop(ht)
