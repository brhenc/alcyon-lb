#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
"""MY-7: held h2 streams, memory retention and per-stream cost.  Lab only (127.0.0.1).
    streamsprobe.py <h2c port> <conns> <secs> label=binary ...
Starts haterm and the proxy (battery timeouts), runs `clients.py attack h2_streams` with <conns>
connections (300 unfinished POST streams each) for <secs>, samples the proxy's RSS, fds and the
established backend connections every 2 s, kills the attacker, keeps sampling for 60 s, then
sends a second identical wave and samples again.  Prints peak and after values per wave."""
import os, signal, socket, subprocess, sys, time
sys.path.insert(0, "/root/battery"); sys.path.insert(0, "/root/battery/repro")
from clients import PREFACE, settings, frame, hpack_lit
from labproxy import start_haterm, start_proxy, stop, fds, rss_cpu, be_conns

PORT, CONNS, SECS = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
SPECS = [s.split("=", 1) for s in sys.argv[4:]]
CFG = f"""global
    nbthread 4
    maxconn 2000
defaults
    mode http
    timeout connect 5s
    timeout client 30s
    timeout server 30s
    timeout http-request 5s
frontend f
    bind 127.0.0.1:{PORT} proto h2
    default_backend b
backend b
    server s1 127.0.0.1:8890
"""

def sample(pid): r, c = rss_cpu(pid); return (r, fds(pid), be_conns(8890), c)

def smaps(pid):
    want = ("Rss", "Pss", "Anonymous", "Private_Dirty")
    return " ".join(l.split()[0][:-1] + "=" + l.split()[1] + "k" for l in open(f"/proc/{pid}/smaps_rollup") if l.split(":")[0] in want)

SET = {3: "MAX_CONCURRENT_STREAMS", 4: "INITIAL_WINDOW_SIZE", 6: "MAX_HEADER_LIST_SIZE"}

def observer(label, pid):
    """One connection, 300 unfinished POST streams like the attacker: how many does the proxy accept?"""
    s = socket.create_connection(("127.0.0.1", PORT)); s.sendall(PREFACE + settings()); time.sleep(0.2)
    for k in range(300):
        s.sendall(frame(1, 0x4, 1 + 2 * k, b"\x83\x86\x84\x41" + hpack_lit(b"battery")))
        if k % 50 == 49: time.sleep(0.01)
    s.settimeout(0.1); t0 = time.time(); buf = b""; rst = {}; hdr = {}; go = None; srv = {}; closed = None
    while time.time() - t0 < 3 and closed is None:
        try:
            d = s.recv(65536)
            if not d: closed = "EOF"; break
            buf += d
        except socket.timeout: continue
        except OSError as e: closed = e.strerror; break
        while len(buf) >= 9:
            ln = int.from_bytes(buf[:3], "big"); t = buf[3]; sid = int.from_bytes(buf[5:9], "big") & 0x7fffffff
            if len(buf) < 9 + ln: break
            pl = buf[9:9 + ln]; buf = buf[9 + ln:]
            if t == 4 and sid == 0:
                for i in range(0, len(pl) - 5, 6): srv[SET.get(int.from_bytes(pl[i:i+2], "big"), int.from_bytes(pl[i:i+2], "big"))] = int.from_bytes(pl[i+2:i+6], "big")
            elif t == 3: rst[sid] = int.from_bytes(pl[:4], "big")
            elif t == 1: hdr[sid] = ln
            elif t == 7: go = (int.from_bytes(pl[:4], "big"), int.from_bytes(pl[4:8], "big"))
    be = be_conns(8890); f = fds(pid)
    errs = {}
    for e in rst.values(): errs[e] = errs.get(e, 0) + 1
    print(f"{label:9s} observer: 300 POST streams on one connection -> RST_STREAM {len(rst)} (err codes {errs}), HEADERS {len(hdr)}, "
          f"GOAWAY {go}, conn {closed or 'open'}; backend conns now {be}, proxy fds {f}; server SETTINGS {srv}", flush=True)
    s.close(); time.sleep(1)

def wave(label, pid, n):
    att = subprocess.Popen(["taskset", "-c", "32-47", "python3", "/root/battery/clients.py", "attack", "h2_streams", "127.0.0.1", str(PORT), str(SECS), str(CONNS)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, preexec_fn=os.setsid)
    t0 = time.time(); during = []
    while time.time() - t0 < SECS:
        time.sleep(2); during.append(sample(pid))
    try: os.killpg(att.pid, signal.SIGKILL)
    except ProcessLookupError: pass
    att.wait(5); t1 = time.time(); after = []
    while time.time() - t1 < 60:
        time.sleep(2); after.append(sample(pid))
    pk = max(during, key=lambda s: s[0])
    print(f"{label:9s} wave {n} ({CONNS} conns x 300 streams, {SECS} s): peak RSS {pk[0]} MB, peak fds {max(s[1] for s in during)}, "
          f"peak backend conns {max(s[2] for s in during)}, CPU-s during {during[-1][3] - during[0][3]:.1f}; "
          f"after kill: RSS at +2/+10/+30/+60 s {after[0][0]}/{after[4][0]}/{after[14][0]}/{after[-1][0]} MB, fds {after[0][1]} -> {after[-1][1]}, backend conns {after[0][2]} -> {after[-1][2]}", flush=True)
    print(f"          RSS during every 10 s: {[s[0] for s in during[::5]]}; smaps_rollup after: {smaps(pid)}")

ht = start_haterm(8890, extra=("-G", "maxconn 100000"))
try:
    for label, binary in SPECS:
        p = start_proxy(binary, CFG, PORT, f"streams-{label}")
        if not p: continue
        try:
            print(f"{label:9s} idle: RSS {rss_cpu(p.pid)[0]} MB, fds {fds(p.pid)}; smaps {smaps(p.pid)}")
            observer(label, p.pid)
            wave(label, p.pid, 1); wave(label, p.pid, 2)
            print(f"{label:9s} end: RSS {rss_cpu(p.pid)[0]} MB, fds {fds(p.pid)}, alive {p.poll() is None}", flush=True)
        finally:
            stop(p)
finally:
    stop(ht)
