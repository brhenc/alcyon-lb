# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
"""Shared bits for the single-connection probes: start haterm and a proxy on 127.0.0.1, a UDP
syslog sink for the proxy's httplog lines, /proc readers.  Lab only."""
import os, re, socket, subprocess, sys, threading, time

HATERM = "/root/ibex-test/haterm"
TICK = os.sysconf("SC_CLK_TCK")

def wait_port(port, secs=5):
    t0 = time.time()
    while time.time() - t0 < secs:
        try: socket.create_connection(("127.0.0.1", port), 0.2).close(); return True
        except OSError: time.sleep(0.05)
    return False

def start_haterm(port, cpus="16-31", extra=()):
    p = subprocess.Popen(["taskset", "-c", cpus, HATERM, "-L", f"127.0.0.1:{port}", "-G", "nbthread 4", *extra],
                         stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    if not wait_port(port): p.terminate(); raise SystemExit("haterm did not listen")
    time.sleep(0.2); return p

def start_proxy(binary, cfg_text, port, tag, cpus="0-3", wrap=()):
    cfg = f"/tmp/probe-{tag}.cfg"; open(cfg, "w").write(cfg_text)
    log = open(f"/tmp/probe-{tag}.log", "a")
    p = subprocess.Popen([*wrap, "taskset", "-c", cpus, binary, "-f", cfg], stdout=log, stderr=subprocess.STDOUT)
    if not wait_port(port): p.terminate(); p.wait(5); print(f"{tag}: did not listen; log tail:"); print(open(f"/tmp/probe-{tag}.log").read()[-800:]); return None
    time.sleep(0.2); return p

def stop(p):
    if p and p.poll() is None:
        p.terminate()
        try: p.wait(5)
        except subprocess.TimeoutExpired: p.kill(); p.wait(5)

class UdpLog:
    """Binds a UDP port for `log 127.0.0.1:<port> local0`; .lines() returns what arrived (text after the syslog header)."""
    def __init__(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); self.s.bind(("127.0.0.1", 0)); self.port = self.s.getsockname()[1]
        self.buf = []; self.s.settimeout(0.2); threading.Thread(target=self._rx, daemon=True).start()
    def _rx(self):
        while True:
            try: d, _ = self.s.recvfrom(65536)
            except socket.timeout: continue
            except OSError: return
            t = d.decode(errors="replace").strip(); t = re.sub(r"^<\d+>\S+ \S+ \S+ \S+ ", "", t) if t.startswith("<") else t
            self.buf.append((time.time(), t))
    def lines(self, since=0.0): return [(round(ts - since, 1) if since else ts, t) for ts, t in self.buf]

def proxy_pid(p):
    """The proxy's worker pid: HAProxy forks a master unless run in foreground mode; we run both plain."""
    return p.pid

def rss_cpu(pid):
    rss = int([l for l in open(f"/proc/{pid}/status") if l.startswith("VmRSS")][0].split()[1]) // 1024
    f = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()
    return rss, (int(f[11]) + int(f[12])) / TICK

def fds(pid):
    return len(os.listdir(f"/proc/{pid}/fd"))

def be_conns(port):
    out = subprocess.run(["ss", "-Htn", "state", "established", f"( dport = :{port} )"], capture_output=True, text=True).stdout
    return len([l for l in out.splitlines() if l.strip()])

def ended_how(s, secs):
    """Reads until the peer ends the connection or secs pass: returns (bytes, 'EOF'|'RST'|'open', t)."""
    s.settimeout(0.1); t0 = time.time(); n = 0; got = bytearray()
    def ret(how): LAST_BYTES[:] = got; return n, how, round(time.time() - t0, 2)
    while time.time() - t0 < secs:
        try:
            d = s.recv(65536)
            if not d: return ret("EOF")
            n += len(d); got += d
        except socket.timeout: continue
        except ConnectionResetError: return ret("RST")
        except OSError as e: return ret(f"err {e.errno}")
    return ret("open")

LAST_BYTES = bytearray()  # what ended_how() read, for callers that want to decode it
H2NAMES = {0: "DATA", 1: "HEADERS", 3: "RST_STREAM", 4: "SETTINGS", 6: "PING", 7: "GOAWAY", 8: "WINDOW_UPDATE"}

def h2_frames(buf):
    out = []
    while len(buf) >= 9:
        ln = int.from_bytes(buf[:3], "big"); t = buf[3]; fl = buf[4]; sid = int.from_bytes(buf[5:9], "big") & 0x7fffffff
        if len(buf) < 9 + ln: break
        pl = buf[9:9 + ln]; buf = buf[9 + ln:]
        d = f"{H2NAMES.get(t, t)}({sid}"
        if t == 3: d += f",err={int.from_bytes(pl[:4], 'big')}"
        if t == 7: d += f",last={int.from_bytes(pl[:4], 'big')},err={int.from_bytes(pl[4:8], 'big')}"
        if t == 1: d += f",{ln}B"
        out.append(d + ")")
    return " ".join(out)
