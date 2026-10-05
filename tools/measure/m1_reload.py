#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
"""M1: reload time and memory (T214). SIGUSR2 under constant `wrk2 -t2 -c50 -R2000` load.

Layouts: haproxy `-W`; ibex `-W`; ibex `-W -S <sock>` (master CLI, T200).
    tools/measure/m1_reload.py single [--runs 3] [--sizes 1000,10000]
    tools/measure/m1_reload.py soak [--reloads 100] [--sizes 1000]

single: per (size, layout), interleaved over the runs: seconds from SIGUSR2 to the first
answer on a connection a new worker holds (a probe opens one every ~5 ms, then finds the
process owning the accepted socket in /proc; Ibex has no `pid` fetch to put in a header),
seconds until the old workers are gone, peak combined VmRSS of every process of the layout
(master + old + new; sampled every 10 ms), failed requests (wrk2 socket errors + non-2xx).
soak: N reloads one after the other under load; RSS and fds of the master and of the
current worker before / after (fds both raw and net of established TCP sockets).
Processes are found by the (unique) config path on their command line.
"""
import argparse
import os
import re
import signal
import socket
import statistics
import subprocess
import threading
import time
import m1lib as m

WRK2 = os.path.expanduser(os.environ.get("WRK2", "~/.local/bin/wrk2"))
LAYOUTS = (("haproxy", "-W"), ("ibex", "-W"), ("ibex", "-W -S"))
_ports = iter(range(27001, 27100))


def next_port():
    for p in _ports:
        s = socket.socket()
        try:
            s.bind(("127.0.0.1", p))
            return p
        except OSError:
            continue
        finally:
            s.close()
    raise RuntimeError("out of ports 27001-27099")


m.free_port = next_port  # m1lib.start_origin uses it too


def cfg_text(port, origin, n, kind="ibex", sock=""):
    out = ["global", "    maxconn 20000", "    nbthread 1"] + ([f"    stats socket {sock} mode 600 level admin expose-fd listeners"] if kind == "haproxy" and not os.environ.get("NO_EXPOSE_FD") else []) + ["defaults", "    mode http",
           "    timeout connect 5s", "    timeout client 30s", "    timeout server 30s",
           "frontend fe", "    maxconn 20000", f"    bind 127.0.0.1:{port}",
           "    default_backend b0"]
    for i in range(n):
        out += [f"backend b{i}", f"    server s{i} 127.0.0.1:{origin}"]
    return "\n".join(out) + "\n"


def rss(pid):
    try:
        return m.rss_kb(pid) or 0
    except OSError:
        return 0


def starttime(pid):
    with open(f"/proc/{pid}/stat") as f:
        return int(f.read().rsplit(")", 1)[1].split()[19])


def alive(pid):
    try:
        with open(f"/proc/{pid}/stat") as f:
            return f.read().rsplit(")", 1)[1].split()[0] != "Z"
    except OSError:
        return False


def find_pids(tag):
    out = []
    for d in os.listdir("/proc"):
        if d.isdigit():
            try:
                with open(f"/proc/{d}/cmdline", "rb") as f:
                    if tag in f.read().decode(errors="replace") and alive(int(d)):
                        out.append(int(d))
            except OSError:
                pass
    return out


def est_inodes():
    out = set()
    for f in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            for line in open(f).readlines()[1:]:
                x = line.split()
                if x[3] in ("01", "02", "03", "08"):
                    out.add(x[9])
        except OSError:
            pass
    return out


def fds_net(pid):
    """fds net of established TCP sockets (what a leak would grow)."""
    est = est_inodes()
    n = 0
    try:
        for fd in os.listdir(f"/proc/{pid}/fd"):
            try:
                t = os.readlink(f"/proc/{pid}/fd/{fd}")
            except OSError:
                continue
            if not (t.startswith("socket:[") and t[8:-1] in est):
                n += 1
    except OSError:
        pass
    return n


class Proxy:
    def __init__(self, kind, flags, nback, origin):
        self.kind, self.flags = kind, flags
        self.port = next_port()
        tag = f"m1r-{os.getpid()}-{kind}-{flags.replace(' ', '')}-{nback}-{self.port}"
        self.dir = os.path.join(m.TMP, tag)
        os.makedirs(self.dir, exist_ok=True)
        self.cfg = os.path.join(self.dir, "c.cfg")
        self.pidfile = os.path.join(self.dir, "p.pid")
        with open(self.cfg, "w") as f:
            f.write(cfg_text(self.port, origin, nback, kind, f"/tmp/m1r-{os.getpid()}-{self.port}.stats"))
        binary = m.IBEX if kind == "ibex" else m.HAPROXY
        argv = [binary] + flags.split() + ["-f", self.cfg, "-p", self.pidfile]
        if "-S" in argv:  # master CLI socket: short path (sun_path limit)
            argv.insert(argv.index("-S") + 1, f"/tmp/m1r-{os.getpid()}-{self.port}.sock")
        self.log = open(os.path.join(self.dir, "log"), "w")
        self.proc = subprocess.Popen(argv, stdout=self.log, stderr=self.log)
        m.wait_listen(self.proc, self.port, timeout=180)
        time.sleep(1)
        self.master = self.proc.pid if (kind == "haproxy" or "-S" in flags) else None

    def pids(self):
        return find_pids(self.cfg)

    def workers(self):
        return [p for p in self.pids() if p != self.master]

    def current_worker(self):
        w = self.workers()
        return max(w, key=starttime) if w else None

    def signal_target(self):
        if self.master:
            return self.master
        try:
            return int(open(self.pidfile).read().split()[0])
        except (OSError, ValueError, IndexError):
            return self.proc.pid

    def reload(self):
        os.kill(self.signal_target(), signal.SIGUSR2)

    def stop(self):
        for sig in (signal.SIGTERM, signal.SIGKILL):
            for p in self.pids():
                try:
                    os.kill(p, sig)
                except OSError:
                    pass
            time.sleep(0.5)
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass


def owner_of(port, cport, pids):
    """The process (among pids) holding the accepted side of the connection cport -> port."""
    ino = None
    for f in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            for line in open(f).readlines()[1:]:
                x = line.split()
                lp, rp = int(x[1].rsplit(":", 1)[1], 16), int(x[2].rsplit(":", 1)[1], 16)
                if lp == port and rp == cport and x[3] == "01":
                    ino = x[9]
        except OSError:
            pass
    if ino is None:
        return None
    want = f"socket:[{ino}]"
    for p in pids:
        try:
            for fd in os.listdir(f"/proc/{p}/fd"):
                try:
                    if os.readlink(f"/proc/{p}/fd/{fd}") == want:
                        return p
                except OSError:
                    pass
        except OSError:
            pass
    return None


class Probe(threading.Thread):
    """Opens a keep-alive connection every few ms, gets one answer, then asks /proc which
    process holds the accepted side: records (time of the answer, that pid)."""
    def __init__(self, px):
        super().__init__(daemon=True)
        self.px, self.port = px, px.port
        self.seen, self.stop_ev, self.errors = [], threading.Event(), 0

    def run(self):
        pids, last = [], 0.0
        while not self.stop_ev.is_set():
            try:
                s = socket.create_connection(("127.0.0.1", self.port), timeout=2)
                cport = s.getsockname()[1]
                s.sendall(b"GET /probe HTTP/1.1\r\nHost: m1\r\n\r\n")
                buf = b""
                while b"\r\n\r\n" not in buf:
                    d = s.recv(4096)
                    if not d:
                        break
                    buf += d
                t = time.monotonic()
                if buf.startswith(b"HTTP/1.1 200"):
                    if t - last > 0.05:
                        pids, last = self.px.pids(), t
                    o = owner_of(self.port, cport, pids)
                    if o is None:
                        pids, last = self.px.pids(), t
                        o = owner_of(self.port, cport, pids)
                    if o is not None:
                        self.seen.append((t, o))
                else:
                    self.errors += 1
                s.close()
            except OSError:
                self.errors += 1
            time.sleep(0.002)


class Sampler(threading.Thread):
    """Every 10 ms: sum of VmRSS (kB) of the layout's processes. The pid set is refreshed by
    a second thread as fast as /proc scanning allows (so the sampling loop never waits)."""
    def __init__(self, px):
        super().__init__(daemon=True)
        self.px, self.series, self.stop_ev = px, [], threading.Event()
        self.pids = px.pids()
        threading.Thread(target=self.scan, daemon=True).start()

    def scan(self):
        while not self.stop_ev.is_set():
            self.pids = self.px.pids()

    def run(self):
        while not self.stop_ev.is_set():
            t = time.monotonic()
            pids = list(self.pids)
            self.series.append((t, sum(rss(p) for p in pids), len(pids)))
            time.sleep(max(0.0, 0.01 - (time.monotonic() - t)))


class PyClient(threading.Thread):
    """Side client next to wrk2: 10 keep-alive connections, 20 requests/s each. An idle
    connection the proxy closed is retried once on a new one (legal HTTP/1.1, counted as
    `idle_closed`); a request that gets a reset, a truncated answer or no answer within 2 s
    is `failed`."""
    def __init__(self, port):
        super().__init__(daemon=True)
        self.port, self.stop_ev = port, threading.Event()
        self.ok = self.idle_closed = self.failed = 0
        self.lock = threading.Lock()

    def conn_loop(self):
        s = None
        nxt = time.monotonic()
        while not self.stop_ev.is_set():
            nxt += 0.05
            for attempt in (0, 1):
                try:
                    reused = s is not None
                    if s is None:
                        s = socket.create_connection(("127.0.0.1", self.port), timeout=2)
                    s.sendall(b"GET / HTTP/1.1\r\nHost: m1\r\n\r\n")
                    buf = b""
                    while b"\r\n\r\n" not in buf:
                        d = s.recv(4096)
                        if not d:
                            raise EOFError
                        buf += d
                    if not buf.startswith(b"HTTP/1.1 200"):
                        raise ValueError
                    with self.lock:
                        self.ok += 1
                    if b"onnection: close" in buf:
                        s.close()
                        s = None
                    break
                except (OSError, EOFError, ValueError) as e:
                    if s is not None:
                        s.close()
                    s = None
                    if reused and attempt == 0 and not isinstance(e, socket.timeout) and "buf" in dir() and not buf:
                        with self.lock:
                            self.idle_closed += 1
                        continue
                    with self.lock:
                        self.failed += 1
                    break
            time.sleep(max(0.0, nxt - time.monotonic()))

    def run(self):
        ts = [threading.Thread(target=self.conn_loop, daemon=True) for _ in range(10)]
        [t.start() for t in ts]
        [t.join() for t in ts]


def wrk(port, dur):
    cmd = [WRK2, "-t2", "-c50", "-R2000", "-d", f"{int(dur)}s", "--timeout", "5s", f"http://127.0.0.1:{port}/"]
    return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)


def wrk_result(p):
    out = p.communicate()[0]
    r = {}
    mt = re.search(r"Socket errors: connect (\d+), read (\d+), write (\d+), timeout (\d+)", out)
    r["sock_errors"] = sum(int(x) for x in mt.groups()) if mt else 0
    mt = re.search(r"Non-2xx or 3xx responses: (\d+)", out)
    r["non2xx"] = int(mt.group(1)) if mt else 0
    mt = re.search(r"(\d+) requests in", out)
    r["requests"] = int(mt.group(1)) if mt else 0
    mt = re.search(r"Requests/sec:\s+([\d.]+)", out)
    r["rps"] = float(mt.group(1)) if mt else 0.0
    r["failed"] = r["sock_errors"] + r["non2xx"]
    r["wrk_tail"] = "|".join(l.strip() for l in out.splitlines() if re.search(r"Socket errors|Non-2xx|requests in|Requests/sec", l))
    return r


def one_reload(px, probe, timeout=30):
    """Send SIGUSR2; return (t_new_accepting, t_old_gone) in seconds after the signal."""
    old = set(px.workers())
    seen_before = {p for _, p in probe.seen}
    n0 = len(probe.seen)
    t0 = time.monotonic()
    px.reload()
    t_new = t_gone = None
    while time.monotonic() - t0 < timeout:
        if t_new is None:
            for t, p in probe.seen[n0:]:
                if p not in seen_before:
                    t_new = t - t0
                    break
        if t_gone is None and not any(alive(p) for p in old):
            t_gone = time.monotonic() - t0
        if t_new is not None and t_gone is not None:
            break
        time.sleep(0.002)
    return t_new, t_gone


def single(kind, flags, nback, origin):
    px = Proxy(kind, flags, nback, origin)
    probe = Probe(px)
    sam = Sampler(px)
    try:
        w = wrk(px.port, 14)
        pyc = PyClient(px.port)
        pyc.start()
        time.sleep(3)
        probe.start()
        sam.start()
        time.sleep(1)
        base = sam.series[-1][1]
        t_sig = time.monotonic()
        t_new, t_gone = (None, None) if os.environ.get('NO_RELOAD') else one_reload(px, probe)
        time.sleep(1.5)
        end = t_sig + (t_gone or 5) + 1.0
        win = [s for s in sam.series if t_sig - 0.05 <= s[0] <= end]
        peak = max(s[1] for s in win)
        maxprocs = max(s[2] for s in win)
        after = sam.series[-1][1]
        pyc.stop_ev.set()
        r = wrk_result(w)
        return {"new_accepting_s": t_new, "old_gone_s": t_gone, "rss_base_kb": base,
                "rss_peak_kb": peak, "max_procs": maxprocs, "samples": len(win), "rss_after_kb": after, "failed": r["failed"],
                "requests": r["requests"], "rps": r["rps"], "wrk": r["wrk_tail"], "py_ok": pyc.ok, "py_idle_closed": pyc.idle_closed, "py_failed": pyc.failed, "probe_errors": probe.errors}
    finally:
        probe.stop_ev.set()
        sam.stop_ev.set()
        px.stop()


def snapshot(px):
    w = px.current_worker()
    res = {"worker_rss_kb": rss(w), "worker_fds": m.nfds(w) if w else 0,
           "worker_fds_net": fds_net(w) if w else 0}
    if px.master:
        res |= {"master_rss_kb": rss(px.master), "master_fds": m.nfds(px.master),
                "master_fds_net": fds_net(px.master)}
    res["procs"] = len(px.pids())
    return res


def avg_snap(px):
    ss = []
    for _ in range(5):
        ss.append(snapshot(px))
        time.sleep(0.2)
    return {k: statistics.median(s[k] for s in ss) for k in ss[0]}


def soak(kind, flags, nback, origin, reloads):
    px = Proxy(kind, flags, nback, origin)
    probe = Probe(px)
    try:
        w = wrk(px.port, int(reloads * 1.6 + 25))
        pyc = PyClient(px.port)
        pyc.start()
        time.sleep(3)
        probe.start()
        time.sleep(1)
        before = avg_snap(px)
        slow = []
        for i in range(reloads):
            t_new, t_gone = one_reload(px, probe)
            if t_new is None or t_gone is None:
                slow.append(i)
            time.sleep(1.0)
        time.sleep(3)
        after = avg_snap(px)
        pyc.stop_ev.set()
        r = wrk_result(w)
        return {"py_ok": pyc.ok, "py_idle_closed": pyc.idle_closed, "py_failed": pyc.failed, "wrk": r["wrk_tail"], "reloads": reloads, "before": before, "after": after, "failed": r["failed"],
                "sock_errors": r["sock_errors"], "non2xx": r["non2xx"], "requests": r["requests"],
                "not_completed": slow, "probe_errors": probe.errors}
    finally:
        probe.stop_ev.set()
        px.stop()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=("single", "soak"))
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--sizes", default="1000,10000")
    ap.add_argument("--reloads", type=int, default=100)
    ap.add_argument("--layouts", default="all", help="indexes into the layout list, e.g. 0,2")
    a = ap.parse_args()
    sizes = [int(x) for x in a.sizes.split(",")]
    layouts = LAYOUTS if a.layouts == "all" else [LAYOUTS[int(i)] for i in a.layouts.split(",")]
    print(m.header("m1_reload"), "mode=" + a.mode, flush=True)
    m.wait_load(limit=16, patience=30)
    origin_p, origin = m.start_origin()
    try:
        if a.mode == "single":
            res = {}
            for run in range(a.runs):
                for n in sizes:
                    for kind, flags in layouts:
                        r = single(kind, flags, n, origin)
                        res.setdefault((n, kind, flags), []).append(r)
                        m.emit(param="reload", backends=n, kind=kind, flags=flags, run=run, **r)
            for (n, kind, flags), rs in res.items():
                med = {k: statistics.median(x[k] for x in rs if x[k] is not None) for k in
                       ("new_accepting_s", "old_gone_s", "rss_base_kb", "rss_peak_kb")}
                m.emit(param="reload-median", backends=n, kind=kind, flags=flags,
                       failed_total=sum(x["failed"] for x in rs), **med)
        else:
            for n in sizes:
                for kind, flags in layouts:
                    m.emit(param="soak", backends=n, kind=kind, flags=flags,
                           **soak(kind, flags, n, origin, a.reloads))
    finally:
        m.stop(origin_p)


if __name__ == "__main__":
    main()
