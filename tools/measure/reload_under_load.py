#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

"""Reload under load (T166, M1 operations parameter "Reload").

Runs either HAProxy or Alcyon with -W, puts constant keep-alive h1 load, a few long
downloads and one WebSocket through it, sends SIGUSR2 every --interval seconds,
--reloads times, then SIGUSR1 with a download in flight. Prints what an operator
observes: failed requests, resets, old-process drain times, WebSocket lifetime after
the reload that retired its process, RSS and fd count of the master (HAProxy) or of the
serving process (Alcyon, which has no master).

    tools/measure/reload_under_load.py --binary /path/haproxy --kind haproxy --reloads 100
    tools/measure/reload_under_load.py --binary target/debug/alcyon --kind alcyon --reloads 100

Exit 0 when every criterion holds, 1 otherwise; --json writes the numbers.

Request accounting: a request sent on a reused keep-alive connection that is closed
before a single response byte arrives is what every HTTP client retries (RFC 9112 9.3.1,
curl, browsers); it is counted in "stale_retried" and retried once on a new connection.
Everything else that does not end in a complete 200 is a failed request.
"""

import argparse
import base64
import errno
import hashlib
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

BIG = 8 * 1024 * 1024
BIG_SECONDS = 2.5
CHUNK = 64 * 1024


# ---------------------------------------------------------------- backend
def backend_conn(s):
    f = s.makefile("rb")
    try:
        while True:
            line = f.readline()
            if not line:
                return
            path = line.split()[1] if len(line.split()) > 1 else b"/"
            hdrs = {}
            while True:
                h = f.readline()
                if not h or h in (b"\r\n", b"\n"):
                    break
                k, _, v = h.partition(b":")
                hdrs[k.strip().lower()] = v.strip()
            if hdrs.get(b"upgrade", b"").lower() == b"websocket":
                acc = base64.b64encode(hashlib.sha1(
                    hdrs.get(b"sec-websocket-key", b"") +
                    b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest())
                s.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                          b"Connection: Upgrade\r\nSec-WebSocket-Accept: " + acc + b"\r\n\r\n")
                while True:
                    d = s.recv(4096)
                    if not d:
                        return
                    s.sendall(d)
            if path == b"/slow":
                time.sleep(0.3)
            if path == b"/big":
                s.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % BIG)
                n = BIG // CHUNK
                pause = BIG_SECONDS / n
                blob = b"x" * CHUNK
                for _ in range(n):
                    s.sendall(blob)
                    time.sleep(pause)
            else:
                s.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
    except OSError:
        pass
    finally:
        s.close()


def start_backend():
    ls = socket.socket()
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("127.0.0.1", 0))
    ls.listen(1024)

    def loop():
        while True:
            c, _ = ls.accept()
            threading.Thread(target=backend_conn, args=(c,), daemon=True).start()
    threading.Thread(target=loop, daemon=True).start()
    return ls.getsockname()[1]


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


# ---------------------------------------------------------------- clients
class Stats:
    def __init__(self):
        self.lock = threading.Lock()
        self.c = {}
        self.errors = []

    def inc(self, k, n=1):
        with self.lock:
            self.c[k] = self.c.get(k, 0) + n

    def err(self, what):
        with self.lock:
            if len(self.errors) < 20:
                self.errors.append(f"{time.monotonic():.3f} {what}")


def classify(e):
    if isinstance(e, ConnectionResetError) or getattr(e, "errno", None) == errno.ECONNRESET:
        return "rst"
    if isinstance(e, ConnectionRefusedError):
        return "refused"
    if isinstance(e, socket.timeout):
        return "timeout"
    if isinstance(e, BrokenPipeError):
        return "epipe"
    return "eof"


def read_response(s, f):
    """Returns (status, close) or raises; 'got' tells whether any byte arrived."""
    line = f.readline()
    if not line:
        raise EOFError("eof before status")
    status = int(line.split()[1])
    clen, close = 0, False
    while True:
        h = f.readline()
        if not h:
            raise EOFError("eof in headers")
        if h in (b"\r\n", b"\n"):
            break
        k, _, v = h.partition(b":")
        k = k.strip().lower()
        if k == b"content-length":
            clen = int(v)
        elif k == b"connection" and b"close" in v.lower():
            close = True
    body = f.read(clen)
    if len(body) != clen:
        raise EOFError("short body")
    return status, close


def keepalive_client(port, st, stop):
    s = f = None
    reused = False
    while not stop.is_set():
        for attempt in (0, 1):
            try:
                if s is None:
                    s = socket.create_connection(("127.0.0.1", port), timeout=5)
                    f = s.makefile("rb")
                    reused = False
                s.sendall(b"GET /s HTTP/1.1\r\nHost: t\r\n\r\n")
                status, close = read_response(s, f)
                if status != 200:
                    st.inc("failed_status")
                    st.err(f"status {status}")
                else:
                    st.inc("ok")
                if close:
                    st.inc("conn_close_hdr")
                    s.close()
                    s = None
                else:
                    reused = True
                break
            except (OSError, EOFError, ValueError, IndexError) as e:
                kind = classify(e) if isinstance(e, OSError) else "eof"
                got = isinstance(e, EOFError) and str(e) != "eof before status"
                try:
                    s.close()
                except Exception:
                    pass
                s = None
                if kind == "rst":
                    st.inc("rst_seen")
                if reused and not got and attempt == 0 and kind in ("rst", "eof", "epipe"):
                    st.inc("stale_retried")
                    st.inc(f"stale_{kind}")
                    continue
                st.inc("failed")
                st.inc(f"failed_{kind}")
                st.err(f"ka {kind} reused={reused} {e!r}")
                break


def download_client(port, st, stop):
    while not stop.is_set():
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=10)
            s.sendall(b"GET /big HTTP/1.1\r\nHost: t\r\n\r\n")
            f = s.makefile("rb")
            status, _ = read_response(s, f)
            st.inc("dl_ok" if status == 200 else "dl_failed")
        except (OSError, EOFError, ValueError, IndexError) as e:
            st.inc("dl_failed")
            st.err(f"download {e!r}")
        finally:
            try:
                s.close()
            except Exception:
                pass


def ws_open(port):
    s = socket.create_connection(("127.0.0.1", port), timeout=3)
    s.sendall(b"GET /ws HTTP/1.1\r\nHost: t\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
              b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
    head = b""
    while b"\r\n\r\n" not in head:
        d = s.recv(1)
        if not d:
            raise EOFError("ws handshake eof")
        head += d
    if b" 101 " not in head.split(b"\r\n")[0]:
        raise EOFError("ws not 101")
    return s


def ws_client(port, st, stop, lives):
    """Opens a WebSocket, pings it until it dies, records (opened, died), reopens."""
    while not stop.is_set():
        try:
            s = ws_open(port)
        except (OSError, EOFError) as e:
            st.inc("ws_open_failed")
            st.err(f"ws open {e!r}")
            time.sleep(0.2)
            continue
        opened = time.monotonic()
        how = "stopped"
        while not stop.is_set():
            try:
                s.sendall(b"ping")
                got = b""
                while len(got) < 4:
                    d = s.recv(4 - len(got))
                    if not d:
                        raise EOFError("eof")
                    got += d
            except (OSError, EOFError) as e:
                how = classify(e) if isinstance(e, OSError) else "eof"
                break
            time.sleep(0.1)
        lives.append((opened, time.monotonic(), how))
        s.close()


# ---------------------------------------------------------------- processes
def rss_kb(pid):
    try:
        for line in open(f"/proc/{pid}/status"):
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    except OSError:
        pass
    return 0


def nfds(pid):
    try:
        return len(os.listdir(f"/proc/{pid}/fd"))
    except OSError:
        return 0


def established_inodes():
    """Inodes of every TCP connection on the host that is open, opening or half-closed
    (ESTABLISHED, SYN_SENT, SYN_RECV, CLOSE_WAIT): the ones load comes and goes with."""
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


def nfds_idle(pid):
    """fds net of established TCP connections: what is left is what a leak would grow.
    The load keeps a varying number of client and server connections open, so the raw
    count of a process that serves them moves with the load, not with the reloads."""
    est = established_inodes()
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


def alive(pid):
    try:
        with open(f"/proc/{pid}/stat") as fh:
            return fh.read().rsplit(")", 1)[1].split()[0] != "Z"
    except OSError:
        return False


def children(pid):
    out = []
    try:
        for t in os.listdir(f"/proc/{pid}/task"):
            out += [int(x) for x in open(f"/proc/{pid}/task/{t}/children").read().split()]
    except OSError:
        pass
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", required=True)
    ap.add_argument("--kind", choices=("haproxy", "alcyon"), required=True)
    ap.add_argument("--reloads", type=int, default=10)
    ap.add_argument("--interval", type=float, default=1.0)
    ap.add_argument("--hard-stop-after", type=float, default=4.0)
    ap.add_argument("--clients", type=int, default=8)
    ap.add_argument("--downloads", type=int, default=2)
    ap.add_argument("--json")
    ap.add_argument("--nbthread", type=int, default=1,
                    help="global nbthread (Alcyon defaults to 1, HAProxy to the CPU count)")
    a = ap.parse_args()

    bport = start_backend()
    port = free_port()
    tmp = tempfile.mkdtemp(prefix="t166-", dir="/tmp")
    cfg = os.path.join(tmp, "c.cfg")
    pidfile = os.path.join(tmp, "p.pid")
    hsa = int(a.hard_stop_after * 1000)
    with open(cfg, "w") as fh:
        fh.write(f"global\n  hard-stop-after {hsa}ms\n  nbthread {a.nbthread}\n"
                 "defaults\n  mode http\n  timeout connect 2s\n  timeout client 30s\n"
                 "  timeout server 30s\n  timeout tunnel 60s\n"
                 f"frontend fe\n  bind 127.0.0.1:{port}\n  default_backend be\n"
                 f"backend be\n  server s1 127.0.0.1:{bport}\n")
    argv = [a.binary, "-W", "-f", cfg, "-p", pidfile]
    if a.kind == "haproxy":
        argv += ["-S", os.path.join("/tmp", f"t166m-{os.getpid()}.sock")]
    log = open(os.path.join(tmp, "proxy.log"), "w")
    proc = subprocess.Popen(argv, stdout=log, stderr=log)
    deadline = time.monotonic() + 10
    while True:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=1).close()
            break
        except OSError:
            if time.monotonic() > deadline or proc.poll() is not None:
                print("proxy did not start; log in", tmp)
                return 2
            time.sleep(0.05)

    def serving():
        """(signal target, the process whose RSS/fds the operator watches, workers)."""
        if a.kind == "haproxy":
            return proc.pid, proc.pid, children(proc.pid)
        try:
            p = int(open(pidfile).read().split()[0])
        except (OSError, ValueError, IndexError):
            p = proc.pid
        return p, p, [p]

    st = Stats()
    stop = threading.Event()
    lives = []
    threads = [threading.Thread(target=keepalive_client, args=(port, st, stop), daemon=True)
               for _ in range(a.clients)]
    threads += [threading.Thread(target=download_client, args=(port, st, stop), daemon=True)
                for _ in range(a.downloads)]
    wst = threading.Thread(target=ws_client, args=(port, st, stop, lives), daemon=True)
    threads.append(wst)
    for t in threads:
        t.start()
    time.sleep(1.0)

    # Every process that ever served, with the time the reload that retired it was sent and
    # the time it was last seen alive.
    retired = {}       # pid -> retire time
    gone = {}          # pid -> first time seen dead
    reload_at = []
    reload_took = []
    samples = {}
    mon_stop = threading.Event()

    def monitor():
        while not mon_stop.is_set():
            now = time.monotonic()
            for pid in list(retired):
                if pid not in gone and not alive(pid):
                    gone[pid] = now
            time.sleep(0.02)
    threading.Thread(target=monitor, daemon=True).start()

    total_rss_peak = 0
    for i in range(1, a.reloads + 1):
        target, watched, workers = serving()
        t0 = time.monotonic()
        for w in workers:
            retired.setdefault(w, t0)
        os.kill(target, signal.SIGUSR2)
        reload_at.append(t0)
        # Reload done = a new serving process exists.
        done = None
        while time.monotonic() - t0 < 5:
            _, _, now_workers = serving()
            if any(w not in retired for w in now_workers):
                done = time.monotonic() - t0
                break
            time.sleep(0.005)
        reload_took.append(done)
        rest = a.interval - (time.monotonic() - t0)
        if rest > 0.05:
            time.sleep(rest - 0.05)
        _, watched, workers = serving()
        live = [watched] + [p for p in retired if p not in gone and p != watched] + \
            [w for w in workers if w != watched]
        total = sum(rss_kb(p) for p in set(live))
        total_rss_peak = max(total_rss_peak, total)
        if i in (1, 10, 100) or i == a.reloads:
            samples[i] = {"rss_kb": rss_kb(watched), "fds": nfds(watched), "fds_net": min(nfds_idle(watched) for _ in range(3)),
                          "live_procs": len(set(live)), "total_rss_kb": total}
        time.sleep(max(0.0, a.interval - (time.monotonic() - t0)))

    # Let the last old processes drain, keep the load on meanwhile.
    time.sleep(a.hard_stop_after + 1.5)
    stop.set()
    for t in threads:
        t.join(timeout=12)
    mon_stop.set()

    # Graceful stop with a download in flight.
    target, _, workers = serving()
    res = {}

    def last_download():
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=10)
            s.sendall(b"GET /big HTTP/1.1\r\nHost: t\r\n\r\n")
            res["status"] = read_response(s, s.makefile("rb"))[0]
        except (OSError, EOFError, ValueError) as e:
            res["error"] = repr(e)
    t = threading.Thread(target=last_download)
    t.start()
    time.sleep(0.5)
    os.kill(target, signal.SIGUSR1)
    t.join(timeout=15)
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and any(alive(p) for p in [target] + workers):
        time.sleep(0.05)
    usr1_exited = not any(alive(p) for p in [target] + workers)
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()

    drains = sorted(gone[p] - retired[p] for p in gone)
    undrained = [p for p in retired if p not in gone]
    # A WebSocket's process is retired by the first reload after the WebSocket opened.
    ws = []
    for opened, died, how in lives:
        r = next((t for t in reload_at if t > opened), None)
        if r is not None:
            ws.append({"after_retire_s": round(died - r, 2), "how": how})
    c = st.c
    first, last = samples.get(10) or samples.get(1), samples.get(a.reloads)
    out = {
        "kind": a.kind, "reloads": a.reloads, "interval": a.interval,
        "hard_stop_after_s": a.hard_stop_after,
        "requests_ok": c.get("ok", 0), "failed": c.get("failed", 0) + c.get("failed_status", 0),
        "failed_by_kind": {k: v for k, v in c.items() if k.startswith("failed_")},
        "stale_retried": c.get("stale_retried", 0),
        "stale_by_kind": {k: v for k, v in c.items() if k.startswith("stale_") and k != "stale_retried"},
        "resets_seen": c.get("rst_seen", 0), "conn_close_hdr": c.get("conn_close_hdr", 0),
        "downloads_ok": c.get("dl_ok", 0), "downloads_failed": c.get("dl_failed", 0),
        "ws_after_retire": ws, "ws_open_failed": c.get("ws_open_failed", 0),
        "drain_s": {"n": len(drains), "max": round(drains[-1], 2) if drains else None,
                    "median": round(drains[len(drains) // 2], 2) if drains else None},
        "undrained": len(undrained),
        "reload_s": {"max": round(max(x for x in reload_took if x is not None), 3)
                     if any(reload_took) else None,
                     "missed": sum(1 for x in reload_took if x is None)},
        "samples": samples, "total_rss_peak_kb": total_rss_peak,
        "usr1_inflight_download": res, "usr1_exited": usr1_exited,
        "errors": st.errors, "logdir": tmp,
    }
    ok = (out["failed"] == 0 and out["downloads_failed"] == 0 and out["undrained"] == 0
          and out["reload_s"]["missed"] == 0 and res.get("status") == 200 and usr1_exited
          and all(w["after_retire_s"] >= a.hard_stop_after - a.interval - 0.5 for w in ws if w["how"] != "stopped"))
    if first and last and a.reloads >= 10:
        # HAProxy's master holds one socketpair per live worker: compare fds net of those.
        extra = (lambda smp: smp["live_procs"] - 1) if a.kind == "haproxy" else (lambda smp: 0)
        ok = ok and last["rss_kb"] <= first["rss_kb"] * 1.05 and \
            last["fds_net"] - extra(last) <= (first["fds_net"] - extra(first)) * 1.05
    out["pass"] = ok
    print(json.dumps(out, indent=1))
    if a.json:
        with open(a.json, "w") as fh:
            json.dump(out, fh, indent=1)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
