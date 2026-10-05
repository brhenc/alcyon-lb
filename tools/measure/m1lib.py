# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
"""Shared helpers for the tools/measure/m1_*.py scripts (T180).

Binaries come from the environment: IBEX (default $CARGO_TARGET_DIR/release/ibex),
HAPROXY (default /home/bhenc/reference/haproxy/haproxy). Every script runs both proxies
on the same generated config, with one HAProxy as the shared origin server.
"""
import json
import os
import resource
import select
import signal
import socket
import statistics
import subprocess
import time
import multiprocessing as mp

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
IBEX = os.environ.get("IBEX", os.path.join(os.environ.get("CARGO_TARGET_DIR", os.path.join(ROOT, "target")), "release", "ibex"))
HAPROXY = os.environ.get("HAPROXY", "/home/bhenc/reference/haproxy/haproxy")
ORIGIN_HAPROXY = os.environ.get("ORIGIN_HAPROXY", HAPROXY)
RUNS = int(os.environ.get("RUNS", "3"))
TICK = os.sysconf("SC_CLK_TCK")
TMP = os.environ.get("M1_TMP", os.path.expanduser("~/ibex-targets/t180/tmp"))  # never /tmp (RAM)
os.makedirs(TMP, exist_ok=True)


def raise_nofile():
    """Raise RLIMIT_NOFILE soft to the hard limit; return the resulting soft limit."""
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    try:
        resource.setrlimit(resource.RLIMIT_NOFILE, (hard, hard))
    except (ValueError, OSError):
        pass
    return resource.getrlimit(resource.RLIMIT_NOFILE)[0]


def wait_load(limit=8.0, patience=300):
    """Wait up to `patience` s for the 1-minute load average to fall under `limit`."""
    end = time.time() + patience
    while os.getloadavg()[0] > limit and time.time() < end:
        time.sleep(10)
    return os.getloadavg()[0]


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def write_file(name, text):
    path = os.path.join(TMP, name)
    with open(path, "w") as f:
        f.write(text)
    return path


def wait_listen(proc, port, timeout=120):
    """Poll every ms until a connection to `port` is accepted; return that time."""
    end = time.time() + timeout
    while True:
        if proc.poll() is not None:
            raise RuntimeError(f"exited {proc.returncode} before listening on {port}")
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            return time.time()
        except OSError:
            if time.time() > end:
                raise RuntimeError(f"nothing listening on {port}")
            time.sleep(0.001)


def stop(proc):
    for sig in (signal.SIGTERM, signal.SIGKILL):
        if proc.poll() is not None:
            return
        proc.send_signal(sig)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass


def start(kind, cfg_path, port, wait=True):
    """kind: 'ibex' or 'haproxy'. Returns Popen."""
    cmd = [IBEX, "-f", cfg_path] if kind == "ibex" else [HAPROXY, "-db", "-f", cfg_path]
    p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if wait:
        wait_listen(p, port)
    return p


# --- origin server: a HAProxy answering from `http-request return` -------------------
def start_origin():
    """Returns (proc, port). Paths: /small (2 bytes), /64k, /1m."""
    for name, n in (("body64k", 65536), ("body1m", 1 << 20)):
        with open(os.path.join(TMP, name), "wb") as f:
            f.write(b"x" * n)
    port = free_port()
    cfg = f"""global
    nbthread 4
    maxconn 100000
    tune.bufsize 1179648
defaults
    mode http
    timeout connect 5s
    timeout client 300s
    timeout server 300s
frontend o
    bind 127.0.0.1:{port}
    http-request return status 200 content-type application/octet-stream file {TMP}/body64k if {{ path /64k }}
    http-request return status 200 content-type application/octet-stream file {TMP}/body1m if {{ path /1m }}
    http-request return status 200 content-type text/plain string ok
"""
    p = subprocess.Popen([ORIGIN_HAPROXY, "-db", "-f", write_file("origin.cfg", cfg)],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    wait_listen(p, port)
    return p, port


def proxy_cfg(port, origin_port, nbthread=1, maxconn=100000, bind_extra=""):
    return f"""global
    nbthread {nbthread}
    maxconn {maxconn}
defaults
    mode http
    timeout connect 5s
    timeout client 300s
    timeout server 300s
frontend fe
    maxconn {maxconn}
    bind 127.0.0.1:{port} {bind_extra}
    default_backend be
backend be
    server o 127.0.0.1:{origin_port}
"""


def make_cert():
    """ECDSA P-256 self-signed PEM (key+cert in one file) for TLS tests."""
    pem = os.path.join(TMP, "m1.pem")
    if not os.path.exists(pem):
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                        "-nodes", "-days", "30", "-subj", "/CN=localhost", "-keyout", pem, "-out", pem],
                       check=True, stderr=subprocess.DEVNULL)
    return pem


# --- /proc readers -------------------------------------------------------------------
def rss_kb(pid):
    with open(f"/proc/{pid}/status") as f:
        for line in f:
            if line.startswith("VmRSS:"):
                return int(line.split()[1])


def cpu_s(pid):
    with open(f"/proc/{pid}/stat") as f:
        parts = f.read().rsplit(")", 1)[1].split()
    return (int(parts[11]) + int(parts[12])) / TICK


def nfds(pid):
    return len(os.listdir(f"/proc/{pid}/fd"))


# --- load generator (stands in for wrk / wrk2: neither is installed) ------------------
def _worker(port, path, nconn, dur, warm, rate, q):
    """Closed-loop (rate None) or open-loop constant-rate HTTP/1.1 keep-alive client.
    Latency of an open-loop request is measured from its scheduled send time."""
    req = f"GET {path} HTTP/1.1\r\nHost: m1\r\n\r\n".encode()
    ep = select.epoll()
    conns = {}
    interval = (nconn / rate) if rate else 0.0
    now = time.perf_counter()
    for i in range(nconn):
        s = socket.create_connection(("127.0.0.1", port))
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.setblocking(False)
        ep.register(s.fileno(), select.EPOLLIN)
        # state: sock, buf, remaining (None = header incomplete), t0, busy, next scheduled send
        conns[s.fileno()] = [s, b"", None, 0.0, False, time.perf_counter() + 0.2 + interval * i / nconn]
    t_meas = time.perf_counter() + 0.2 + warm
    t_end = t_meas + dur
    lat = []
    done = 0

    def send(c, t):
        c[3] = t
        c[4] = True
        c[1] = b""
        c[2] = None
        c[0].setblocking(True)
        c[0].send(req)
        c[0].setblocking(False)

    if not rate:
        for c in conns.values():
            send(c, time.perf_counter())
    while True:
        now = time.perf_counter()
        if now >= t_end:
            break
        if rate:
            nxt = t_end
            for c in conns.values():
                if not c[4]:
                    if c[5] <= now:
                        send(c, c[5])
                        c[5] += interval
                    else:
                        nxt = min(nxt, c[5])
            timeout = max(0.0, min(nxt, t_end) - time.perf_counter())
        else:
            timeout = t_end - now
        for fd, _ in ep.poll(timeout):
            c = conns[fd]
            try:
                data = c[0].recv(262144)
            except BlockingIOError:
                continue
            if not data:
                raise RuntimeError("connection closed by proxy")
            if c[2] is None:
                c[1] += data
                he = c[1].find(b"\r\n\r\n")
                if he < 0:
                    continue
                head = c[1][:he].lower()
                i = head.find(b"content-length:")
                cl = int(head[i + 15:].split(b"\r\n")[0]) if i >= 0 else 0
                c[2] = cl - (len(c[1]) - he - 4)
            else:
                c[2] -= len(data)
            if c[2] <= 0:
                t = time.perf_counter()
                c[4] = False
                if t >= t_meas:
                    done += 1
                    lat.append(t - c[3])
                if not rate:
                    send(c, time.perf_counter())
    q.put((done, lat))


def load(port, path, conns, dur=5.0, warm=1.0, rate=None, procs=None):
    """Returns dict(rps, p50_us, p99_us). `rate` is total requests/s (open loop)."""
    procs = procs or min(conns, int(os.environ.get("LOAD_PROCS", "12")))
    q = mp.Queue()
    ps = []
    for i in range(procs):
        n = conns // procs + (1 if i < conns % procs else 0)
        p = mp.Process(target=_worker, args=(port, path, n, dur, warm, (rate * n / conns) if rate else None, q))
        p.start()
        ps.append(p)
    done, lat = 0, []
    for _ in ps:
        d, l = q.get()
        done += d
        lat += l
    for p in ps:
        p.join()
    lat.sort()
    pick = lambda f: lat[min(len(lat) - 1, int(len(lat) * f))] * 1e6 if lat else float("nan")
    return {"rps": done / dur, "p50_us": pick(0.50), "p99_us": pick(0.99)}


def median_of(fn, runs=None):
    """Run fn() RUNS times (each returns a dict of numbers); per-key median, and all runs."""
    rs = [fn() for _ in range(runs or RUNS)]
    return {k: statistics.median(r[k] for r in rs) for k in rs[0]}, rs


def header(script):
    la = os.getloadavg()
    return (f"# {script} date={time.strftime('%F %T')} load={la[0]:.1f} {la[1]:.1f} {la[2]:.1f} "
            f"nofile={raise_nofile()} runs={RUNS} ibex={IBEX} haproxy={HAPROXY}")


def emit(**row):
    print("RESULT " + json.dumps(row), flush=True)
