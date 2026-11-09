#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

"""T452: one batch of the gate's 1-connection A/B (or A/A), with the machine state per sample.

A sample is what `measure.measure_ab` does: a fresh proxy, 5000 warm-up requests, `--n`
1-connection requests timed, then (with `--load`) 100000 requests on 50 connections. Next to
the requests/s it records, for the timed 1-connection phase:

  * `perf stat -e cycles,instructions,task-clock` on the proxy and on the backend for one
    second inside the phase (sudo -n, counting only): cycles / task-clock is the clock the
    process actually ran at;
  * the same counters per pinned CPU, system-wide (`-a -A -C`), for the same second;
  * cpuidle entries per state on the pinned CPUs (POLL, C1, C2), per request;
  * average scaling_cur_freq of the pinned CPUs (acpi-cpufreq's requested P-state);
  * busy% of CPUs 4-7 and 36-39 (the CCX of CPU 4: its L3 and SMT siblings) from /proc/stat;
  * where the llama-server thread ran (if one runs) and the load average.

One line of JSON per sample goes to `--out`. Run by tools/measure/t452_night.sh; read by
tools/measure/t452_report.py.
"""

import argparse
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import measure as m  # noqa: E402

TARGET = Path(os.environ.get("T452_TARGET")
              or Path(os.environ.get("ALCYON_TARGETS")
                      or Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache") / "alcyon" / "targets") / "t452")
EXTRA_BINS = Path(os.environ.get("T452_BINS", "/tmp/t452/bins"))
CCX = [4, 5, 6, 7, 36, 37, 38, 39]
PERF_LAUNCH_CPUS = "16-31"  # perf/sudo themselves run away from node0


def binaries():
    bins = {"cand": TARGET / "release" / "alcyon"}
    for p in (TARGET / "measure-ref").glob("alcyon-*"):
        bins[p.name[5:13]] = p
    if EXTRA_BINS.is_dir():
        for p in EXTRA_BINS.iterdir():
            bins[p.name] = p
    return bins


def idle(cpus):
    out = {}
    for c in cpus:
        d = f"/sys/devices/system/cpu/cpu{c}/cpuidle"
        n = len([s for s in os.listdir(d) if s.startswith("state")])
        out[c] = [int(open(f"{d}/state{s}/usage").read()) for s in range(n)]
    return out


def procstat():
    r = {}
    for line in open("/proc/stat"):
        if line.startswith("cpu") and line[3].isdigit():
            f = line.split()
            v = list(map(int, f[1:]))
            r[int(f[0][3:])] = (sum(v) - v[3] - v[4], sum(v))
    return r


class FreqSampler(threading.Thread):
    def __init__(self, cpus):
        super().__init__(daemon=True)
        self.cpus, self.s, self.stop = cpus, {c: [] for c in cpus}, False

    def run(self):
        while not self.stop:
            for c in self.cpus:
                with open(f"/sys/devices/system/cpu/cpu{c}/cpufreq/scaling_cur_freq") as f:
                    self.s[c].append(int(f.read()) // 1000)
            time.sleep(0.05)

    def summary(self):
        return {c: round(sum(v) / max(1, len(v))) for c, v in self.s.items()}


def llama_where():
    """(tid, CPU last run on, CPU ticks so far) of every llama-server thread."""
    res = subprocess.run(["pgrep", "-x", "llama-server"], capture_output=True, text=True)
    out = []
    for pid in res.stdout.split():
        try:
            for tid in os.listdir(f"/proc/{pid}/task"):
                f = open(f"/proc/{pid}/task/{tid}/stat").read().rsplit(")", 1)[1].split()
                out.append((tid, int(f[36]), int(f[11]) + int(f[12])))  # processor, utime+stime
        except OSError:
            pass
    return out


def perf_start(args):
    return subprocess.Popen(["taskset", "-c", PERF_LAUNCH_CPUS, "sudo", "-n", "perf", "stat", "-x,",
                             "-e", "cycles,instructions,task-clock"] + args + ["--", "sleep", "1"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)


def perf_parse(proc):
    """{cpu-or-'all': {event: value}} from `perf stat -x,` (with -A the first field is CPUn)."""
    try:
        err = proc.communicate(timeout=10)[1]
    except subprocess.TimeoutExpired:
        proc.kill()
        return {"error": "timeout"}
    out = {}
    for line in err.splitlines():
        f = line.split(",")
        if len(f) < 3:
            continue
        key = "all"
        if f[0].startswith("CPU"):
            key, f = f[0][3:], f[1:]
        try:
            val = float(f[0])
        except ValueError:
            continue
        ev = f[2].split(":")[0]
        out.setdefault(key, {})[ev] = val
    for key, v in out.items():
        if v.get("task-clock") and v.get("cycles"):
            # Per process: the clock while it ran. Per CPU (-a), task-clock is the wall
            # time, so this is cycles per wall second; divide by busy% for the clock.
            v["ghz" if key == "all" else "ghz_wall"] = round(v["cycles"] / (v["task-clock"] * 1e6), 3)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", required=True, help="the variable this batch tests")
    ap.add_argument("--bins", required=True, help="labels in order; two labels alternate ABBA")
    ap.add_argument("--rounds", type=int, default=16)
    ap.add_argument("--cpus", default="4;5;6", help="proxy;client;backend CPU lists")
    ap.add_argument("--wrap", default="", help="prefix for the three processes, e.g. 'numactl --membind=0'")
    ap.add_argument("--nbthread", type=int, default=1)
    ap.add_argument("--n", type=int, default=30000)
    ap.add_argument("--load", action="store_true", help="the gate's 50-connection phase after each sample")
    ap.add_argument("--no-perf", action="store_true")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    bins = binaries()
    labels = a.bins.split(",")
    for lab in labels:
        if lab not in bins:
            sys.exit(f"unknown binary {lab}; have {sorted(bins)}")
    groups = a.cpus.split(";")
    pinned = sorted({int(c) for g in groups for c in expand(g)})
    watch = sorted(set(CCX) | set(pinned))
    wrap = a.wrap.split() if a.wrap else []
    pin = lambda i: wrap + ["taskset", "-c", groups[i]]
    fe, be_port = m.get_free_port(), m.get_free_port()
    cfg = (f"global\n    nbthread {a.nbthread}\n"
           "defaults\n    mode http\n    timeout client 10s\n    timeout server 10s\n"
           f"    timeout connect 5s\nfrontend fe\n    bind 127.0.0.1:{fe}\n"
           f"    default_backend be\nbackend be\n    server s1 127.0.0.1:{be_port}\n")
    cfgp = f"/tmp/t452/cfg-{os.getpid()}.cfg"
    os.makedirs("/tmp/t452", exist_ok=True)
    with open(cfgp, "w") as f:
        f.write(cfg)
    bench = TARGET / "release" / "measure-bench"
    be = subprocess.Popen(pin(2) + [str(bench), "backend", str(be_port)],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    out = open(a.out, "a")
    try:
        m._wait_listening(be_port, be)
        for r in range(a.rounds):
            order = (labels if r % 2 == 0 else labels[::-1]) if len(labels) == 2 else labels
            for lab in order:
                proc = subprocess.Popen(pin(0) + [str(bins[lab]), "-f", cfgp],
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                try:
                    m._wait_listening(fe, proc)
                    addr = f"127.0.0.1:{fe}"
                    subprocess.run(pin(1) + [str(bench), "fixed", addr, "1", "5000"],
                                   capture_output=True, check=True)
                    fs = FreqSampler(pinned)
                    i0, p0, l0 = idle(pinned), procstat(), llama_where()
                    t0 = time.monotonic()
                    client = subprocess.Popen(pin(1) + [str(bench), "fixed", addr, "1", str(a.n)],
                                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    fs.start()
                    perfs = []
                    if not a.no_perf:
                        time.sleep(0.2)
                        perfs = [perf_start(["-p", str(proc.pid)]), perf_start(["-p", str(be.pid)]),
                                 perf_start(["-a", "-A", "-C", ",".join(map(str, pinned))])]
                    cout = client.communicate()[0]
                    wall = time.monotonic() - t0
                    i1, p1, l1 = idle(pinned), procstat(), llama_where()
                    fs.stop = True
                    fs.join()
                    done = re.search(r"completed:\s*(\d+)", cout)
                    if client.returncode != 0 or not done or int(done.group(1)) < a.n:
                        raise RuntimeError(f"client failed: {cout!r}")
                    perf = {}
                    if perfs:
                        perf = {"proxy": perf_parse(perfs[0]).get("all"),
                                "backend": perf_parse(perfs[1]).get("all"),
                                "cpus": {k: v for k, v in perf_parse(perfs[2]).items() if k != "all"}}
                        if wall < 1.25:
                            perf["short"] = True  # the perf second overran the phase
                    rec = {"tag": a.tag, "r": r, "bin": lab, "pos": order.index(lab),
                           "rps": int(a.n / wall), "wall": round(wall, 3),
                           "idle_per_req": {c: [round((i1[c][s] - i0[c][s]) / a.n, 3)
                                                for s in range(len(i1[c]))] for c in pinned},
                           "busy": {c: round(100 * (p1[c][0] - p0[c][0]) / max(1, p1[c][1] - p0[c][1]))
                                    for c in watch},
                           "freq_req": fs.summary(), "perf": perf,
                           # CPUs of the llama-server threads that ran during the phase
                           "llama_cpu": sorted({c for tid, c, t in l1
                                                if t > dict((x[0], x[2]) for x in l0).get(tid, t)}),
                           "llama_ticks": sum(t for _, _, t in l1) - sum(t for _, _, t in l0),
                           "load": open("/proc/loadavg").read().split()[0], "time": time.time(),
                           "cpus": a.cpus, "wrap": a.wrap, "nbthread": a.nbthread}
                    if a.load:
                        t1 = time.monotonic()
                        subprocess.run(pin(1) + [str(bench), "fixed", addr, "50", "100000"],
                                       capture_output=True, check=True)
                        rec["rps_50"] = int(100000 / (time.monotonic() - t1))
                    out.write(json.dumps(rec) + "\n")
                    out.flush()
                    g = perf.get("proxy") or {}
                    print(f"{a.tag} r{r} {lab:9} {rec['rps']:6} proxy {g.get('ghz', '-')} GHz "
                          f"C2/req {[v[-1] for v in rec['idle_per_req'].values()]} "
                          f"ccx busy {list(rec['busy'].values())}", flush=True)
                finally:
                    proc.send_signal(signal.SIGUSR1)
                    try:
                        proc.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait()
    finally:
        be.terminate()
        try:
            be.wait(timeout=2)
        except subprocess.TimeoutExpired:
            be.kill()
            be.wait()
        os.remove(cfgp)


def expand(spec):
    cpus = []
    for part in spec.split(","):
        lo, _, hi = part.partition("-")
        cpus.extend(range(int(lo), int(hi or lo) + 1))
    return cpus


if __name__ == "__main__":
    main()
