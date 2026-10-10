#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
"""Hostile-client battery orchestrator (runs on devtest7; see run.sh and README.md).

    battery.py run <proxy-binary> <label> <outdir> <seconds> [scenario...]
    battery.py table <outdir>            # markdown table from the result files

Per scenario: fresh haterm + fake backends + proxy, a legit haload at modest rate, the
attack for <seconds>, a 1 Hz sampler of the proxy's RSS/CPU/fds, then up to 45 s of
recovery polling.  One JSON file per (label, scenario) in <outdir>.
"""
import glob, json, os, re, signal, subprocess, sys, threading, time, urllib.request

D = os.path.dirname(os.path.abspath(__file__))
HATERM, HALOAD = "/root/ibex-test/haterm", "/root/ibex-test/haload"
H1, H2 = 10080, 10081
# name: (attack processes [(client scenario, port, workers)], legit protocol)
SCEN = {
    "slowloris":      ([("slowloris", H1, 0)], "h1"),
    "slow_post":      ([("slow_post", H1, 0)], "h1"),
    "nonreader":      ([("nonreader", H1, 0)], "h1"),
    "h2_rapid_reset": ([("h2_rapid_reset", H2, 4)], "h2c"),
    "h2_flood":       ([("h2_flood", H2, 8)], "h2c"),
    "h2_window0":     ([("h2_window0", H2, 0)], "h2c"),
    "hdr_storm":      ([("hdr_storm", H1, 0), ("hdr_storm_h2", H2, 0)], "h1"),
    "churn":          ([("churn", H1, 0)], "h1"),
    "be_hang":        ([("be_hang", H1, 0)], "h1"),
    "be_drip":        ([("be_drip", H1, 0)], "h1"),
    "be_reset":       ([("be_reset", H1, 0)], "h1"),
}
CFG = """global
    nbthread 4
    maxconn 2000
    stats socket {run}/stats.sock mode 666 level admin
defaults
    mode http
    timeout connect 5s
    timeout client 30s
    timeout server 30s
    timeout http-request 5s
frontend f
    bind 127.0.0.1:{h1}
    bind 127.0.0.1:{h2} proto h2
    use_backend hang if {{ path_beg /hang }}
    use_backend drip if {{ path_beg /drip }}
    use_backend reset if {{ path_beg /reset }}
    default_backend b
backend b
    server s1 127.0.0.1:8888
backend hang
    server s1 127.0.0.1:9001
backend drip
    server s1 127.0.0.1:9002
backend reset
    server s1 127.0.0.1:9003
"""
TICK = os.sysconf("SC_CLK_TCK")


def spawn(cmd, cpus, log=None, **kw):
    return subprocess.Popen(["taskset", "-c", cpus] + cmd, stdout=log, stderr=subprocess.STDOUT,
                            preexec_fn=lambda: os.setsid(), **kw)


def stop(p):
    if p and p.poll() is None:
        try: os.killpg(p.pid, signal.SIGTERM)
        except OSError: pass
        try: p.wait(10)
        except subprocess.TimeoutExpired:
            os.killpg(p.pid, signal.SIGKILL); p.wait()


def stat(pid):
    try:
        rss = int(re.search(r"VmRSS:\s+(\d+)", open(f"/proc/{pid}/status").read()).group(1))
        f = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()
        return rss, (int(f[11]) + int(f[12])) / TICK, len(os.listdir(f"/proc/{pid}/fd"))
    except (OSError, AttributeError):
        return None


def probe(port, h2):
    cmd = ["curl", "-s", "-o", "/dev/null", "--max-time", "3", "-w", "%{http_code}"]
    if h2: cmd.append("--http2-prior-knowledge")
    r = subprocess.run(cmd + [f"http://127.0.0.1:{port}/?s=1k"], capture_output=True, text=True)
    return r.stdout.strip() == "200"


def wait_port(port):
    for _ in range(100):
        if subprocess.run(["curl", "-s", "-o", "/dev/null", f"http://127.0.0.1:{port}/"]).returncode in (0, 22, 52, 56):
            return
        time.sleep(0.1)


def parse_haload(text):
    rows = [l.split() for l in text.splitlines() if re.match(r"\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s", l)]
    err = max([int(r[5]) for r in rows] or [0])
    ok = sum(int(r[11]) for r in rows)
    bad = sum(int(r[13]) + int(r[14]) for r in rows)
    p99 = None
    for l in text.splitlines():
        m = re.match(r"(99(?:\.\d+)?)\s+[\d.]+\s+\d+\s+\d+\s+[\d.]+\s+\d+\s+([\d.]+)$", l)
        if m and float(m.group(1)) >= 99:
            p99 = float(m.group(2)); break
    return dict(legit_ok=ok, legit_bad=bad, legit_err=err, legit_p99_ms=p99)


def run_one(binary, label, outdir, secs, name):
    run = f"/tmp/battery-{label}-{name}"
    subprocess.run(["rm", "-rf", run]); os.makedirs(run)
    open(f"{run}/proxy.cfg", "w").write(CFG.format(run=run, h1=H1, h2=H2))
    procs = []
    try:
        procs.append(spawn([HATERM, "-L", "127.0.0.1:8888", "-G", "nbthread 8"], "16-31", open(f"{run}/haterm.log", "w")))
        for kind, port in (("hang", 9001), ("drip", 9002), ("reset", 9003)):
            procs.append(spawn([sys.executable, f"{D}/clients.py", "backend", kind, str(port), str(secs + 120)], "36-39"))
        proxy = spawn([binary, "-f", f"{run}/proxy.cfg"], "0-3", open(f"{run}/proxy.log", "w"))
        wait_port(H1); time.sleep(0.5)
        pid = proxy.pid
        base = stat(pid) or (0, 0, 0)
        res = dict(label=label, scenario=name, secs=secs, base_rss=base[0], base_fds=base[2])
        samples = []; stopflag = []
        def sampler():
            last = stat(pid)
            while not stopflag:
                time.sleep(1); s = stat(pid)
                if s is None: samples.append(None); return
                samples.append((s[0], (s[1] - last[1]) * 100, s[2])); last = s
        th = threading.Thread(target=sampler); th.start()
        attacks, proto = SCEN[name]
        lport, lopt = (H2, "-h2c") if proto == "h2c" else (H1, "-h1")
        legit = spawn([HALOAD, "-t", "2", "-u", "4", "-R", "50", "-d", str(secs), "-hs", "-P", lopt,
                       f"http://127.0.0.1:{lport}/?s=1k"], "32-35", subprocess.PIPE)
        time.sleep(3)  # let the legit load establish itself before the attack starts
        t0 = time.time()
        aps = [spawn([sys.executable, f"{D}/clients.py", "attack", a, "127.0.0.1", str(port), str(max(secs - 3, 1)), str(n)],
                     "40-47", open(f"{run}/attack-{a}.log", "w")) for a, port, n in attacks]
        mid = []
        while time.time() - t0 < secs - 3:
            time.sleep(10)  # mid-attack probe: can a new client get served at all
            mid.append(probe(lport, proto == "h2c"))
        for a in aps: stop(a)
        out = legit.communicate(timeout=60)[0].decode(errors="replace")
        open(f"{run}/haload.out", "w").write(out)
        res.update(parse_haload(out))
        res["mid_probe_ok"] = f"{sum(mid)}/{len(mid)}"
        # recovery: attack is over; a probe works on both binds and fds are back near the baseline
        t1 = time.time(); rec = None
        while time.time() - t1 < 45:
            s = stat(pid)
            if s is None: break
            if probe(H1, False) and probe(H2, True) and s[2] <= base[2] + 30:
                rec = round(time.time() - t1, 1); break
            time.sleep(1)
        stopflag.append(1); th.join()
        alive = proxy.poll() is None
        end = stat(pid) if alive else None
        live = [s for s in samples if s]
        res.update(alive=alive, recovered=rec is not None and alive, recover_s=rec,
                   peak_rss_kb=max([s[0] for s in live] or [0]), end_rss_kb=end[0] if end else None,
                   cpu_avg_pct=round(sum(s[1] for s in live[:secs]) / max(len(live[:secs]), 1)),
                   cpu_peak_pct=round(max([s[1] for s in live] or [0])),
                   peak_fds=max([s[2] for s in live] or [0]), end_fds=end[2] if end else None,
                   exit=proxy.returncode)
        res["panics"] = len(re.findall(r"panic|SIGSEGV|abort", open(f"{run}/proxy.log").read(), re.I))
        json.dump(res, open(f"{outdir}/{label}-{name}.json", "w"))
        print(json.dumps(res), flush=True)
        stop(proxy)
    finally:
        for p in procs: stop(p)


def table(outdir):
    rows = {}
    for f in glob.glob(f"{outdir}/*.json"):
        r = json.load(open(f)); rows.setdefault(r["scenario"], {})[r["label"]] = r
    def cell(r):
        if not r: return "-"
        rss = lambda k: f"{(r[k] or 0) / 1024:.0f}M"
        p99 = "-" if r["legit_p99_ms"] is None else f"{r['legit_p99_ms']:.1f}ms"
        return (f"RSS {rss('peak_rss_kb')}->{rss('end_rss_kb')}, cpu {r['cpu_avg_pct']}%/{r['cpu_peak_pct']}%, "
                f"fds {r['peak_fds']}->{r['end_fds']}, p99 {p99}, ok {r['legit_ok']} bad {r['legit_bad']} err {r['legit_err']}, "
                f"mid {r['mid_probe_ok']}, recovered {'y' if r['recovered'] else 'N'}"
                + (f" ({r['recover_s']}s)" if r["recover_s"] is not None else "")
                + ("" if r["alive"] else " DEAD") + (f" panics {r['panics']}" if r["panics"] else ""))
    labels = sorted({l for v in rows.values() for l in v})
    print("| scenario | " + " | ".join(labels) + " |\n|---|" + "---|" * len(labels))
    for s in SCEN:
        if s in rows: print(f"| {s} | " + " | ".join(cell(rows[s].get(l)) for l in labels) + " |")


if __name__ == "__main__":
    if sys.argv[1] == "table":
        table(sys.argv[2])
    else:
        binary, label, outdir, secs = sys.argv[2], sys.argv[3], sys.argv[4], int(sys.argv[5])
        os.makedirs(outdir, exist_ok=True)
        os.system("ulimit -n 100000")
        import resource; resource.setrlimit(resource.RLIMIT_NOFILE, (100000, 100000))
        for n in (sys.argv[6:] or list(SCEN)):
            run_one(binary, label, outdir, secs, n)
