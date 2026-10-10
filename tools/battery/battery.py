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
H1, H2, TLS = 10080, 10081, 10443
CRT = os.environ.get("BATTERY_CRT", "/root/ibex-test/lab.pem")  # TLS bind only if this exists
# name: (attack processes, legit protocol).  An attack process is either
#   (client scenario, port, workers)            -> clients.py attack ... (one Python process)
#   ("haload", port, scheme, [haload args])     -> haload as a rate-capped flood engine (-R)
# legit protocol: h1 / h2c (clear) / h1s / h2s (over the TLS bind).
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
HL = lambda port, scheme, *a: ("haload", port, scheme, list(a))
# protocol-spam scenarios (red team, 2026-10-11); rates are caps, see README
SCEN.update({
    "hoic_h1_ka":        ([HL(H1, "http", "-h1", "-t", "4", "-u", "200", "-R", "20000")], "h1"),
    "hoic_h1_conn":      ([HL(H1, "http", "-h1", "-t", "4", "-u", "200", "-r", "1", "-R", "5000")], "h1"),
    "hoic_h2":           ([HL(H2, "http", "-h2c", "-t", "4", "-u", "50", "-m", "50", "-R", "20000")], "h2c"),
    "hoic_rand":         ([("hoic_rand", H1, 32)] * 4, "h1"),
    "h1_pipeline":       ([("h1_pipeline", H1, 32)] * 2, "h1"),
    "h1_range":          ([("h1_range", H1, 64)], "h1"),
    "h2_continuation":   ([("h2_continuation", H2, 16)] * 2, "h2c"),
    "h2_cont_drip":      ([("h2_cont_drip", H2, 400)], "h2c"),
    "h2_hpack_bomb":     ([("h2_hpack_bomb", H2, 16)] * 2, "h2c"),
    "h2_madeyoureset":   ([("h2_madeyoureset", H2, 4)], "h2c"),
    "h2_priority_flood": ([("h2_priority_flood", H2, 8)], "h2c"),
    "h2_empty_data":     ([("h2_empty_data", H2, 8)], "h2c"),
    "h2_wu_storm":       ([("h2_wu_storm", H2, 8)], "h2c"),
    "h2_streams":        ([("h2_streams", H2, 200)], "h2c"),
    "h2_preface_idle":   ([("h2_preface_idle", H2, 3000)], "h2c"),
    "tls_hs_full":       ([HL(TLS, "https", "-h1", "-t", "4", "-u", "200", "-r", "1", "-R", "2000", "--server", "no-ssl-reuse")], "h2s"),
    "tls_hs_resume":     ([HL(TLS, "https", "-h1", "-t", "4", "-u", "200", "-r", "1", "-R", "4000")], "h2s"),
    "tls_hello_only":    ([("tls_hello_only", TLS, 2500)], "h2s"),
    "tls_reneg":         ([("tls_reneg", TLS, 50)], "h2s"),
    "maxconn_full":      ([("maxconn_full", H1, 2500)], "h1"),
    "mixed":             ([("slowloris", H1, 1000), ("h2_rapid_reset", H2, 2),
                           HL(H1, "http", "-h1", "-t", "2", "-u", "100", "-R", "5000"),
                           HL(TLS, "https", "-h1", "-t", "2", "-u", "50", "-r", "1", "-R", "500", "--server", "no-ssl-reuse")], "h1"),
})
LEGIT = {"h1": (H1, "-h1", "http"), "h2c": (H2, "-h2c", "http"), "h1s": (TLS, "-h1", "https"), "h2s": (TLS, "-h2", "https")}
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
{tlsbind}    use_backend hang if {{ path_beg /hang }}
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


def probe(port, h2, tls=False, detail=False):
    cmd = ["curl", "-s", "-k", "-o", "/dev/null", "--max-time", "3", "-w", "%{http_code}"]
    if h2: cmd.append("--http2" if tls else "--http2-prior-knowledge")
    r = subprocess.run(cmd + [f"{'https' if tls else 'http'}://127.0.0.1:{port}/?s=1k"], capture_output=True, text=True)
    ok = r.stdout.strip() == "200"
    return (ok, r.stdout.strip() if r.returncode == 0 else f"curl{r.returncode}") if detail else ok


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
    tot_req = max([int(r[3]) for r in rows] or [0]); tot_bytes = max([int(r[4]) for r in rows] or [0])
    tot_conn = max([int(r[2]) for r in rows] or [0])
    p99 = None
    for l in text.splitlines():
        m = re.match(r"(99(?:\.\d+)?)\s+[\d.]+\s+\d+\s+\d+\s+[\d.]+\s+\d+\s+([\d.]+)$", l)
        if m and float(m.group(1)) >= 99:
            p99 = float(m.group(2)); break
    return dict(legit_ok=ok, legit_bad=bad, legit_err=err, legit_p99_ms=p99, tot_req=tot_req, tot_bytes=tot_bytes,
                tot_conn=tot_conn, secs=len(rows))


def haterm_cli(run, cmd):
    import socket as so
    c = so.socket(so.AF_UNIX); c.settimeout(2); c.connect(f"{run}/haterm.sock"); c.sendall(cmd + b"\n")
    buf = b""
    while True:
        d = c.recv(65536)
        if not d: break
        buf += d
    c.close()
    return buf.decode(errors="replace")


def haterm_counters(run):
    """Backend-side counters from haterm's stats socket (haterm is HAProxy code): connections
    accepted (show info CumConns) and requests / 2xx answered summed over its frontends (show stat)."""
    try:
        info = {k: int(v) for k, v in re.findall(r"^(CumConns|CurrConns): (\d+)", haterm_cli(run, b"show info"), re.M)}
        lines = [l.split(",") for l in haterm_cli(run, b"show stat").splitlines() if l and not l.startswith("#")]
        hdr = haterm_cli(run, b"show stat").splitlines()[0].lstrip("# ").split(",")
        ix = {k: hdr.index(k) for k in ("type", "req_tot", "hrsp_2xx", "hrsp_4xx", "hrsp_5xx") if k in hdr}
        for k in ("req_tot", "hrsp_2xx", "hrsp_4xx", "hrsp_5xx"):
            info[k] = sum(int(l[ix[k]] or 0) for l in lines if k in ix and len(l) > ix[k] and l[ix["type"]] == "0")
        return info
    except (OSError, ValueError, IndexError):
        return {}


def attack_counters(run, attacks):
    """Attacker-side totals: haload's own per-second counters, or the SUMMARY line of clients.py."""
    tot = dict(att_reqs=0, att_resps_2xx=0, att_resps_4xx5xx=0, att_errs=0, att_conns=0, att_bytes_sent=0, att_bytes_recv=0)
    for k, a in enumerate(attacks):
        if a[0] == "haload":
            h = parse_haload(open(f"{run}/attack-{k}-haload.log").read())
            tot["att_reqs"] += h["tot_req"]; tot["att_resps_2xx"] += h["legit_ok"]; tot["att_resps_4xx5xx"] += h["legit_bad"]
            tot["att_errs"] += h["legit_err"]; tot["att_bytes_recv"] += h["tot_bytes"]; tot["att_conns"] += h["tot_conn"]
        else:
            for l in open(f"{run}/attack-{k}-{a[0]}.log"):
                if l.startswith("SUMMARY "):
                    c = json.loads(l[8:])
                    tot["att_reqs"] += c["reqs"]; tot["att_resps_2xx"] += c["resps"]; tot["att_errs"] += c["errs"]
                    tot["att_conns"] += c["conns"]; tot["att_bytes_sent"] += c["bytes_sent"]
    return tot


def run_one(binary, label, outdir, secs, name):
    run = f"/tmp/battery-{label}-{name}"
    subprocess.run(["rm", "-rf", run]); os.makedirs(run)
    tlsbind = f"    bind 127.0.0.1:{TLS} ssl crt {CRT} alpn h2,http/1.1\n" if os.path.exists(CRT) else ""
    open(f"{run}/proxy.cfg", "w").write(CFG.format(run=run, h1=H1, h2=H2, tlsbind=tlsbind))
    procs = []
    try:
        procs.append(spawn([HATERM, "-L", "127.0.0.1:8888", "-G", "nbthread 8", "-G", f"stats socket {run}/haterm.sock mode 666"],
                           "16-31", open(f"{run}/haterm.log", "w")))
        for kind, port in (("hang", 9001), ("drip", 9002), ("reset", 9003)):
            procs.append(spawn([sys.executable, f"{D}/clients.py", "backend", kind, str(port), str(secs + 120)], "36-39"))
        proxy = spawn([binary, "-f", f"{run}/proxy.cfg"], "0-3", open(f"{run}/proxy.log", "w"))
        wait_port(H1); time.sleep(0.5)
        pid = proxy.pid
        base = stat(pid) or (0, 0, 0)
        ver = subprocess.run([binary, "-v"], capture_output=True, text=True).stdout.splitlines()
        res = dict(label=label, scenario=name, secs=secs, base_rss=base[0], base_fds=base[2], version=ver[0] if ver else "")
        samples = []; stopflag = []
        def sampler():
            last = stat(pid)
            while not stopflag:
                time.sleep(1); s = stat(pid)
                if s is None: samples.append(None); return
                samples.append((s[0], (s[1] - last[1]) * 100, s[2])); last = s
        th = threading.Thread(target=sampler); th.start()
        attacks, proto = SCEN[name]
        lport, lopt, lscheme = LEGIT[proto]
        ltls = lscheme == "https"
        legit = spawn([HALOAD, "-t", "2", "-u", "4", "-R", "50", "-d", str(secs), "-hs", "-P", lopt,
                       f"{lscheme}://127.0.0.1:{lport}/?s=1k"], "32-35", subprocess.PIPE)
        time.sleep(3)  # let the legit load establish itself before the attack starts
        ht0 = haterm_counters(run)
        t0 = time.time()
        aps = []
        for k, a in enumerate(attacks):
            if a[0] == "haload":
                _, port, scheme, args = a
                cmd = [HALOAD, "-d", str(max(secs - 3, 1)), "-hs"] + args + [f"{scheme}://127.0.0.1:{port}/?s=1k"]
                aps.append(spawn(cmd, "40-47", open(f"{run}/attack-{k}-haload.log", "w")))
            else:
                sc, port, n = a
                aps.append(spawn([sys.executable, f"{D}/clients.py", "attack", sc, "127.0.0.1", str(port), str(max(secs - 3, 1)), str(n)],
                                 "40-47", open(f"{run}/attack-{k}-{sc}.log", "w")))
        mid = []; mid_detail = []
        while time.time() - t0 < secs - 3:
            time.sleep(10)  # mid-attack probe: can a new client get served at all
            ok, det = probe(lport, proto in ("h2c", "h2s"), ltls, detail=True)
            mid.append(ok); mid_detail.append(det)
        for a in aps:
            try: a.wait(15)  # let the attack tools print their summaries
            except subprocess.TimeoutExpired: stop(a)
        ht1 = haterm_counters(run)
        out = legit.communicate(timeout=60)[0].decode(errors="replace")
        open(f"{run}/haload.out", "w").write(out)
        lg = parse_haload(out)
        for k in ("secs", "tot_req", "tot_bytes", "tot_conn"): lg.pop(k, None)
        res.update(lg)
        res.update(attack_counters(run, attacks))
        for k, src in (("backend_reqs", "req_tot"), ("backend_2xx", "hrsp_2xx"), ("backend_conns", "CumConns")):
            res[k] = (ht1.get(src, 0) - ht0.get(src, 0)) if ht0 and ht1 and src in ht1 else None
        res["mid_probe_ok"] = f"{sum(mid)}/{len(mid)}"
        res["mid_probe_detail"] = mid_detail
        # recovery: attack is over; a probe works on both binds and fds are back near the baseline
        t1 = time.time(); rec = None
        while time.time() - t1 < int(os.environ.get("RECOVER_MAX", 45)):
            s = stat(pid)
            if s is None: break
            if probe(H1, False) and probe(H2, True) and (not tlsbind or probe(TLS, True, True)) and s[2] <= base[2] + 30:
                rec = round(time.time() - t1, 1); break
            time.sleep(1)
        stopflag.append(1); th.join()
        alive = proxy.poll() is None
        end = stat(pid) if alive else None
        live = [s for s in samples if s]
        res.update(alive=alive, recovered=rec is not None and alive, recover_s=rec,
                   peak_rss_kb=max([s[0] for s in live] or [0]), end_rss_kb=end[0] if end else None,
                   cpu_avg_pct=round(sum(s[1] for s in live[:secs]) / max(len(live[:secs]), 1)),
                   cpu_s=round(sum(s[1] for s in live[:secs]) / 100, 1),
                   cpu_peak_pct=round(max([s[1] for s in live] or [0])),
                   peak_fds=max([s[2] for s in live] or [0]), end_fds=end[2] if end else None,
                   cpu_series=[round(s[1]) for s in live], fds_series=[s[2] for s in live], rss_series=[s[0] // 1024 for s in live],
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
