#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
"""Run-time DNS resolution, Ibex vs HAProxy (rc4, T483/T484). Functional only: no timing claims.

dns_battery.py IBEX [HAPROXY] [-k name,name] [-o OUTDIR] [-p OFFSET]

Each case is one config plus a timeline of zone changes. Both proxies run it in turn against the same
scripted nameservers (vvdns.py: ns1 127.0.0.1:19953, ns2 :19954, a dead one at :19959). The battery
samples `show servers state` every 0.25 s and prints, per proxy:
  start     started / the first ALERT line if the config was refused
  states    each change of (srv_addr, srv_op_state, srv_admin_state) with its time from start
  log       the proxy's lines about the server (timestamps and pids removed)
  dns       queries seen by the nameservers: count per type, EDNS sizes, ids (random? reused on retries?)
  http      for traffic cases: which backend address answered each request on one keep-alive connection
  alive     whether the process was still running at the end (a crash is a finding whatever HAProxy does)
SAME/DIFF compares start, the state sequence (times ignored), the log lines and http; "<-- t" flags a
state reached more than 1 s apart. Ports: proxy 19970, backends 127.0.0.1:19971 and 127.0.0.2:19971.
-p OFFSET (or VV_DNS_PORT_OFFSET) adds OFFSET to every port, and the default OUTDIR becomes
/tmp/vv-dns-pOFFSET, so two runs with different offsets do not share ports or the stats socket.
Expected differences, from docs/design/dns-2026-10-25.md §2.7/§2.8, are tagged in the case's note.
"""
import json, os, re, shutil, signal, socket, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
args = [a for a in sys.argv[1:]]
only, out = None, None
off = int(os.environ.get("VV_DNS_PORT_OFFSET", "0"))
if "-k" in args:
    i = args.index("-k"); only = set(args[i + 1].split(",")); del args[i:i + 2]
if "-o" in args:
    i = args.index("-o"); out = args[i + 1]; del args[i:i + 2]
if "-p" in args:
    i = args.index("-p"); off = int(args[i + 1]); del args[i:i + 2]
if out is None:
    out = "/tmp/vv-dns" if off == 0 else "/tmp/vv-dns-p%d" % off
IB = args[0]
HA = args[1] if len(args) > 1 else "/home/bhenc/reference/haproxy/haproxy"
P, NS1, NS2, DEAD, BE = (x + off for x in (19970, 19953, 19954, 19959, 19971))
SOCK = os.path.join(out, "cli.sock")
for b in (IB, HA):
    if not os.access(b, os.X_OK):
        sys.exit("not an executable: %s" % b)
os.makedirs(out, exist_ok=True)

RS = "resolvers r\n    nameserver ns1 127.0.0.1:%d\n" % NS1
RS2 = RS + "    nameserver ns2 127.0.0.1:%d\n" % NS2
def cfg(resolvers, servers, extra_be="", glob=""):
    return ("global\n    log stdout format raw local0\n    stats socket %s level admin\n%s"
            "%s"
            "defaults\n    mode http\n    log global\n    timeout connect 1s\n    timeout client 5s\n"
            "    timeout server 5s\n"
            "listen l\n    bind 127.0.0.1:%d\n%s%s") % (SOCK, glob, resolvers, P, extra_be, servers)

A1 = {"a": ["10.0.0.1"], "ttl": 300}
BASE = {"a1.test": A1, "a2.test": {"a": ["10.0.0.2"]}, "be.test": {"a": ["127.0.0.1"]},
        "multi.test": {"a": ["10.0.0.1", "10.0.0.2", "10.0.0.3"]},
        "both.test": {"a": ["10.0.0.1"], "aaaa": ["2001:db8::1"]},
        "v6only.test": {"aaaa": ["2001:db8::6"]},
        "cname.test": {"cname": "a1.test"}, "dangling.test": {"cname": "nowhere.test"}}
def z(**over):
    d = json.loads(json.dumps(BASE))
    for k, v in over.items():
        d[k.replace("_", ".")] = v
    return d

S1 = "    server s1 a1.test:80 resolvers r\n"
# name, config, ns1 zone at start, timeline [(t, "ns1"|"ns2", zone)], seconds, flags, note
CASES = [
 # --- start-up (T483): libc, init-addr
 ("start-localhost", cfg("", "    server s1 localhost:%d\n" % BE), z(), [], 1.5, "", "A.t1f: HAProxy ::1 (libc prefers v6)"),
 ("start-libc-fail", cfg("", "    server s1 nosuch.invalid:80\n"), z(), [], 1.5, "", "A.t0: fatal"),
 ("start-libc-none", cfg("", "    server s1 nosuch.invalid:80 init-addr libc,none\n"), z(), [], 1.5, "", "A.t1e: RMAINT forever"),
 ("start-init-ip", cfg("", "    server s1 nosuch.invalid:80 init-addr 10.9.9.9\n"), z(), [], 1.5, "", ""),
 ("start-init-last", cfg("", "    server s1 nosuch.invalid:80 init-addr last,libc,none\n"), z(), [], 1.5, "",
  "expected DIFF: Ibex refuses `last` until T490 (design §2.8.3)"),
 ("start-resolvers-libc", cfg(RS, "    server s1 a1.test:80 resolvers r init-addr libc\n"), z(), [], 1.5, "", "A.t1d: fatal"),
 ("start-nameserver-dup", cfg(RS + "    nameserver ns1 127.0.0.1:%d\n" % NS2, S1), z(), [], 1.5, "", "duplicate nameserver name"),
 ("start-hold-bad", cfg(RS + "    hold nx foo\n", S1), z(), [], 1.5, "", "A.t15d"),
 ("start-unknown-resolvers", cfg(RS, "    server s1 a1.test:80 resolvers nosuch\n"), z(), [], 1.5, "", ""),
 # --- run time (T484)
 ("resolve-basic", cfg(RS, S1), z(), [], 2.5, "", "A.t1a: MAINT (resolution) then READY with 10.0.0.1"),
 ("resolve-init-none", cfg(RS, "    server s1 a1.test:80 resolvers r init-addr none\n"), z(), [], 2.5, "", "A.t1b"),
 ("resolve-init-ip", cfg(RS, "    server s1 a1.test:80 resolvers r init-addr 10.9.9.9\n"), z(), [], 2.5, "", "A.t1c"),
 ("resolve-libc-none", cfg(RS, "    server s1 localhost:%d resolvers r init-addr libc,none\n" % BE),
  z(localhost={"a": ["10.0.0.5"]}), [], 2.5, "", "libc first, then the resolver's answer replaces it"),
 ("addr-change", cfg(RS, S1), z(), [(2.0, "ns1", z(a1_test={"a": ["10.0.0.2"]}))], 4.0, "", "A.t3"),
 ("addr-change-traffic", cfg(RS, "    server s1 be.test:%d resolvers r\n" % BE), z(),
  [(2.5, "ns1", z(be_test={"a": ["127.0.0.2"]}))], 6.0, "http", "A.t3b: same client conn, next request goes to the new address"),
 ("addr-keep-current", cfg(RS, "    server s1 multi.test:80 resolvers r\n"), z(),
  [(2.0, "ns1", z(multi_test={"a": ["10.0.0.3", "10.0.0.1", "10.0.0.2"]}))], 4.0, "", "F7: +1 for the current address"),
 ("hold-nx", cfg(RS + "    hold nx 3s\n", S1), z(), [(2.0, "ns1", z(a1_test={"rcode": "nx"}))], 8.0, "", "A.t4: DOWN (DNS NX status)"),
 ("hold-nx-recover", cfg(RS + "    hold nx 1s\n", S1), z(),
  [(2.0, "ns1", z(a1_test={"rcode": "nx"})), (6.5, "ns1", z())], 9.0, "", "back READY on a valid answer"),
 ("nx-within-hold", cfg(RS + "    hold nx 30s\n", S1), z(), [(2.0, "ns1", z(a1_test={"rcode": "nx"}))], 7.0, "",
  "hold not expired: address kept"),
 ("never-valid", cfg(RS, "    server s1 nx.test:80 resolvers r\n"), z(), [], 6.0, "", "A.t4b"),
 ("hold-timeout", cfg(RS + "    resolve_retries 3\n    timeout retry 1s\n    hold timeout 3s\n", S1), z(),
  [(2.0, "ns1", z(a1_test={"silent": True}))], 8.0, "", "A.t5"),
 ("hold-refused", cfg(RS + "    hold refused 2s\n", S1), z(), [(2.0, "ns1", z(a1_test={"rcode": "refused"}))], 8.0, "", "A.t6"),
 ("hold-servfail", cfg(RS + "    hold other 2s\n", S1), z(), [(2.0, "ns1", z(a1_test={"rcode": "servfail"}))], 8.0, "", "A.t6b"),
 ("hold-nodata", cfg(RS + "    hold other 2s\n", S1), z(), [(2.0, "ns1", z(a1_test={"nodata": True}))], 8.0, "", "A.t6c"),
 ("dead-nameserver", cfg("resolvers r\n    nameserver ns1 127.0.0.1:%d\n    hold timeout 2s\n" % DEAD,
  "    server s1 a1.test:80 resolvers r init-addr 10.9.9.9\n"), z(), [], 6.0, "", "A.t7"),
 ("two-ns-nx-then-valid", cfg(RS2, S1), z(a1_test={"rcode": "nx"}), [], 3.0, "ns2delay", "A.t10: address from ns2"),
 ("prefer-v6-auto", cfg(RS, "    server s1 both.test:80 resolvers r resolve-prefer ipv6\n"), z(), [], 2.5, "",
  "A.t18 + §2.8.2: no v6 route here -> A only"),
 ("v6only-auto", cfg(RS, "    server s1 v6only.test:80 resolvers r\n"), z(), [], 3.0, "", "A.t8: stays MAINT"),
 ("resolve-net", cfg(RS, "    server s1 multi.test:80 resolvers r resolve-net 10.0.0.2/32\n"), z(), [], 2.5, "", "A.t19"),
 ("two-servers-one-addr", cfg(RS, S1 + "    server s2 a1.test:80 resolvers r\n"), z(), [], 2.5, "", "A.t12b"),
 ("two-servers-dup-ip", cfg(RS, "    server s1 a1.test:80 resolvers r resolve-opts allow-dup-ip\n"
  "    server s2 a1.test:80 resolvers r resolve-opts allow-dup-ip\n"), z(), [], 2.5, "", "A.t12c"),
 ("cname", cfg(RS, "    server s1 cname.test:80 resolvers r\n"), z(), [], 2.5, "", "A.t20"),
 ("cname-dangling", cfg(RS, "    server s1 dangling.test:80 resolvers r\n"), z(), [], 4.0, "", "A.t20b"),
 ("payload-4096", cfg(RS + "    accepted_payload_size 4096\n", S1), z(), [], 2.0, "", "A.t15: edns=4096"),
 ("truncated-udp", cfg(RS, S1), z(a1_test=dict(A1, tc_udp=True)), [], 3.0, "",
  "A.t9; expected DIFF until T488 (no TCP fallback in T484)"),
 # --- hostile replies: each is sent BEFORE the honest answer 10.0.0.1; 10.6.6.6 must never appear
 ("spoof-other-port", cfg(RS, S1), z(a1_test=dict(A1, spoof_port="10.6.6.6")), [], 3.0, "", "F15: connected socket"),
 ("spoof-wrong-name", cfg(RS, S1), z(a1_test=dict(A1, wrong_name="10.6.6.6")), [], 3.0, "", "F8"),
 ("spoof-wrong-id", cfg(RS, S1), z(a1_test=dict(A1, wrong_id="10.6.6.6")), [], 3.0, "", "F8: outdated"),
 ("spoof-wrong-type", cfg(RS, S1), z(a1_test=dict(A1, wrong_type="2001:db8::666")), [], 3.0, "", "AAAA record to an A query"),
 ("spoof-flood", cfg(RS, S1), z(a1_test=dict(A1, flood=200)), [], 3.0, "", "200 random-id replies per query"),
 ("garbage-short", cfg(RS, S1), z(a1_test=dict(A1, garbage="short")), [], 3.0, "", ""),
 ("garbage-loop", cfg(RS, S1), z(a1_test=dict(A1, garbage="loop")), [], 3.0, "", "compression pointer to itself"),
 ("garbage-ancount", cfg(RS, S1), z(a1_test=dict(A1, garbage="ancount")), [], 3.0, "", ""),
 ("garbage-qd0", cfg(RS, S1), z(a1_test=dict(A1, garbage="qd0")), [], 3.0, "", ""),
 ("garbage-qd2", cfg(RS, S1), z(a1_test=dict(A1, garbage="qd2")), [], 3.0, "", ""),
 ("garbage-rdlen", cfg(RS, S1), z(a1_test=dict(A1, garbage="rdlen")), [], 3.0, "", ""),
 ("garbage-only", cfg(RS + "    hold other 2s\n", S1), z(), [(2.0, "ns1", z(a1_test={"garbage": "loop", "only": True}))], 8.0, "",
  "only hostile replies after 2 s: what status does the server reach?"),
 ("oversize-100", cfg(RS, S1), z(a1_test={"many_a": 100}), [], 3.0, "", "F8: > 512 bytes over UDP = too_big"),
 ("oversize-4000", cfg(RS + "    accepted_payload_size 65535\n", S1), z(a1_test={"many_a": 4000}), [], 3.0, "", "B.P8"),
 # --- still refused after T484 (design §2.7); HAProxy accepts them
 ("refused-template", cfg(RS, "    server-template srv 3 multi.test:80 resolvers r\n"), z(), [], 2.5, "",
  "refused until T486"),
 ("refused-srv", cfg(RS, "    server-template srv 2 _http._tcp.srv.test resolvers r\n"), z(), [], 2.0, "", "refused until T487"),
 ("refused-do-resolve", cfg(RS, "    http-request do-resolve(txn.ip,r,ipv4) str(a1.test)\n    server s1 127.0.0.1:%d\n" % BE),
  z(), [], 1.5, "", "refused until T489"),
 ("refused-parse-resolv-conf", cfg(RS + "    parse-resolv-conf\n", S1), z(), [], 1.5, "", "refused until T489"),
 ("refused-tcp-ns", cfg("resolvers r\n    nameserver ns1 tcp@127.0.0.1:%d\n" % NS1, S1), z(), [], 1.5, "", "refused until T488"),
 ("refused-accept-family", cfg(RS, S1, glob="    dns-accept-family ipv4,ipv6\n"), z(), [], 1.5, "", "refused until T489"),
]

def write_zone(path, zone):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(zone, f)
    os.replace(tmp, path)

def cli(cmd):
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(1)
        s.connect(SOCK); s.sendall((cmd + "\n").encode()); s.shutdown(socket.SHUT_WR)
        b = b""
        while True:
            d = s.recv(65536)
            if not d:
                break
            b += d
        s.close()
        return b.decode(errors="replace")
    except OSError:
        return None

def state():
    t = cli("show servers state")
    if t is None:
        return None
    hdr, rows = None, {}
    for line in t.splitlines():
        if line.startswith("# be_id"):
            hdr = line[2:].split()
        elif hdr and line and not line.startswith("#") and len(line.split()) >= 7:
            f = dict(zip(hdr, line.split()))
            rows[f.get("srv_name")] = "%s op=%s adm=%s" % (f.get("srv_addr"), f.get("srv_op_state"), f.get("srv_admin_state"))
    return rows

def logclean(line):
    line = re.sub(r"^\[(WARNING|NOTICE|ALERT)\]\s+\(\d+\)\s*:\s*", r"[\1] ", line)
    line = re.sub(r"\d+ active and \d+ backup servers left.*", "", line)
    line = re.sub(r"\d+ sessions active, \d+ requeued, \d+ remaining in queue", "", line)
    return line.strip()

def http_client(n, iv):
    res = []
    try:
        s = socket.create_connection(("127.0.0.1", P), timeout=2)
        for _ in range(n):
            s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"); buf = b""
            while b"\r\n\r\n" not in buf:
                d = s.recv(4096)
                if not d:
                    res.append("closed"); return res
                buf += d
            head, rest = buf.split(b"\r\n\r\n", 1)
            cl = int(re.search(rb"(?i)content-length:\s*(\d+)", head).group(1)) if re.search(rb"(?i)content-length", head) else 0
            while len(rest) < cl:
                rest += s.recv(4096)
            res.append(head.split()[1].decode() + " " + rest[:cl].decode().strip().replace("backend ", ""))
            time.sleep(iv)
    except Exception as e:
        res.append("error %s" % type(e).__name__)
    return res

def dns_summary(lines):
    q = [l.split() for l in lines if len(l.split()) >= 6 and l.split()[1] in ("A", "AAAA", "SRV", "ANY")]
    if not q:
        return "no queries"
    types = {}
    for f in q:
        types[f[1]] = types.get(f[1], 0) + 1
    ids = [int(f[3][3:]) for f in q]
    edns = sorted(set(f[5] for f in q))
    u = [i for k, i in enumerate(ids) if k == 0 or i != ids[k - 1]]
    seq = len(u) > 2 and all(b - a == 1 for a, b in zip(u, u[1:]))
    distinct = len(set(ids))
    return "%s %s ids=%d distinct%s" % (" ".join("%s:%d" % kv for kv in sorted(types.items())),
                                            ",".join(edns), distinct, " SEQUENTIAL" if seq else "")

def run_one(binary, name, conf, zone0, timeline, secs, flags):
    d = os.path.join(out, name); os.makedirs(d, exist_ok=True)
    cf = os.path.join(d, "cfg"); open(cf, "w").write(conf)
    z1, z2 = os.path.join(d, "ns1.json"), os.path.join(d, "ns2.json")
    write_zone(z1, zone0)
    write_zone(z2, z() if "ns2delay" not in flags else z(a1_test=dict(A1, delay=0.3)))
    tag = "ibex" if binary == IB else "haproxy"
    l1, l2 = os.path.join(d, tag + ".ns1.log"), os.path.join(d, tag + ".ns2.log")
    for p in (l1, l2, SOCK):
        if os.path.exists(p):
            os.unlink(p)
    ns = [subprocess.Popen(["python3", "-I", os.path.join(HERE, "vvdns.py"), str(port), zf, lf],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
          for port, zf, lf in ((NS1, z1, l1), (NS2, z2, l2))]
    bes = []
    if "http" in flags:
        bes = [subprocess.Popen(["python3", "-I", "/home/bhenc/ibex-worktrees/review/night-1025/t481-oracle/be.py", ip, str(BE)],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) for ip in ("127.0.0.1", "127.0.0.2")]
    time.sleep(0.3)
    logp = os.path.join(d, tag + ".log")
    lf = open(logp, "w")
    t0 = time.time()
    px = subprocess.Popen(["taskset", "-c", "48-51", binary, "-f", cf], stdout=lf, stderr=subprocess.STDOUT)
    states, last, http, tl = [], None, None, list(timeline)
    import threading
    hc = None
    if "http" in flags:
        box = {}
        def go():
            time.sleep(1.2); box["r"] = http_client(10, 0.5)
        hc = threading.Thread(target=go); hc.start()
    started = False
    while time.time() - t0 < secs:
        now = time.time() - t0
        while tl and tl[0][0] <= now:
            _, which, zz = tl.pop(0); write_zone(z1 if which == "ns1" else z2, zz)
        if px.poll() is not None:
            break
        st = state()
        if st is not None:
            started = True
            key = json.dumps(st, sort_keys=True)
            if key != last:
                states.append((round(now, 2), st)); last = key
        time.sleep(0.25)
    alive = px.poll() is None
    if hc:
        hc.join(10); http = box.get("r")
    if alive:
        px.send_signal(signal.SIGTERM)
        try:
            px.wait(3)
        except subprocess.TimeoutExpired:
            px.kill(); px.wait()
    for p in ns + bes:
        p.terminate(); p.wait()
    lf.close()
    raw = open(logp, errors="replace").read().splitlines()
    alerts = [l for l in raw if "ALERT" in l]
    if not started:
        start = "did not start: " + (re.sub(r"\(\d+\)", "", alerts[0])[-200:] if alerts else (raw[-1][-200:] if raw else "no output"))
    else:
        start = "started"
    logl = [logclean(l) for l in raw if re.search(r"\bl/s[12]\b|resolv|DNS|nameserver", l) and "ALERT" not in l]
    dnsl = [l.strip() for p in (l1, l2) if os.path.exists(p) for l in open(p).read().splitlines()]
    return {"start": start, "states": states, "log": logl, "dns": dns_summary(dnsl),
            "http": http, "alive": alive or not started, "exit": px.returncode, "rawdns": dnsl}

def main():
    same = diff = 0
    for name, conf, zone0, tl, secs, flags, note in CASES:
        if only and name not in only:
            continue
        r = {tag: run_one(b, name, conf, zone0, tl, secs, flags) for tag, b in (("ibex", IB), ("haproxy", HA))}
        json.dump(r, open(os.path.join(out, name, "result.json"), "w"), indent=1)
        a, h = r["ibex"], r["haproxy"]
        seq = lambda x: [s for _, s in x["states"]]
        ok = (a["start"] == h["start"] and seq(a) == seq(h) and sorted(a["log"]) == sorted(h["log"])
              and a["http"] == h["http"] and a["alive"])
        same += ok; diff += not ok
        print("%s %s%s" % ("SAME" if ok else "DIFF", name, ("   (" + note + ")") if note else ""))
        for tag in ("ibex", "haproxy"):
            x = r[tag]
            print("   %-7s %s%s" % (tag, x["start"], "" if x["alive"] else "   ** NOT ALIVE at end, exit %s **" % x["exit"]))
        if a["start"] != "started" and h["start"] != "started":
            continue
        n = max(len(a["states"]), len(h["states"]))
        for i in range(n):
            sa = a["states"][i] if i < len(a["states"]) else None
            sh = h["states"][i] if i < len(h["states"]) else None
            fmt = lambda s: ("t=%5.2f %s" % (s[0], " | ".join("%s %s" % kv for kv in sorted(s[1].items())))) if s else "-"
            flag = ""
            if sa and sh and sa[1] != sh[1]:
                flag = "   <--"
            elif sa and sh and abs(sa[0] - sh[0]) > 1.0:
                flag = "   <-- t"
            elif not sa or not sh:
                flag = "   <--"
            print("   state  ibex %-46s haproxy %s%s" % (fmt(sa), fmt(sh), flag))
        for tag in ("ibex", "haproxy"):
            print("   dns    %-7s %s" % (tag, r[tag]["dns"]))
        if a["http"] or h["http"]:
            print("   http   ibex    %s" % a["http"]); print("   http   haproxy %s" % h["http"])
        la, lh = set(a["log"]), set(h["log"])
        for l in sorted(lh - la):
            print("   log    haproxy only: %s" % l[:200])
        for l in sorted(la - lh):
            print("   log    ibex only:    %s" % l[:200])
    print("same %d, diff %d" % (same, diff))

main()
