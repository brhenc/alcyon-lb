#!/usr/bin/env python3
# oracle.py CASE.json : {"servers": "...", "resolvers": "...", "zones": [[t, {zone}], ...], "dur": s, "bin": path}
import json, os, socket, subprocess, sys, time
case = json.load(open(sys.argv[1]))
d = "/tmp/t487/run"; os.makedirs(d, exist_ok=True)
for f in ("dns.log", "zone.json"):
    try: os.unlink(f"{d}/{f}")
    except FileNotFoundError: pass
def freeport():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p
dp, fp = freeport(), freeport()
json.dump(case["zones"][0][1], open(f"{d}/zone.json", "w"))
dns = subprocess.Popen([sys.executable, "/home/bhenc/ibex-worktrees/t487/tools/battery/repro/vv-dns/vvdns.py", str(dp), f"{d}/zone.json", f"{d}/dns.log"])
time.sleep(0.3)
sock = f"{d}/hap.sock"
cfg = f"""global
  log stdout format raw local0
  stats socket {sock} level admin
{case.get('global','')}
resolvers r
  nameserver ns1 127.0.0.1:{dp}
{case.get('resolvers','')}
defaults
  mode http
  log global
  timeout connect 1s
  timeout client 5s
  timeout server 5s
listen l
  bind 127.0.0.1:{fp}
{case['servers']}
"""
open(f"{d}/hap.cfg", "w").write(cfg)
t0 = time.time()
p = subprocess.Popen([case.get("bin", "/home/bhenc/reference/haproxy/haproxy"), "-f", f"{d}/hap.cfg"], stdout=open(f"{d}/out.log", "w"), stderr=open(f"{d}/err.log", "w"))
def cli(c):
    try:
        s = socket.socket(socket.AF_UNIX); s.connect(sock); s.sendall((c + "\n").encode())
        out = b""
        while True:
            b = s.recv(65536)
            if not b: break
            out += b
        return out.decode()
    except Exception as e:
        return ""
last = {}
zi = 1
while time.time() - t0 < case["dur"]:
    t = time.time() - t0
    if zi < len(case["zones"]) and t >= case["zones"][zi][0]:
        json.dump(case["zones"][zi][1], open(f"{d}/zone.json", "w")); print("[t=%.2f] zone %d" % (t, zi)); zi += 1
    for l in cli("show servers state l").splitlines():
        f = l.split(" ")
        if len(f) > 20 and f[3] != "srv_name":
            v = " ".join([f[4], f[5], f[6], f[7], f[8], f[17], f[18], f[19] if len(f) > 19 else ""] + ([f[20]] if len(f) > 20 else []))
            if last.get(f[3]) != v:
                print("[t=%.2f] %s %s" % (t, f[3], v)); last[f[3]] = v
    time.sleep(0.05)
print("--- show stat"); print("\n".join(",".join(l.split(",")[:2] + [l.split(",")[17], l.split(",")[18]] + l.split(",")[73:74]) for l in cli("show stat").splitlines()[1:] if l))
print("--- state header"); print(cli("show servers state l").splitlines()[1])
print("--- extra"); 
for c in case.get("cli", []): print(c); print(cli(c))
p.send_signal(10); time.sleep(0.3)
if p.poll() is None: p.kill()
dns.kill()
print("--- out"); print(open(f"{d}/out.log").read()); print("--- err"); print(open(f"{d}/err.log").read()); print("--- dns"); print(open(f"{d}/dns.log").read())
