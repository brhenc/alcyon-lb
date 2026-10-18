#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
"""Stats page access control vs HAProxy: stats auth/realm, http-request rules in front of stats,
stats http-request, stats in a backend.  stats_acl.py IBEX [HAPROXY]
Each case: one config, a list of requests (path, credentials, extra header); prints status and
WWW-Authenticate per request for both proxies, SAME/DIFF per case.  Port 19970, backend 19971."""
import base64, os, socket, subprocess, sys, tempfile, time
IB = sys.argv[1]; HA = sys.argv[2] if len(sys.argv) > 2 else "/home/bhenc/reference/haproxy/haproxy"
P = 19970
HEAD = """global
    nbthread 1
defaults
    mode http
    timeout client 2s
    timeout server 2s
    timeout connect 1s
"""
FE = "frontend f\n    bind 127.0.0.1:%d\n" % P
BE = "backend app\n    http-request return status 200 content-type text/plain string app\n"
GOOD, BAD, ADM = ("u", "p"), ("u", "x"), ("admin", "secret")
R = [("/st", None, None), ("/st", BAD, None), ("/st", GOOD, None), ("/st;csv", GOOD, None),
     ("/st", None, "x-t: yes"), ("/st", GOOD, "x-t: yes"), ("/st", ADM, None), ("/other", None, None)]
CASES = [
 ("auth+realm", FE + "    stats enable\n    stats uri /st\n    stats auth u:p\n    stats realm MyRealm\n    default_backend app\n"),
 ("auth-no-enable", FE + "    stats uri /st\n    stats auth u:p\n    default_backend app\n"),
 ("auth-two-users", FE + "    stats uri /st\n    stats auth u:p\n    stats auth admin:secret\n    default_backend app\n"),
 ("auth-default-realm", FE + "    stats enable\n    stats uri /st\n    stats auth u:p\n    default_backend app\n"),
 ("deny-not-trusted", FE + "    acl trusted req.hdr(x-t) yes\n    http-request deny if !trusted\n    stats enable\n    stats uri /st\n    default_backend app\n"),
 ("deny-before-auth", FE + "    acl trusted req.hdr(x-t) yes\n    http-request deny if !trusted\n    stats enable\n    stats uri /st\n    stats auth u:p\n    default_backend app\n"),
 ("allow-then-deny", FE + "    acl trusted req.hdr(x-t) yes\n    http-request allow if trusted\n    http-request deny\n    stats enable\n    stats uri /st\n    default_backend app\n"),
 ("fe-http-auth", FE + "    userlist L\n" if False else "userlist L\n    user u insecure-password p\n" + FE + "    acl ok http_auth(L)\n    http-request auth realm FeRealm if !ok\n    stats enable\n    stats uri /st\n    default_backend app\n"),
 ("stats-http-req-deny", FE + "    acl trusted req.hdr(x-t) yes\n    stats enable\n    stats uri /st\n    stats http-request deny unless trusted\n    default_backend app\n"),
 ("stats-http-req-auth", "userlist L\n    user u insecure-password p\n" + FE + "    acl ok http_auth(L)\n    stats enable\n    stats uri /st\n    stats http-request auth realm SR unless ok\n    default_backend app\n"),
 ("stats-http-req-allow", FE + "    acl trusted req.hdr(x-t) yes\n    stats enable\n    stats uri /st\n    stats auth u:p\n    stats http-request allow if trusted\n    default_backend app\n"),
 ("backend-stats-auth", FE + "    use_backend st if { path_beg /st }\n    default_backend app\nbackend st\n    stats enable\n    stats uri /st\n    stats auth u:p\n    stats realm BeRealm\n"),
 ("backend-stats-fe-deny", FE + "    acl trusted req.hdr(x-t) yes\n    http-request deny if !trusted\n    use_backend st if { path_beg /st }\n    default_backend app\nbackend st\n    stats enable\n    stats uri /st\n"),
 ("backend-stats-be-deny", FE + "    use_backend st if { path_beg /st }\n    default_backend app\nbackend st\n    acl trusted req.hdr(x-t) yes\n    http-request deny if !trusted\n    stats enable\n    stats uri /st\n"),
 ("defaults-stats-auth", FE.replace("frontend f", "frontend f") + "    default_backend app\n", "    stats enable\n    stats uri /st\n    stats auth u:p\n"),
 ("listen-auth-admin", "listen l\n    bind 127.0.0.1:%d\n    stats enable\n    stats uri /st\n    stats auth u:p\n    stats auth admin:secret\n    stats admin if TRUE\n    http-request return status 200 content-type text/plain string app if !{ path_beg /st }\n" % P),
]

def req(path, cred, hdr):
    s = socket.create_connection(("127.0.0.1", P), timeout=3)
    h = "GET %s HTTP/1.1\r\nHost: x\r\nConnection: close\r\n" % path
    if cred: h += "Authorization: Basic %s\r\n" % base64.b64encode(("%s:%s" % cred).encode()).decode()
    if hdr: h += hdr + "\r\n"
    s.sendall((h + "\r\n").encode()); b = b""
    try:
        while True:
            d = s.recv(65536)
            if not d: break
            b += d
    except socket.timeout: pass
    s.close()
    if not b: return "no-answer"
    head, _, body = b.partition(b"\r\n\r\n"); lines = head.decode(errors="replace").split("\r\n")
    st = lines[0].split()[1] if len(lines[0].split()) > 1 else lines[0]
    wa = [l.split(":", 1)[1].strip() for l in lines[1:] if l.lower().startswith("www-authenticate:")]
    kind = "stats" if (b"Statistics Report" in body or b"pxname" in body) else ("app" if body.strip() == b"app" else "")
    return st + (" WA=" + "|".join(wa) if wa else "") + (" " + kind if kind else "")

def wait(p):
    for _ in range(50):
        try: socket.create_connection(("127.0.0.1", P), 0.2).close(); return True
        except OSError:
            if p.poll() is not None: return False
            time.sleep(0.05)
    return False

d = tempfile.mkdtemp(prefix="vv-stats-"); same = diff = 0
for name, fe, *dfl in CASES:
    cfg = HEAD + (dfl[0] if dfl else "") + fe + BE
    f = os.path.join(d, name + ".cfg"); open(f, "w").write(cfg)
    out = {}
    for nm, b in (("ibex", IB), ("haproxy", HA)):
        p = subprocess.Popen(["taskset", "-c", "48-49", b, "-f", f], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if not wait(p):
            p.kill(); o = p.communicate()[0].decode(errors="replace")
            al = [l for l in o.splitlines() if "ALERT" in l][:1]
            out[nm] = ["did not start: " + (al[0][-160:] if al else o[-160:])]; continue
        out[nm] = [req(*r) for r in R]
        p.terminate(); p.wait(5)
    ok = out["ibex"] == out["haproxy"]; same += ok; diff += not ok
    print(("SAME " if ok else "DIFF ") + name)
    for i, r in enumerate(R if len(out["ibex"]) > 1 or len(out["haproxy"]) > 1 else [None]):
        a = out["ibex"][i] if i < len(out["ibex"]) else "-"; h = out["haproxy"][i] if i < len(out["haproxy"]) else "-"
        lab = "%-8s %-7s %-9s" % (r[0], (r[1] or ("", ""))[0] + (":" + r[1][1] if r[1] else ""), r[2] or "") if r else ""
        print("   %s ibex %-40s haproxy %s%s" % (lab, a, h, "" if a == h else "   <--"))
print("same %d, diff %d" % (same, diff))
