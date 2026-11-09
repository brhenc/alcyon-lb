#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
"""Stats page admin actions vs HAProxy (VV-18, VV-19): stats admin absent / if FALSE / if TRUE /
by source, with stats auth; cross-origin Origin/Referer; ;st= codes and banners; Alcyon-only
query-string and JSON admin calls.  stats_admin.py ALCYON [HAPROXY]
Each request runs against a fresh process; prints status, Location, banner and s1's status
from ;csv afterwards, for both proxies, SAME/DIFF per case.  Port 19970, s1 at 19971 (no listener)."""
import base64, os, re, socket, subprocess, sys, tempfile, time
IB = sys.argv[1]; HA = sys.argv[2] if len(sys.argv) > 2 else os.path.join(os.environ["ALCYON_REFERENCE"], "haproxy/haproxy")
P = 19970
HEAD = """global
    nbthread 1
defaults
    mode http
    timeout client 2s
    timeout server 2s
    timeout connect 1s
frontend f
    bind 127.0.0.1:%d
    stats enable
    stats uri /st
""" % P
TAIL = "    default_backend app\nbackend app\n    server s1 127.0.0.1:19971\n    server s2 127.0.0.1:19972\n"
CRED = ("u", "p")
CASES = [("no-admin", ""), ("admin-if-FALSE", "    stats admin if FALSE\n"),
         ("admin-if-TRUE", "    stats admin if TRUE\n"), ("admin-bare", "    stats admin\n"),
         ("admin-src-local", "    stats admin if { src 127.0.0.1 }\n"),
         ("admin-src-other", "    stats admin if { src 10.0.0.0/8 }\n"),
         ("auth-admin", "    stats auth u:p\n    stats admin if TRUE\n")]
FORM = "application/x-www-form-urlencoded"
# (label, method, path, body, content-type, extra headers)
REQS = [
 ("post maint", "POST", "/st", "s=s1&action=maint&b=app", FORM, []),
 ("post maint Origin=evil", "POST", "/st", "s=s1&action=maint&b=app", FORM, ["Origin: http://evil.example"]),
 ("post maint Origin=same", "POST", "/st", "s=s1&action=maint&b=app", FORM, ["Origin: http://x"]),
 ("post maint Referer=evil", "POST", "/st", "s=s1&action=maint&b=app", FORM, ["Referer: http://evil.example/st"]),
 ("post maint Referer=same", "POST", "/st", "s=s1&action=maint&b=app", FORM, ["Referer: http://x/st"]),
 ("post maint Origin=null", "POST", "/st", "s=s1&action=maint&b=app", FORM, ["Origin: null"]),
 ("post drain", "POST", "/st", "s=s1&action=drain&b=app", FORM, []),
 ("post bad action", "POST", "/st", "s=s1&action=frobnicate&b=app", FORM, []),
 ("post bad backend", "POST", "/st", "s=s1&action=maint&b=nosuch", FORM, []),
 ("post bad server", "POST", "/st", "s=nosuch&action=maint&b=app", FORM, []),
 ("post partial", "POST", "/st", "s=s1&s=nosuch&action=maint&b=app", FORM, []),
 ("post no server", "POST", "/st", "action=maint&b=app", FORM, []),
 ("post two servers", "POST", "/st", "s=s1&s=s2&action=maint&b=app", FORM, []),
 ("post ;up;norefresh", "POST", "/st;up;norefresh", "s=s1&action=maint&b=app", FORM, []),
 ("post json", "POST", "/st", '{"backend":"app","server":"s1","action":"maint"}', "application/json", ["Accept: application/json"]),
 ("get ?action=maint", "GET", "/st?b=app&s=s1&action=maint", None, None, []),
 ("put", "PUT", "/st", "s=s1&action=maint&b=app", FORM, []),
] + [("get ;st=%s" % c, "GET", "/st;st=%s" % c, None, None, [])
     for c in ("DONE", "NONE", "PART", "ERRP", "EXCD", "DENY", "IVAL", "UNKN", "XXXX")]

def http(method, path, body, ctype, hdrs, cred):
    s = socket.create_connection(("127.0.0.1", P), timeout=3)
    h = "%s %s HTTP/1.1\r\nHost: x\r\nConnection: close\r\n" % (method, path)
    if cred: h += "Authorization: Basic %s\r\n" % base64.b64encode(("%s:%s" % cred).encode()).decode()
    for x in hdrs: h += x + "\r\n"
    b = (body or "").encode()
    if body is not None: h += "Content-Type: %s\r\nContent-Length: %d\r\n" % (ctype, len(b))
    s.sendall((h + "\r\n").encode() + b); r = b""
    try:
        while True:
            d = s.recv(65536)
            if not d: break
            r += d
    except socket.timeout: pass
    s.close()
    head, _, rb = r.partition(b"\r\n\r\n"); lines = head.decode(errors="replace").split("\r\n")
    if any(l.lower().replace(" ", "") == "transfer-encoding:chunked" for l in lines[1:]):
        out = b""
        while rb:
            n, _, rest = rb.partition(b"\r\n")
            try: n = int(n.split(b";")[0], 16)
            except ValueError: break
            if n == 0: break
            out += rest[:n]; rb = rest[n + 2:]
        rb = out
    return lines, rb

def banner(rb):
    m = re.search(rb'<p><div class=([a-z_]+)><a class=lfsb href="([^"]*)"[^>]*>\[X\]</a> (.*?)</div>', rb, re.S)
    return "banner=%s href=%s %r" % (m.group(1).decode(), m.group(2).decode(), m.group(3).decode()[:60]) if m else "no-banner"

def s1_status(cred):
    lines, rb = http("GET", "/st;csv", None, None, [], cred)
    rows = rb.decode(errors="replace").splitlines()
    if not rows or not rows[0].startswith("#"): return "csv?" + (lines[0] if lines else "")
    col = rows[0][2:].split(",").index("status")
    st = {r.split(",")[1]: r.split(",")[col] for r in rows[1:] if r.startswith("app,s")}
    return "s1=%s s2=%s" % (st.get("s1"), st.get("s2"))

def one(binary, cfg, r, cred):
    p = subprocess.Popen(["taskset", "-c", "48-49", binary, "-f", cfg], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for _ in range(50):
        try: socket.create_connection(("127.0.0.1", P), 0.2).close(); break
        except OSError:
            if p.poll() is not None: break
            time.sleep(0.05)
    if p.poll() is not None:
        o = p.communicate()[0].decode(errors="replace"); return "did not start: " + o[-160:]
    lines, rb = http(r[1], r[2], r[3], r[4], r[5], cred)
    st = lines[0].split()[1] if lines and len(lines[0].split()) > 1 else "no-answer"
    loc = [l.split(":", 1)[1].strip() for l in lines[1:] if l.lower().startswith("location:")]
    out = st + (" Location=" + loc[0] if loc else "")
    if r[1] == "GET": out += " " + banner(rb)
    out += " | " + s1_status(cred)
    p.terminate(); p.wait(5)
    return out

d = tempfile.mkdtemp(prefix="vv-stadm-"); same = diff = 0
for name, extra in CASES:
    f = os.path.join(d, name + ".cfg"); open(f, "w").write(HEAD + extra + TAIL)
    creds = [CRED, None] if name == "auth-admin" else [None]
    rows = []; ok = True
    for cred in creds:
        for r in REQS:
            if cred is None and name == "auth-admin" and not r[0].startswith(("post maint", "get ?action")): continue
            a, h = one(IB, f, r, cred), one(HA, f, r, cred)
            ok &= a == h
            rows.append("   %-26s %-4s alcyon %s\n   %-31s haproxy %s%s" % (r[0], "cred" if cred else "", a, "", h, "" if a == h else "   <--"))
    same += ok; diff += not ok
    print(("SAME " if ok else "DIFF ") + name); print("\n".join(rows))
print("same %d, diff %d" % (same, diff))
