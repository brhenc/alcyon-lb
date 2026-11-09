#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
"""cfgcmp.py ALCYON CASES.py: `-c` each config case on Alcyon and HAProxy; print rc and core ALERT."""
import os, re, subprocess, sys, tempfile
IB, CASES = sys.argv[1], sys.argv[2]
HA = "/home/bhenc/reference/haproxy/haproxy"
ns = {}; exec(open(CASES).read(), ns)
TPL = """global
    nbthread 1
defaults
    mode http
    timeout client 1s
    timeout server 1s
    timeout connect 1s
frontend f
    bind 127.0.0.1:19899
{fe}
    default_backend b
backend b
{be}
    server s 127.0.0.1:19898
backend t
    stick-table type ip size 10
"""
def core(out):
    al = [l for l in out.splitlines() if "ALERT" in l and "Error(s) found" not in l and "Fatal errors" not in l]
    if not al: return ""
    m = al[0]
    m = re.sub(r"^\[ALERT\]\s*\(\d+\)\s*:\s*(config\s*:\s*)?", "", m)
    m = re.sub(r"^[Pp]arsing \[[^\]]*\]\s*:?\s*", "", m)
    m = re.sub(r"error detected in (frontend|backend|proxy) '[^']*' while parsing '[^']*' rule\s*:\s*", "", m)
    return m.replace(d + "/", "")
d = tempfile.mkdtemp(prefix="cfgcmp-")
same = diff = 0
for name, fe, *rest in ns["CASES"]:
    be = rest[0] if rest else ""
    f = os.path.join(d, name + ".cfg")
    open(f, "w").write(TPL.format(fe="\n".join("    " + x for x in fe.split("\n") if x), be="\n".join("    " + x for x in be.split("\n") if x)))
    r = {}
    for nm, b in (("alcyon", IB), ("haproxy", HA)):
        p = subprocess.run([b, "-c", "-f", f], capture_output=True, text=True, timeout=10)
        r[nm] = (p.returncode, core(p.stdout + p.stderr))
    ok = r["alcyon"][0] == r["haproxy"][0]
    same += ok; diff += not ok
    print(("RC-SAME " if ok else "RC-DIFF ") + name)
    for nm in r: print("   %-7s rc=%d %s" % (nm, r[nm][0], r[nm][1][:240]))
print("rc same %d, rc diff %d" % (same, diff))
