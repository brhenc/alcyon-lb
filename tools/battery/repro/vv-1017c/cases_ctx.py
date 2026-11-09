# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
# cases for cfgcmp.py (python3 cfgcmp.py ALCYON ctx.py)
CASES = []
for e in ["src,ipmask(abc)","int(x)","str(a),bytes(x)","str(a),regsub(a**,b)","str(a),map(/nonexistent/m)","str(a),lower(x)","hdr(x,abc)","src,bool"]:
    k=e.replace("/","_")[:22]
    CASES += [("setvar-"+k, "http-request set-var(txn.v) %s" % e),
              ("acl-"+k,    "acl a %s -m found\n    http-request deny if a" % e),
              ("anon-"+k,   "http-request deny if { %s -m found }" % e),
              ("stick-"+k,  "", "stick-table type string size 10\n    stick on %s" % e)]
