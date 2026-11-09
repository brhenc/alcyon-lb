#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
"""VV-24: server state changes are neither logged nor printed.

vv24.py ALCYON [HAPROXY]
s1 has a check on a closed port (127.0.0.1:19991); after 2 s the CLI puts it into maintenance.
Then a second process loads a server-state file that has s1 in maintenance. Prints every
non-NOTICE line of stdout+stderr (`log stdout`). HAProxy: 'Server b/s1 is DOWN, reason: ...',
'backend b has no server available!', 'Server b/s1 was DOWN and now enters maintenance.', and on
the reload 'Server b/s1 is DOWN, changed from server-state after a reload.', each on stderr and in the
log. Port 19990, socket and files in a temporary directory."""
import os, socket, subprocess, sys, tempfile, time

IB = sys.argv[1]; HA = sys.argv[2] if len(sys.argv) > 2 else os.path.join(os.environ["ALCYON_REFERENCE"], "haproxy/haproxy")
D = tempfile.mkdtemp(prefix="vv24-"); S = D + "/cli.sock"

def cfg(extra_global="", extra_be=""):
    return ("global\n    log stdout format raw local0\n    stats socket %s level admin\n%s"
            "defaults\n    mode http\n    log global\n    timeout client 5s\n    timeout server 5s\n    timeout connect 1s\n"
            "backend b\n%s    server s1 127.0.0.1:19991 check inter 300\n"
            "frontend f\n    bind 127.0.0.1:19990\n    default_backend b\n" % (S, extra_global, extra_be))

def cli(cmd):
    c = socket.socket(socket.AF_UNIX); c.connect(S); c.sendall(cmd.encode() + b"\n"); d = b""
    while True:
        x = c.recv(65536)
        if not x:
            return d.decode()
        d += x

def run(b, conf, wait, cmds=(), save=None):
    open(D + "/c.cfg", "w").write(conf)
    p = subprocess.Popen(["taskset", "-c", "48-51", b, "-f", D + "/c.cfg"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    time.sleep(wait)
    for c in cmds:
        cli(c)
    time.sleep(0.5)
    if save:
        open(save, "w").write(cli("show servers state b"))
    p.terminate()
    out = p.communicate()[0].decode(errors="replace")
    if os.path.exists(S):
        os.unlink(S)
    for l in out.splitlines():
        if l.strip() and "NOTICE" not in l and "FD limit" not in l:
            print("    " + l[:170])

for tag, b in (("alcyon", IB), ("haproxy", HA)):
    st = D + "/state." + tag
    print("%s: check fails, then disable server" % tag)
    run(b, cfg(), 2.0, ["disable server b/s1"], save=st)
    print("%s: start with the state file (s1 in maintenance)" % tag)
    run(b, cfg("    server-state-file %s\n" % st, "    load-server-state-from-file global\n"), 1.0)
