#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
"""MY-10 / VV-16. Local wrapper for tools/battery/repro/h2rxbudget.py (MY-10): no VM, so haterm is replaced by a
reference HAProxy answering 200, and every process is pinned to cores 48-55.
    taskset -c 54-55 python3 run.py 19960 <conns> label=binary ...   (env as h2rxbudget.py: LEGIT=1 HOLD_SECS=120;
    TIMEOUT_CONNECT=60s TIMEOUT_CLIENT=6s override the proxy timeouts)
Run sample.sh <secs> next to it to log the proxy fds and backend SYN-SENT sockets every 5 s."""
import os, subprocess, sys
B = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path[:0] = [B, B + "/repro"]
import labproxy
HA = os.path.join(os.environ["ALCYON_REFERENCE"], "haproxy/haproxy")
TCFG = """global
    nbthread 2
defaults
    mode http
    timeout client 60s
    timeout server 60s
    timeout connect 5s
frontend t
    bind 127.0.0.1:{port}
    http-request return status 200 content-type text/plain string "ok"
"""
_sp = labproxy.start_proxy
def start_haterm(port, cpus="16-31", extra=()):
    open("/tmp/vv-my10-term.cfg", "w").write(TCFG.format(port=port))
    p = subprocess.Popen(["taskset", "-c", "52-53", HA, "-f", "/tmp/vv-my10-term.cfg"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    if not labproxy.wait_port(port): p.terminate(); raise SystemExit("terminator did not listen")
    return p
def start_proxy(binary, cfg_text, port, tag, cpus="0-3", wrap=()):
    return _sp(binary, cfg_text, port, tag, cpus="48-51", wrap=wrap)
labproxy.start_haterm = start_haterm
labproxy.start_proxy = start_proxy
sys.argv = [B + "/repro/h2rxbudget.py"] + sys.argv[1:]
src = open(sys.argv[0]).read()
for kw in ("connect", "client"):  # TIMEOUT_CONNECT / TIMEOUT_CLIENT override the probe's 60 s (VV-16: client < connect)
    v = os.environ.get("TIMEOUT_" + kw.upper())
    if v: src = src.replace(f"    timeout {kw} 60s\n", f"    timeout {kw} {v}\n")
exec(compile(src, sys.argv[0], "exec"), {"__name__": "__main__"})
