#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
"""VV-12: a backend restart (SIGKILL + start) while h2 streams are in flight on it.

  probe.py PORT BIGLOG SLOWPORT CONNS
Per h2 connection: rounds of 2 x POST /up 256 KB (healthy bigapp) + 4 x GET /s (slowbe.py, 50 ms,
keep-alive, pooled). Rounds 0-1 normal; in round 2 the slow backend is SIGKILLed 20 ms after the
round starts and restarted at once; round 3 checks the connection is still usable.
"""
import os, subprocess, sys, threading, time
PORT, BIGLOG, SLOW, CONNS = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
sys.argv = [sys.argv[0], PORT, BIGLOG]
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import h2c as u  # noqa: E402

BE = [subprocess.Popen(["python3", os.path.join(HERE, "slowbe.py"), SLOW])]
time.sleep(0.5)

def restart():
    BE[0].kill(); BE[0].wait()
    BE[0] = subprocess.Popen(["python3", os.path.join(HERE, "slowbe.py"), SLOW])

def specs(r):
    sp = [dict(method=b"POST", path=b"/up", body=262144) for _ in range(2)]
    sp += [dict(method=b"GET", path=b"/s?r=%d&i=%d" % (r, i)) for i in range(4)]
    return sp

try:
    for n in range(CONNS):
        c = u.Conn()
        out = []
        for r in range(4):
            before = dict(u.ST); u.REASONS.clear()
            t = threading.Timer(0.02, restart) if r == 2 else None
            if t:
                t.start()
            try:
                u.run_round(c, specs(r), deadline=10)
                out.append("r%d ok+%d bad+%d %s" % (r, u.ST["ok"] - before["ok"], u.ST["bad"] - before["bad"],
                                                   [x[:60] for x in u.REASONS]))
            except Exception as e:
                out.append("r%d EXC %s: %s (ok+%d)" % (r, type(e).__name__, e, u.ST["ok"] - before["ok"]))
                break
            finally:
                if t:
                    t.join()
                    time.sleep(0.3)  # backend listening again
        print("conn %d: %s | goaway=%s" % (n, " || ".join(out), c.goaway), flush=True)
        c.close()
        time.sleep(0.2)
finally:
    BE[0].kill()
