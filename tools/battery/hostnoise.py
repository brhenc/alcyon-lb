#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
# Host-side noise sampler for load runs: run on the VM host alongside a battery run and line the
# per-second lines up with the run times. "wwm" is Where Winds Meet (wwm.exe / wineserver under
# Steam/Proton); a run that overlaps it is discarded (user rule, 2026-10-11).
"""One CSV line per second: time, loadavg1, qemu CPU % per VM, game CPU % (steam/proton/wine/pressure-vessel/*.exe), game process count."""
import os, re, time
TICK = os.sysconf("SC_CLK_TCK")
GAME = re.compile(r"steam|proton|wine|pressure-vessel|pv-bwrap|srt-bwrap|reaper|\.exe", re.I)
WWM = re.compile(r"wwm\.exe|wineserver", re.I)

def procs():
    out = {}
    for pid in os.listdir("/proc"):
        if not pid.isdigit(): continue
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f: cmd = f.read().replace(b"\0", b" ").decode(errors="replace")
            with open(f"/proc/{pid}/stat") as f: st = f.read()
        except OSError: continue
        comm = st[st.index("(") + 1:st.rindex(")")]
        fields = st[st.rindex(")") + 2:].split()
        ticks = int(fields[11]) + int(fields[12])
        if "qemu-system" in comm or "qemu-system" in cmd[:200]:
            m = re.search(r"guest=([\w.-]+)", cmd); key = "vm:" + (m.group(1) if m else pid)
        elif WWM.search(comm) or WWM.search(cmd[:400]):
            key = "wwm"
        elif GAME.search(comm) or GAME.search(cmd[:300]):
            key = "game"
        else: continue
        out.setdefault(key, [0, 0]); out[key][0] += ticks; out[key][1] += 1
    return out

prev, t0 = procs(), time.monotonic()
while True:
    time.sleep(1)
    cur, t1 = procs(), time.monotonic()
    dt = t1 - t0
    parts = []
    for k in sorted(set(prev) | set(cur)):
        c = cur.get(k, [0, 0])[0] - prev.get(k, [0, 0])[0]
        parts.append(f"{k}={100 * c / TICK / dt:.0f}%" + (f"({cur[k][1]}p)" if k in ("game", "wwm") and k in cur else ""))
    print(time.strftime("%H:%M:%S"), f"load={open('/proc/loadavg').read().split()[0]}", *parts, flush=True)
    prev, t0 = cur, t1
