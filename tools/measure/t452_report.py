#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

"""T452: per batch of t452_night.sh, the 1-conn modes and what goes with them.

    tools/measure/t452_report.py [/tmp/t452/results.jsonl] [--tag PREFIX]

All samples are split at one threshold (measure.split_modes over every sample of the file,
so every batch is judged by the same line). Per batch and binary: samples, median, how many
slow/fast, the median of each mode. Then, per mode over all batches, the means of what was
recorded next to each sample: the proxy's and the backend's effective clock (perf cycles /
task-clock), C1 and C2 entries per request on each pinned CPU, busy% of the SMT siblings and
the rest of the CCX, and how often llama-server was last seen on the CCX of CPU 4.
"""

import argparse
import json
import statistics
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from measure import _median, split_modes  # noqa: E402

CCX4 = {4, 5, 6, 7, 36, 37, 38, 39}


def mean(xs):
    xs = [x for x in xs if x is not None]
    return round(statistics.mean(xs), 3) if xs else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path", nargs="?", default="/tmp/t452/results.jsonl")
    ap.add_argument("--tag", default="")
    a = ap.parse_args()
    samples, batches = [], []
    for line in open(a.path):
        rec = json.loads(line)
        if not rec.get("tag", "").startswith(a.tag):
            continue
        (batches if rec.get("kind") == "batch" else samples).append(rec)
    if not samples:
        sys.exit("no samples")
    th = split_modes([s["rps"] for s in samples], [])["threshold"]
    print(f"{len(samples)} samples; modes split at {th:,.0f} req/s" if th else
          f"{len(samples)} samples; one mode")
    for b in batches:
        if b["status"] == "skip":
            print(f"  skipped {b['tag']}: {b['reason']} {b['host'].get('reason', '')}")
    fast = lambda s: th is not None and s["rps"] >= th
    by_tag = defaultdict(lambda: defaultdict(list))
    for s in samples:
        by_tag[s["tag"]][s["bin"]].append(s)
    print(f"\n{'batch':22} {'binary':10} {'n':>3} {'median':>7} {'slow':>4} {'fast':>4} "
          f"{'slow med':>8} {'fast med':>8}  A/A or A/B diff")
    for tag, per_bin in by_tag.items():
        meds = {}
        for lab, ss in per_bin.items():
            r = [s["rps"] for s in ss]
            sl, fa = [x for x in r if th is None or x < th], [x for x in r if th is not None and x >= th]
            meds[lab] = _median(r)
            print(f"{tag:22} {lab:10} {len(r):3} {_median(r):7} {len(sl):4} {len(fa):4} "
                  f"{_median(sl) if sl else '-':>8} {_median(fa) if fa else '-':>8}")
            if len(per_bin) == 1:  # A/A of one binary: compare the even and odd positions
                ev = [s["rps"] for i, s in enumerate(ss) if i % 2 == 0]
                od = [s["rps"] for i, s in enumerate(ss) if i % 2 == 1]
                if ev and od:
                    print(f"{'':22} {'':10} A/A halves {_median(ev)} vs {_median(od)}: "
                          f"{(_median(ev) - _median(od)) * 100 / _median(od):+.1f}%")
        if len(meds) == 2:
            (la, ma), (lb, mb) = meds.items()
            print(f"{'':22} {la} vs {lb}: {(ma - mb) * 100 / mb:+.1f}%")

    print("\nper mode, means over all samples:")
    rows = defaultdict(lambda: defaultdict(list))
    for s in samples:
        mode = "fast" if fast(s) else "slow"
        row = rows[mode]
        perf = s.get("perf") or {}
        row["proxy GHz"].append((perf.get("proxy") or {}).get("ghz"))
        row["backend GHz"].append((perf.get("backend") or {}).get("ghz"))
        row["proxy IPC"].append(((perf.get("proxy") or {}).get("instructions") or 0)
                                / ((perf.get("proxy") or {}).get("cycles") or 1) or None)
        for c, v in s["idle_per_req"].items():
            row[f"cpu{c} C1/req"].append(v[1] if len(v) > 1 else None)
            row[f"cpu{c} C2/req"].append(v[2] if len(v) > 2 else None)
        for c, v in (perf.get("cpus") or {}).items():
            b = s["busy"].get(c) or s["busy"].get(str(c))
            row[f"cpu{c} GHz busy"].append(round(v["ghz_wall"] * 100 / b, 3) if b and v.get("ghz_wall") else None)
        for c, b in s["busy"].items():
            row[f"cpu{c} busy%"].append(b)
        row["llama on CCX4"].append(1 if any(c in CCX4 for c in s.get("llama_cpu", [])) else 0)
        row["load1"].append(float(s["load"]))
    keys = sorted({k for r in rows.values() for k in r}, key=lambda k: (k.split()[0][:3] != "pro", k))
    print(f"{'':20} {'slow':>9} {'fast':>9}")
    print(f"{'samples':20} {len(rows['slow']['load1']):9} {len(rows['fast']['load1']):9}")
    for k in keys:
        print(f"{k:20} {str(mean(rows['slow'][k])):>9} {str(mean(rows['fast'][k])):>9}")


if __name__ == "__main__":
    main()
