#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

"""The h3 board (quic-transport design section 4, M1): the h3fit rows of data/measurements.jsonl,
one line per (commit, method), with the columns

    release-perf   Alcyon built plain: the A/B and the +0.5 % budget are judged here
    pgo            Alcyon built by tools/pgo-build.sh: the "shipped" figure
    haproxy        the oracle (not PGO-built: the like-for-like comparison is the release-perf one)

and the ratios to HAProxy. insreq.sh records the column in the row's "build" field
(ALCYON_MEASURE_BUILD=pgo for a PGO binary; absent means release-perf, or haproxy when the binary's
path says so). The last row of a column wins.

    tools/measure/h3board.py [data/measurements.jsonl]
"""

import json
import sys
from pathlib import Path

COLS = ("release-perf", "pgo", "haproxy")


def column(row):
    b = row.get("build")
    if b in COLS:
        return b
    return "haproxy" if "haproxy" in row.get("binary", "") else "release-perf"


def board(rows):
    """One dict per (sha, method), in order of first appearance."""
    lines = {}
    for r in rows:
        if r.get("kind") != "insreq-h3" or "h3_fit" not in r:
            continue
        key = (r["sha"], r.get("method", "get"))
        line = lines.setdefault(key, {"sha": r["sha"], "method": key[1], **{c: None for c in COLS}})
        line[column(r)] = r["h3_fit"]
    for line in lines.values():
        h = line["haproxy"]
        line["ratio"] = line["release-perf"] / h if h and line["release-perf"] else None
        line["pgo_ratio"] = line["pgo"] / h if h and line["pgo"] else None
    return list(lines.values())


def render(lines):
    def n(v):
        return "-" if v is None else str(v)

    def x(v):
        return "-" if v is None else f"{v:.2f}x"

    out = [f"{'commit':10} {'method':6} {'release-perf':>12} {'pgo':>8} {'haproxy':>8} {'rp/hap':>7} {'pgo/hap':>8}"]
    for g in lines:
        out.append(f"{g['sha'][:8]:10} {g['method']:6} {n(g['release-perf']):>12} {n(g['pgo']):>8} "
                   f"{n(g['haproxy']):>8} {x(g['ratio']):>7} {x(g['pgo_ratio']):>8}")
    return "\n".join(out)


def main():
    path = Path(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).resolve().parents[2] / "data/measurements.jsonl")
    rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    print(render(board(rows)))


if __name__ == "__main__":
    main()
