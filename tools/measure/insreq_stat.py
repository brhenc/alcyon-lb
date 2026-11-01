#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
"""Reads the `perf stat -x,` file of one insreq.sh round (T568).

    insreq_stat.py <stat-file>     prints "<user> <kernel>"; kernel is "-" when not counted

The file holds one line per event, `<count>,<unit>,<event>,...`, for instructions:u and
instructions:k. A count that perf could not take reads `<not supported>` or `<not counted>`;
that is kernel "-", never an error. A missing user count is an error (exit 1): the round
measured nothing.
"""
import sys


def parse_stat(text):
    """(user, kernel) instruction counts; kernel is None when perf did not count it."""
    got = {}
    for line in text.splitlines():
        f = line.split(",")
        if len(f) < 3 or not f[2].startswith("instructions"):
            continue
        ev = f[2].split(":", 1)[1] if ":" in f[2] else "u"
        got[ev[:1]] = int(f[0]) if f[0].strip().isdigit() else None
    if got.get("u") is None:
        raise ValueError("no instructions:u count in the perf stat output")
    return got["u"], got.get("k")


def main(argv):
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    try:
        u, k = parse_stat(open(argv[1]).read())
    except (OSError, ValueError) as e:
        print(f"insreq_stat: {e}", file=sys.stderr)
        return 1
    print(u, "-" if k is None else k)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
