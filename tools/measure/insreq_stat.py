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


def summary(label, rounds, n):
    """The summary line of rounds [(user, kernel-or-None)] of n requests: the round with the
    least total, with that round's own user and kernel, so user + kernel = total."""
    if any(k is None for _, k in rounds):
        return f"{label} summary (min of {len(rounds)}): user {min(u for u, _ in rounds) // n}, kernel n/a, total n/a ins/req"
    u, k = min(rounds, key=lambda r: r[0] + r[1])
    return (f"{label} summary (min total of {len(rounds)}): user {u // n}, kernel {k // n}, "
            f"total {(u + k) // n} ins/req")


def main(argv):
    if len(argv) == 5 and argv[1] == "summary":  # summary <label> <n> <file of "U K" lines>
        rows = [l.split() for l in open(argv[4]) if l.strip()]
        print(summary(argv[2], [(int(u), None if k == "-" else int(k)) for u, k in rows], int(argv[3])))
        return 0
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
