#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

"""Inventory every clippy suppression in the tree.

`cargo clippy -D warnings` exiting 0 means nothing on its own if the lints were turned
off one `#[allow]` at a time. This counts what is suppressed, where, and how broadly, so
the number can be watched instead of discovered. Chasing one of these -- a sign-loss cast
in the date code -- turned up a wrong leap-day calculation and a reachable panic, which
is the argument for treating the list as work rather than as settled.
"""
from __future__ import annotations
import re, subprocess, sys
from collections import Counter, defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
ALLOW = re.compile(r'#!?\[allow\(([^)]*)\)\]')

# Suppressions that say "this lint does not apply to this kind of code", as opposed to
# "this cast might be wrong and nobody checked".
BENIGN = {
    "clippy::too_many_lines",        # a flat registration table is meant to be flat
    "clippy::implicit_hasher",       # writes into a concretely-typed thread-local
    "clippy::module_name_repetitions",
    "clippy::struct_excessive_bools",
    "clippy::many_single_char_names",
    "clippy::unusual_byte_groupings",
    "clippy::needless_range_loop",
    "clippy::items_after_statements",
    "clippy::chunks_exact_to_as_chunks",
    "dead_code",
}
# Suppressions over an arithmetic conversion. Each one is a place where a value can
# change meaning -- wrap negative, truncate high bits -- with no check that it cannot.
NUMERIC = {
    "clippy::cast_possible_truncation",
    "clippy::cast_possible_wrap",
    "clippy::cast_sign_loss",
    "clippy::cast_precision_loss",
}

def main() -> int:
    files = subprocess.run(["git", "ls-files", "*.rs"], cwd=REPO,
                           capture_output=True, text=True).stdout.split()
    by_file: dict[str, Counter] = defaultdict(Counter)
    blanket: list[tuple[str, int, str]] = []
    total = Counter()

    for rel in files:
        for n, line in enumerate(( REPO / rel).read_text().splitlines(), 1):
            m = ALLOW.search(line)
            if not m:
                continue
            lints = [x.strip() for x in m.group(1).split(",") if x.strip()]
            for lint in lints:
                by_file[rel][lint] += 1
                total[lint] += 1
                if lint in ("clippy::all", "clippy::pedantic", "warnings"):
                    blanket.append((rel, n, lint))

    grand = sum(total.values())
    numeric = sum(c for l, c in total.items() if l in NUMERIC)
    benign = sum(c for l, c in total.items() if l in BENIGN)
    other = grand - numeric - benign

    print(f"{grand} clippy suppressions across {len(by_file)} files\n")
    print(f"  {numeric:4d}  numeric conversion  -- a value can change meaning here")
    print(f"  {benign:4d}  stylistic           -- the lint does not fit the code")
    print(f"  {other:4d}  other\n")

    if blanket:
        print("BLANKET suppressions (these hide every lint, not one):")
        for rel, n, lint in blanket:
            print(f"  {rel}:{n}  {lint}")
        print()

    print("By lint:")
    for lint, count in total.most_common():
        tag = "NUMERIC" if lint in NUMERIC else ("style" if lint in BENIGN else "other")
        print(f"  {count:4d}  {tag:8s} {lint}")

    print("\nBy file (numeric only):")
    rows = [(rel, sum(c for l, c in lints.items() if l in NUMERIC))
            for rel, lints in by_file.items()]
    for rel, count in sorted((r for r in rows if r[1]), key=lambda r: -r[1]):
        print(f"  {count:4d}  {rel}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
