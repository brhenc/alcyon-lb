#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

"""A hand-written per-thread cache is a defect (AGENTS.md section 8, design/memory-2026-10-24.md 7c).

Greps crates/*/src (not crates/ibex-alloc, not tests/) for `thread_local!` blocks whose body
holds a cache-shaped type: RefCell<Vec<, RefCell<VecDeque<, Cell<Option<Vec<,
Cell<Option<String> or Vec<Box<. A match not in ALLOWLIST fails, with file, line and the rule.

ALLOWLIST is today's list (design 2.1). Each entry names the slice that removes it; S4 leaves
it empty and deletes the mechanism. Keyed by (file, static name) so a line move does not
break it; a new static in an allowlisted file is not allowlisted.

    python3 harness/pool_layout.py [repo-root]
"""
import os
import re
import sys

RULE = ("AGENTS.md section 8: a cache, pool, spare list or arena is an ibex_alloc::Pool/Arena "
        "(docs/design/memory-2026-10-24.md), or it does not exist")

PATTERNS = ("RefCell<Vec<", "RefCell<VecDeque<", "Cell<Option<Vec<", "Cell<Option<String>",
            "Vec<Box<")

# (file under the repo root, static name) -> slice that removes it
ALLOWLIST: dict[tuple[str, str], str] = {
    # design 2.1: spare strings, scratch strings/bytes and header lists
    ("crates/ibex-sample/src/spare.rs", "SPARE"): "S1",
    ("crates/ibex-rt/src/reuse.rs", "STR_SLOT"): "S1",
    ("crates/ibex-rt/src/reuse.rs", "STR_SLOT2"): "S1",
    ("crates/ibex-rt/src/reuse.rs", "BYTES_SLOT"): "S1",
    ("crates/ibex-rt/src/reuse.rs", "BYTES_SLOT2"): "S1",
    ("crates/ibex-rt/src/reuse.rs", "SPARE_LISTS"): "S1",
    # design 2.1: log lines, captures, variable stores, check runs, stats rows, scrape boxes,
    # queue waits
    ("crates/ibex-rt/src/logfmt.rs", "LINE_SPARE"): "S3",
    ("crates/ibex-rt/src/txnlog.rs", "CAPTURE_SPARE"): "S3",
    ("crates/ibex-sample/src/vars.rs", "SPARE"): "S3",
    ("crates/ibex-rt/src/check.rs", "RUN_POOL"): "S3",
    ("crates/ibex-rt/src/stats.rs", "ROW_POOL"): "S3",
    ("crates/ibex-rt/src/proxy.rs", "SCRAPE_BOXES"): "S3",
    ("crates/ibex-rt/src/proxy.rs", "QUEUED"): "S3",
    # not in design 2.1 (found by this script on d8e1b801): per-thread scratch of the same
    # shape; S3 puts them on Pool or shows they are not caches
    ("crates/ibex-rt/src/ring.rs", "SCRATCH"): "S3",
    ("crates/ibex-rt/src/syslog.rs", "LINE"): "S3",
    ("crates/ibex-sample/src/registry.rs", "CURRENT_RES_HEADERS"): "S3",
    # not caches (parse-time and runtime-hand-off state); S4 decides: move out of the pattern
    # or delete the entry with the mechanism
    ("crates/ibex-config/src/ast/userlist.rs", "USERLISTS"): "S4",
    ("crates/ibex-sample/src/registry.rs", "DEBUG_DESTS"): "S4",
}

SKIP_CRATES = {"ibex-alloc"}


def thread_local_blocks(text: str):
    """Yields (start offset of the body, body) for each thread_local! { ... } / ( ... )."""
    for m in re.finditer(r"\bthread_local!\s*([{(\[])", text):
        open_c = m.group(1)
        close_c = {"{": "}", "(": ")", "[": "]"}[open_c]
        depth, i = 1, m.end()
        while i < len(text) and depth:
            c = text[i]
            if c == open_c:
                depth += 1
            elif c == close_c:
                depth -= 1
            i += 1
        yield m.end(), text[m.end():i - 1]


def scan_file(path: str, rel: str):
    """Returns [(line, static name, pattern)] for the cache-shaped statics of one file."""
    text = open(path, encoding="utf-8", errors="replace").read()
    found = []
    for start, body in thread_local_blocks(text):
        # one static per `static NAME:` in the block; judge each declaration by its own text
        decls = list(re.finditer(r"\bstatic\s+([A-Za-z_][A-Za-z0-9_]*)\s*:", body))
        for k, d in enumerate(decls):
            end = decls[k + 1].start() if k + 1 < len(decls) else len(body)
            chunk = body[d.start():end]
            for pat in PATTERNS:
                idx = chunk.find(pat)
                if idx >= 0:
                    off = start + d.start() + idx
                    found.append((text.count("\n", 0, off) + 1, d.group(1), pat))
                    break
    return found


def scan(root: str):
    hits = []
    crates = os.path.join(root, "crates")
    for crate in sorted(os.listdir(crates)) if os.path.isdir(crates) else []:
        if crate in SKIP_CRATES:
            continue
        src = os.path.join(crates, crate, "src")
        for dp, dn, fn in os.walk(src):
            dn[:] = [d for d in dn if d != "tests"]
            for f in sorted(fn):
                if f.endswith(".rs"):
                    p = os.path.join(dp, f)
                    rel = os.path.relpath(p, root)
                    for line, name, pat in scan_file(p, rel):
                        hits.append((rel, line, name, pat))
    return hits


def violations(root: str, allowlist=None):
    allowlist = ALLOWLIST if allowlist is None else allowlist
    return [h for h in scan(root) if (h[0], h[2]) not in allowlist]


def main(argv) -> int:
    root = argv[1] if len(argv) > 1 else os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    bad = violations(root)
    for rel, line, name, pat in bad:
        print(f"{rel}:{line}: thread_local! static {name} holds `{pat}`: {RULE}")
    if bad:
        print(f"pool_layout: {len(bad)} hand-written per-thread cache(s) not on the allowlist")
        return 1
    print(f"pool_layout: ok ({len(ALLOWLIST)} allowlisted)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
