#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

"""Catch the regressions the unit tests structurally cannot see, in seconds.

Two things go wrong in this repository that `cargo test` will never notice, because both
are about a daemon that does not start rather than a function that returns the wrong value.

  1. A config keyword becomes an error and the proxy stops starting. On 2026-09-23 the
     `global` section was made strict about unknown keywords -- correct in itself, and the
     right message text -- but `thread-groups` appears in nearly every HAProxy reg-test, so
     208 of 312 tests could no longer launch a proxy. The board went from 7 passing to 1
     and nobody noticed for two hours. Every unit test stayed green throughout.

  2. A test that used to pass stops passing, and the full board takes four minutes, so it
     is run at the end of a session rather than at the end of a change.

This checks both in a few seconds:

  parse gate   `alcyon -c` over every reg-test config in the suite, comparing the number
               that parse against a recorded baseline. A drop is a regression even when
               no test's verdict changed, because it is the leading indicator -- the
               daemon stops starting before the assertions start failing.

  pass gate    re-runs only the tests recorded as passing. Any of them failing is a
               regression, full stop.

Usage:
    python3 harness/smoke.py                 # check against data/board_baseline.json
    python3 harness/smoke.py --accept        # record the current state as the baseline
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import vtc_runner as _vtc  # noqa: E402  -- reuse its preprocessing rather than rewriting it
import reference  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# $ALCYON_REFERENCE/haproxy/reg-tests/ (T630), set by main(): unset, the stage fails naming it.
REGTESTS = ""
BASELINE = os.path.join(REPO, "data", "board_baseline.json")
# The binary `tools/checkin.sh` just built: it builds into CARGO_TARGET_DIR, and a fixed
# `target/` here checked whatever stale binary happened to be there (or none, in a worktree).
BINARY = os.path.join(os.environ.get("CARGO_TARGET_DIR") or os.path.join(REPO, "target"), "debug", "alcyon")


def _vtc_files() -> list[str]:
    out = []
    for root, _, files in os.walk(REGTESTS):
        out.extend(os.path.join(root, f) for f in files if f.endswith(".vtc"))
    return sorted(out)


def _configs_from(path: str) -> list[str]:
    """The `haproxy ... { ... }` config blocks in a .vtc file, preprocessed.

    Reuses `vtc_runner`'s own `preprocess_haproxy_config`: it strips the `.if feature(...)`
    blocks that Alcyon's parser does not understand, and expands the `${...}` macros. Writing
    a second, cruder version of that here produced 0/449 configs parsing and would have
    reported a permanent false regression -- a gate that always fires is as useless as one
    that never does.
    """
    try:
        src = open(path, encoding="utf-8", errors="replace").read()
    except OSError:
        return []
    blocks = []
    for m in re.finditer(r"^haproxy\s+\w+[^\n{]*\{", src, re.M):
        i = src.index("{", m.start())
        depth, j = 0, i
        while j < len(src):
            if src[j] == "{":
                depth += 1
            elif src[j] == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        body = src[i + 1:j]
        if len(body.strip()) < 20:          # the empty first block of `-conf-BAD {} {...}`
            continue
        macros = {"testdir": os.path.dirname(path), "tmpdir": "/tmp"}
        # vtest names servers s1..sN and proxies h1..hN, and a config referring to an
        # unseeded one fails on the macro rather than on anything Alcyon did. Seed generously:
        # an unseeded macro is a false regression, which is the failure mode that makes a
        # gate get ignored.
        for i in range(1, 10):
            for kind, port in (("s", 8100), ("h", 8200), ("c", 8300)):
                macros[f"{kind}{i}_addr"] = "127.0.0.1"
                macros[f"{kind}{i}_port"] = str(port + i)
                macros[f"{kind}{i}_sock"] = f"127.0.0.1:{port + i}"
        eng = _vtc.MacroEngine(macros)
        try:
            body, _ = _vtc.preprocess_haproxy_config(body, eng, "h1")
        except Exception:
            continue                        # unpreprocessable is the runner's problem, not ours
        blocks.append(body)
    return blocks


def parse_gate() -> tuple[int, int, list[str]]:
    """How many reg-test configs does `alcyon -c` accept?"""
    ok = 0
    total = 0
    rejected: list[str] = []
    with tempfile.TemporaryDirectory() as td:
        cfg = os.path.join(td, "c.cfg")
        for path in _vtc_files():
            for body in _configs_from(path):
                total += 1
                with open(cfg, "w") as f:
                    f.write(body)
                r = subprocess.run([BINARY, "-c", "-f", cfg],
                                   capture_output=True, text=True, timeout=20)
                if r.returncode == 0:
                    ok += 1
                else:
                    first = (r.stdout + r.stderr).strip().splitlines()
                    rejected.append(f"{os.path.relpath(path, REGTESTS)}: "
                                    f"{first[0][:110] if first else '(no message)'}")
    return ok, total, rejected


def pass_gate(expected: list[str]) -> tuple[list[str], list[str]]:
    """Re-run the tests recorded as passing. Returns (still passing, regressed)."""
    if not expected:
        return [], []
    paths = [os.path.join(REGTESTS, p) for p in expected]
    paths = [p for p in paths if os.path.exists(p)]
    with tempfile.TemporaryDirectory() as td:
        out = os.path.join(td, "r.json")
        subprocess.run([sys.executable, os.path.join(REPO, "harness", "vtc_runner.py"),
                        *paths, "--binary", BINARY, "--json", out],
                       capture_output=True, text=True, timeout=600)
        try:
            data = json.load(open(out))
        except (OSError, ValueError):
            return [], expected            # the runner itself failed: treat as total regression
    rows = data["results"] if isinstance(data, dict) and "results" in data else data
    status = {r.get("file_path", "").split("reg-tests/")[-1]: r.get("status") for r in rows}
    still = [p for p in expected if status.get(p) == "PASS"]
    gone = [p for p in expected if status.get(p) != "PASS"]
    return still, gone


def main() -> int:
    global REGTESTS
    REGTESTS = reference.require(reference.REGTESTS, who="smoke") + "/"
    ap = argparse.ArgumentParser()
    ap.add_argument("--accept", action="store_true",
                    help="record the current state as the baseline")
    args = ap.parse_args()

    if not os.path.exists(BINARY):
        print(f"smoke: {BINARY} does not exist -- run `cargo build --bin alcyon` first")
        return 2

    t0 = time.monotonic()
    base = {}
    if os.path.exists(BASELINE):
        try:
            base = json.load(open(BASELINE))
        except ValueError:
            base = {}

    ok, total, rejected = parse_gate()
    expected = base.get("passing", [])
    still, gone = pass_gate(expected)
    elapsed = time.monotonic() - t0

    if args.accept:
        # Re-derive the passing list from a full run rather than trusting the old one.
        print("smoke: --accept records the parse count only; refresh `passing` from a full")
        print("       `vtc_runner.py <reg-tests>/ --json` so the list is measured, not copied.")
        json.dump({"configs_parsed": ok, "configs_total": total,
                   "passing": expected, "rejected": rejected}, open(BASELINE, "w"), indent=1)
        open(BASELINE, "a").write("\n")
        print(f"smoke: baseline written -- {ok}/{total} configs parse, "
              f"{len(expected)} tests expected to pass")
        return 0

    prev = base.get("configs_parsed")
    print(f"=== smoke ({elapsed:.1f}s) ===")
    print(f"configs accepted by `alcyon -c`: {ok}/{total}" +
          (f"   (baseline {prev})" if prev is not None else "   (no baseline)"))
    print(f"tests still passing:           {len(still)}/{len(expected)}")

    failed = False
    if prev is not None and ok < prev:
        print(f"\n!! REGRESSION: {prev - ok} config(s) that used to parse no longer do.")
        print("   This is the shape of the thread-groups incident: the daemon stops")
        print("   starting, and no unit test can see it.")
        # The delta, not a sample of every rejection. The first version printed
        # `rejected[:5]`, which on a one-config regression showed five configs that had
        # been failing all along -- noise where the answer should have been.
        was = set(base.get("rejected", []))
        now_new = [r for r in rejected if r not in was]
        if now_new:
            print("   newly rejected:")
            for line in now_new[:10]:
                print(f"     {line}")
        else:
            print("   (no baseline rejection list recorded -- run --accept to enable the delta)")
        failed = True
    if gone:
        print(f"\n!! REGRESSION: {len(gone)} test(s) that passed no longer pass:")
        for p in gone:
            print(f"     {p}")
        failed = True

    if not failed:
        print("\nclean")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
