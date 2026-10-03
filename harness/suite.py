#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

"""Run every test in the workspace and compare against a declared baseline.

`tools/checkin.sh` named four test targets by hand. The workspace has 77, so 73 of them
never ran in the gate -- including every file an agent had added. That is how T48 shipped
`load_balancing.rs` with a red assertion and a SUCCESS report, through two reviewers and a
green check-in: nothing ran the file. A test that exists and is never run is worse than no
test, because it is counted as coverage.

Two things make this usable as a gate rather than noise:

  * A failing target is re-run **alone**, `ALONE_RUNS` times. A test that fails in any of
    those runs is a confirmed failure. One that failed only in the parallel run is
    *flaky*: it is named, and it fails the gate like any other failure unless the
    baseline lists it with a reason. This script used to re-run once and call a
    single pass "flaky, not counted", and `keepalive_binary` was then excused while it
    failed alone 4 runs in 12. A flake is a race in the test or in ibex, and the gate
    is where it gets noticed.

  * Known failures live in `data/suite_baseline.json` with a reason each
    (`known_failures`, and `known_flaky` for parallel-only failures). A *new* failure
    fails the gate. A baselined entry that no longer fails is reported too, so the
    baseline gets tightened instead of quietly protecting a test that no longer needs it.

Usage:  python3 harness/suite.py            # gate
        python3 harness/suite.py --accept   # rewrite the baseline from this run
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASELINE = os.path.join(REPO, "data", "suite_baseline.json")

# The names must exclude the backtick cargo wraps the line in: a greedy \S+ swallows it,
# `cargo test --test resolver_behavior\`` then matches no target, exits 0, and every real
# failure is silently reclassified as a flake. That made the gate pass everything once.
TARGET_RE = re.compile(r"^\s+`?-p ([^\s`]+) --test ([^\s`]+)`?\s*$")
FAIL_RE = re.compile(r"^test (\S+) \.\.\. FAILED\s*$", re.M)
# `     Running tests/foo.rs (target/debug/deps/foo-0123abcd)`, one per test binary.
RUNNING_RE = re.compile(r"^\s+Running (?:unittests )?(?:\S+/)?([^/\s]+?)(?:\.rs)? \(\S+\)\s*$")
ALONE_RUNS = 3


def run(args: list[str], timeout: int = 1800) -> str:
    # One stream, interleaved as written: cargo prints `Running <target>` on stderr and the
    # test results on stdout, and `failed_by_target` needs them in order.
    p = subprocess.run(args, cwd=REPO, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       text=True, timeout=timeout)
    return p.stdout


def failing_targets(out: str) -> list[tuple[str, str]]:
    """The `-p PKG --test TARGET` lines cargo prints after `error: N targets failed:`."""
    targets, collecting = [], False
    for line in out.splitlines():
        if line.startswith("error:") and "targets failed" in line:
            collecting = True
            continue
        if collecting:
            m = TARGET_RE.match(line)
            if m:
                targets.append((m.group(1), m.group(2)))
            elif line.strip():
                break
    return targets


def failed_by_target(out: str) -> dict[str, set[str]]:
    """The failing tests of each test binary in a cargo run, keyed by target name."""
    failed: dict[str, set[str]] = {}
    target = None
    for line in out.splitlines():
        m = RUNNING_RE.match(line)
        if m:
            target = m.group(1)
            continue
        f = FAIL_RE.match(line)
        if f and target:
            failed.setdefault(target, set()).add(f.group(1))
    return failed


def confirm(pkg: str, target: str) -> tuple[set[str], int]:
    """Re-run one target alone `ALONE_RUNS` times.

    Returns the tests that failed in any of those runs, and how many runs failed. A run that
    fails without naming a test (a crash, a timeout) counts as the whole target failing."""
    failed: set[str] = set()
    bad_runs = 0
    for _ in range(ALONE_RUNS):
        p = subprocess.run(["cargo", "test", "-p", pkg, "--test", target, "--no-fail-fast"],
                           cwd=REPO, capture_output=True, text=True, timeout=1800)
        names = set(FAIL_RE.findall(p.stdout + p.stderr))
        if p.returncode != 0:
            bad_runs += 1
            failed |= names or {"<target>"}
    return failed, bad_runs


def main() -> int:
    accept = "--accept" in sys.argv
    print("suite: running every test target in the workspace")
    out = run(["cargo", "test", "--workspace", "--no-fail-fast"])

    targets = failing_targets(out)
    if not targets and "error:" in out and "targets failed" in out:
        print("suite: could not parse cargo's failing-target list; treating as failure")
        return 1

    in_parallel = failed_by_target(out)
    confirmed: dict[str, str] = {}
    flaky: dict[str, str] = {}
    for pkg, target in targets:
        still, bad_runs = confirm(pkg, target)
        for name in still:
            confirmed[f"{pkg}/{target}::{name}"] = ""
        if still:
            print(f"   {pkg}/{target}: fails alone in {bad_runs}/{ALONE_RUNS} runs")
        # A target whose parallel results could not be read: flaky only if it then passed
        # alone every time.
        only_parallel = in_parallel.get(target, set() if still else {"<target>"}) - still
        for name in sorted(only_parallel):
            flaky[f"{pkg}/{target}::{name}"] = ""
            print(f"   {pkg}/{target}::{name}: failed in the parallel run, passes alone "
                  f"{ALONE_RUNS}/{ALONE_RUNS} -- flaky")

    doc = json.load(open(BASELINE)) if os.path.exists(BASELINE) else {}
    base = doc.get("known_failures", {})
    base_flaky = doc.get("known_flaky", {})

    new = sorted(k for k in confirmed if k not in base)
    new_flaky = sorted(k for k in flaky if k not in base_flaky and k not in base)
    fixed = sorted(k for k in base if k not in confirmed)

    if accept:
        unstated = "recorded by --accept; reason not stated"
        doc = {"known_failures": {k: base.get(k, unstated) for k in confirmed},
               "known_flaky": {k: base_flaky.get(k, unstated) for k in flaky}}
        json.dump(doc, open(BASELINE, "w"), indent=1, sort_keys=True)
        open(BASELINE, "a").write("\n")
        print(f"suite: baseline rewritten with {len(confirmed)} known failures, "
              f"{len(flaky)} known flaky")
        return 0

    print(f"suite: {len(confirmed)} confirmed failing, {len(flaky)} flaky, "
          f"{len(base)} + {len(base_flaky)} baselined")
    for k in fixed:
        print(f"   now passing (tighten the baseline): {k}")
    # A known-flaky test that passed this time proves nothing, so it is not reported as fixed.
    if new or new_flaky:
        print("suite: NEW FAILURES")
        for k in new:
            print(f"   {k}")
        for k in new_flaky:
            print(f"   {k} (flaky: parallel run only)")
        return 1
    print("suite: clean" + (" (baselined failures unchanged)" if base else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
