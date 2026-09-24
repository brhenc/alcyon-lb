#!/usr/bin/env python3
"""Run every test in the workspace and compare against a declared baseline.

`tools/checkin.sh` named four test targets by hand. The workspace has 77, so 73 of them
never ran in the gate -- including every file an agent had added. That is how T48 shipped
`load_balancing.rs` with a red assertion and a SUCCESS report, through two reviewers and a
green check-in: nothing ran the file. A test that exists and is never run is worse than no
test, because it is counted as coverage.

Two things make this usable as a gate rather than noise:

  * A failing target is re-run **alone** before it counts. `tcp_proxy` passes 17/17 by
    itself and failed in the full run purely on port contention with the other targets
    running in parallel; `fc_src_is_the_real_peer_after_set_src` did the same thing
    earlier. Without the retry the gate would be red about a third of the time and would
    stop being read, which is the failure mode this script exists to fix.

  * Known failures live in `data/suite_baseline.json` with a reason each. A *new* failure
    fails the gate. A baselined failure that starts passing is reported too, so the
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


def run(args: list[str], timeout: int = 1800) -> str:
    p = subprocess.run(args, cwd=REPO, capture_output=True, text=True, timeout=timeout)
    return p.stdout + p.stderr


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


def confirm(pkg: str, target: str) -> list[str]:
    """Re-run one target alone. Returns the tests that still fail."""
    out = run(["cargo", "test", "-p", pkg, "--test", target, "--no-fail-fast"])
    return sorted(set(FAIL_RE.findall(out)))


def main() -> int:
    accept = "--accept" in sys.argv
    print("suite: running every test target in the workspace")
    out = run(["cargo", "test", "--workspace", "--no-fail-fast"])

    targets = failing_targets(out)
    if not targets and "error:" in out and "targets failed" in out:
        print("suite: could not parse cargo's failing-target list; treating as failure")
        return 1

    confirmed: dict[str, str] = {}
    for pkg, target in targets:
        still = confirm(pkg, target)
        for name in still:
            confirmed[f"{pkg}/{target}::{name}"] = ""
        flaked = set()
        if not still:
            flaked.add(target)
        if flaked:
            print(f"   {pkg}/{target}: failed in the parallel run, passes alone -- flaky, not counted")

    base = {}
    if os.path.exists(BASELINE):
        base = json.load(open(BASELINE)).get("known_failures", {})

    new = sorted(k for k in confirmed if k not in base)
    fixed = sorted(k for k in base if k not in confirmed)

    if accept:
        merged = {k: base.get(k, "recorded by --accept; reason not stated") for k in confirmed}
        json.dump({"known_failures": merged}, open(BASELINE, "w"), indent=1, sort_keys=True)
        open(BASELINE, "a").write("\n")
        print(f"suite: baseline rewritten with {len(merged)} known failures")
        return 0

    print(f"suite: {len(confirmed)} confirmed failing, {len(base)} baselined")
    for k in fixed:
        print(f"   now passing (tighten the baseline): {k}")
    if new:
        print("suite: NEW FAILURES")
        for k in new:
            print(f"   {k}")
        return 1
    print("suite: clean" + (" (baselined failures unchanged)" if base else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
