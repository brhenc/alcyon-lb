#!/usr/bin/env python3
"""Every line a change touched must be executed by a test.

The dominant defect this project has shipped is one thing wearing several hats: the test
does not execute the code the feature lives in. T48's test called `lb::balance_uri`
directly and never entered the engine, so `balance uri` sent every request to one server
while its test passed, through two reviewers and a green check-in. T40's module was never
called. T26 never measured Ibex. T51's first attempt changed nothing and reported SUCCESS.

All four are the same question -- did a test run the lines you changed? -- and that question
is mechanical. This answers it.

Usage:  python3 harness/covercheck.py [base]      # base defaults to origin/main
"""
from __future__ import annotations

import hashlib
import os
import re
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# One report per checkout: agy runs several worktrees at once, and a shared path let one
# checkout's covercheck read another's coverage.
LCOV = os.path.join(tempfile.gettempdir(),
                    f"ibex-covercheck-{hashlib.sha1(REPO.encode()).hexdigest()[:10]}.lcov")
# Only source. Tests are expected to run; that is not the question being asked.
SRC = re.compile(r"^crates/[^/]+/src/.*\.rs$")


def changed_lines(base: str) -> dict[str, set[int]]:
    out = subprocess.run(["git", "diff", "--unified=0", base, "--", "crates"],
                         cwd=REPO, capture_output=True, text=True).stdout
    per: dict[str, set[int]] = {}
    cur = None
    for line in out.splitlines():
        if line.startswith("+++ b/"):
            p = line[6:]
            cur = p if SRC.match(p) else None
        elif line.startswith("@@") and cur:
            m = re.search(r"\+(\d+)(?:,(\d+))?", line)
            if m:
                start, count = int(m.group(1)), int(m.group(2) or 1)
                if count:
                    per.setdefault(cur, set()).update(range(start, start + count))
    return per


def covered(paths: set[str]) -> tuple[dict[str, set[int]], dict[str, set[int]]]:
    env = dict(os.environ)
    # Fedora-packaged Rust, no rustup, so llvm-tools-preview is not installable that way.
    env.setdefault("LLVM_COV", "/usr/bin/llvm-cov")
    env.setdefault("LLVM_PROFDATA", "/usr/bin/llvm-profdata")
    env["PATH"] = os.path.expanduser("~/.cargo/bin") + os.pathsep + env.get("PATH", "")
    # --ignore-run-fail: the suite has two declared failures (data/suite_baseline.json).
    # Without it llvm-cov exits non-zero and writes no report, and this check silently
    # passes -- which is the failure mode that made suite.py green on everything once.
    r = subprocess.run(["cargo", "llvm-cov", "--workspace", "--no-cfg-coverage",
                        "--ignore-run-fail",
                        "--lcov", "--output-path", LCOV],
                       cwd=REPO, capture_output=True, text=True, env=env)
    if not os.path.exists(LCOV):
        print("covercheck: cargo llvm-cov produced no report; skipping")
        print((r.stderr or r.stdout)[-400:])
        return {}, {}
    # An lcov DA: record exists only for an *instrumented* line. A line with no record is
    # not executable -- a struct field, a `use`, a brace -- and must not be reported as
    # uncovered, or splitting a file of type definitions lights up every line in it.
    execd: dict[str, set[int]] = {}
    hit: dict[str, set[int]] = {}
    cur = None
    for line in open(LCOV):
        if line.startswith("SF:"):
            q = os.path.relpath(line[3:].strip(), REPO)
            cur = q if q in paths else None
        elif line.startswith("DA:") and cur:
            ln, _, cnt = line[3:].strip().partition(",")
            execd.setdefault(cur, set()).add(int(ln))
            if cnt.strip() not in ("0", ""):
                hit.setdefault(cur, set()).add(int(ln))
    return execd, hit


def main() -> int:
    base = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("COVERCHECK_BASE")
    if not base:
        ok = subprocess.run(["git", "rev-parse", "--verify", "-q", "origin/main"],
                            cwd=REPO, capture_output=True).returncode == 0
        base = "origin/main" if ok else "HEAD~1"

    changed = changed_lines(base)
    if not changed:
        print(f"covercheck: no source lines changed since {base}")
        return 0
    total = sum(len(v) for v in changed.values())
    print(f"covercheck: {total} source lines changed in {len(changed)} files since {base}")

    execd, hitmap = covered(set(changed))
    if not execd:
        return 0  # reported above; an unavailable tool is not a gate failure

    # Only judge lines the compiler actually instrumented.
    misses = {f: sorted((ls & execd.get(f, set())) - hitmap.get(f, set()))
              for f, ls in changed.items()}
    misses = {f: ls for f, ls in misses.items() if ls}
    executable = sum(len(ls & execd.get(f, set())) for f, ls in changed.items())
    hit = executable - sum(len(v) for v in misses.values())
    print(f"covercheck: {hit}/{executable} executable changed lines are executed by a test"
          f"  ({total} changed, {total - executable} not executable)")
    if not misses:
        print("covercheck: clean")
        return 0
    print("covercheck: changed lines NO test executes")
    for f, ls in sorted(misses.items()):
        shown = ", ".join(str(x) for x in ls[:12]) + (" ..." if len(ls) > 12 else "")
        print(f"   {f}: {shown}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
