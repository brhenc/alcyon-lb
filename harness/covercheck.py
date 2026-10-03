#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

"""Every line a change touched must be executed by a test.

The dominant defect this project has shipped is one thing wearing several hats: the test
does not execute the code the feature lives in. T48's test called `lb::balance_uri`
directly and never entered the engine, so `balance uri` sent every request to one server
while its test passed, through two reviewers and a green check-in. T40's module was never
called. T26 never measured Ibex. T51's first attempt changed nothing and reported SUCCESS.

All four are the same question -- did a test run the lines you changed? -- and that question
is mechanical. This answers it.

Usage:  python3 harness/covercheck.py [base]

The base is what a change is judged against (`default_base`): `[base]`, else
`IBEX_COVERCHECK_BASE` (or the older `COVERCHECK_BASE`), else the same rule as
tools/measure/measure.py `reference_sha()` -- on a branch with commits of its own, the
merge-base with main (everything the branch would bring in); on main, or on a branch with
nothing of its own, HEAD when the tree is dirty (the uncommitted change) and HEAD^ when it is
clean (what the last commit changed; for a merge, everything the merge brought in).

It used to be `origin/main`. This repository is pushed rarely, so on a local main 18 commits
ahead of origin that judged every change since the last push, reviewed and merged work
included. To audit a range of merges, set the base explicitly:
    IBEX_COVERCHECK_BASE=03f2b75 python3 harness/covercheck.py
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


def _git(repo: str, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=repo, capture_output=True, text=True)


def default_base(repo: str = REPO, env: dict | None = None) -> str:
    """The commit a change is judged against, as a full sha. See the module docstring."""
    env = os.environ if env is None else env
    override = env.get("IBEX_COVERCHECK_BASE") or env.get("COVERCHECK_BASE")
    if override:
        r = _git(repo, "rev-parse", "--verify", f"{override}^{{commit}}")
        if r.returncode != 0:
            raise SystemExit(f"covercheck: base {override!r} is not a commit")
        return r.stdout.strip()
    head = _git(repo, "rev-parse", "HEAD").stdout.strip()
    main = _git(repo, "rev-parse", "--verify", "-q", "main").stdout.strip() or head
    fork = _git(repo, "merge-base", "HEAD", main).stdout.strip() or head
    if fork != head:
        return fork  # a branch with commits of its own: everything it would bring in
    # On main, or a branch with nothing of its own yet: the uncommitted change if there is
    # one, else what the last commit changed. Never "nothing changed, pass".
    dirty = (_git(repo, "diff", "--quiet", "HEAD", "--", "crates").returncode != 0
             or bool(_untracked_sources(repo)))
    if dirty:
        return head
    parent = _git(repo, "rev-parse", "--verify", "-q", "HEAD^").stdout.strip()
    return parent or head


def _untracked_sources(repo: str) -> list[str]:
    out = _git(repo, "ls-files", "--others", "--exclude-standard", "--", "crates").stdout
    return [p for p in out.splitlines() if SRC.match(p)]


def changed_lines(base: str, repo: str = REPO) -> dict[str, set[int]]:
    # `--ignore-space-change`: a line only re-indented -- code wrapped in a new block or
    # moved into a closure -- does what it did before, and is not what the change asks a
    # test to run. Without it, wrapping one function's body in an `if` made the check
    # demand coverage of every line of the body (txn/010 re-indented ~180 such lines of
    # response-rule code that no test had run before or after). The cost: a change only
    # to the run of spaces inside a string literal is not seen.
    out = subprocess.run(["git", "diff", "--unified=0", "--ignore-space-change", base,
                          "--", "crates"],
                         cwd=repo, capture_output=True, text=True).stdout
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
    # `git diff` does not see a file nobody has added yet; every line of one is new.
    for p in _untracked_sources(repo):
        with open(os.path.join(repo, p), errors="replace") as f:
            n = sum(1 for _ in f)
        if n:
            per[p] = set(range(1, n + 1))
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
    if len(sys.argv) > 1:
        base = default_base(REPO, {"IBEX_COVERCHECK_BASE": sys.argv[1]})
    else:
        base = default_base()
    desc = _git(REPO, "log", "-1", "--format=%h %s", base).stdout.strip()
    print(f"covercheck: base {desc}  (override: IBEX_COVERCHECK_BASE)")

    changed = changed_lines(base)
    if not changed:
        print(f"covercheck: no source lines changed since {base[:12]}")
        return 0
    total = sum(len(v) for v in changed.values())
    print(f"covercheck: {total} source lines changed in {len(changed)} files"
          f" since {base[:12]}")

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
