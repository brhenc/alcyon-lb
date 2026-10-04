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
import threading
import time

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


def _llvm_env() -> dict:
    env = dict(os.environ)
    # Fedora-packaged Rust, no rustup, so llvm-tools-preview is not installable that way.
    env.setdefault("LLVM_COV", "/usr/bin/llvm-cov")
    env.setdefault("LLVM_PROFDATA", "/usr/bin/llvm-profdata")
    env["PATH"] = os.path.expanduser("~/.cargo/bin") + os.pathsep + env.get("PATH", "")
    return env


def covered(paths: set[str]) -> tuple[dict[str, set[int]], dict[str, set[int]]] | None:
    if os.path.exists(LCOV):
        os.unlink(LCOV)
    ok = run_serial() if os.environ.get("COVERCHECK_SERIAL") == "1" else run_pooled()
    if not ok:
        return None
    if not os.path.exists(LCOV):
        # T143: no report is not "nothing to judge". The gate once passed this section with
        # a corrupt profile and no report at all.
        print("covercheck: no coverage report was produced; FAILING, not skipping")
        return None
    return read_lcov(paths)


def run_pooled() -> bool:
    """The tests, instrumented, through suite.py's pool (T116): `cargo llvm-cov` runs the
    workspace's 130 test binaries one after another, which made this the slowest section
    of the gate. Same build (`cargo llvm-cov show-env`), same target directory as
    `cargo llvm-cov` uses, the same tests; failures are ignored as `--ignore-run-fail`
    ignores them (the suite section judges them), a hung binary is not.

    False when a test binary hung: a gate that cannot finish has not passed."""
    env = _llvm_env()
    # `cargo llvm-cov` builds into `<target>/llvm-cov-target`. `show-env` takes the
    # directory as given and `report` appends `llvm-cov-target` itself, so each is told
    # what makes them meet there.
    outer = env.get("CARGO_TARGET_DIR") or os.path.join(REPO, "target")
    env["CARGO_TARGET_DIR"] = os.path.join(outer, "llvm-cov-target")
    # --no-rustc-wrapper: with cargo-llvm-cov's wrapper, a build into a directory it has not
    # built before left most crates (ibex-sample, ibex-rt ...) uninstrumented: 22 of 148
    # binaries wrote a profile, every changed line read as "not executed" or, worse, the
    # report held none of them and covercheck passed. RUSTFLAGS instruments everything.
    show = subprocess.run(["cargo", "llvm-cov", "show-env", "--sh", "--no-cfg-coverage",
                           "--no-rustc-wrapper"],
                          cwd=REPO, capture_output=True, text=True, env=env)
    for line in show.stdout.splitlines():
        m = re.match(r"export (\w+)='(.*)'$", line)
        if m:
            env[m.group(1)] = m.group(2)
    # Old profiles would count lines an earlier tree's tests ran.
    tdir = env["CARGO_TARGET_DIR"]
    for f in os.listdir(tdir) if os.path.isdir(tdir) else []:
        if f.endswith(".profraw"):
            os.unlink(os.path.join(tdir, f))
    os.environ.clear()
    os.environ.update(env)
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import suite  # noqa: E402 -- reads os.environ when it runs, not when imported
    print("covercheck: running every test target instrumented, "
          f"{suite.JOBS} at a time, {suite.TARGET_TIMEOUT}s each at most", flush=True)
    r = suite.run_parallel(doc=False)
    if r is None:
        print("covercheck: the instrumented tests do not build; skipping")
        return True
    _failing, failed_tests, passed, failed_n = r
    print(f"covercheck: {passed} tests passed, {failed_n} failed (the suite section judges those)")
    for target, names in sorted(failed_tests.items()):
        print(f"   instrumented, failed: {target}: {', '.join(sorted(names))}")
    if any("<hung>" in t for t in failed_tests.values()):
        print("covercheck: a test binary hung (SUITE_TIMEOUT)")
        return False
    stale = prune_stale_binaries(os.path.join(tdir, "debug", "deps"), suite.built_executables)
    if stale:
        print(f"covercheck: removed {stale} test binaries an earlier build left in deps/")
    profraws = sum(f.endswith(".profraw") for f in os.listdir(tdir))
    binaries = _test_binaries(os.path.join(tdir, "debug", "deps"))
    if not enough_profiles(profraws, binaries):
        print(f"covercheck: only {profraws} profiles written by {binaries} test binaries: the "
              "build was not instrumented, so this report cannot judge anything")
        return False
    dropped = drop_corrupt_profiles(tdir, env)
    if dropped:
        print(f"covercheck: dropped {len(dropped)} corrupt profile(s) of {profraws}: "
              + ", ".join(dropped[:8]) + (" ..." if len(dropped) > 8 else ""))
    if not has_profiles(tdir):
        print("covercheck: no usable profile: no report can be made")
        return False
    rep = subprocess.run(["cargo", "llvm-cov", "report", "--lcov", "--output-path", LCOV],
                         cwd=REPO, capture_output=True, text=True, env={**env, "CARGO_TARGET_DIR": outer})
    if rep.returncode != 0:
        print((rep.stderr or rep.stdout)[-600:])
        return False
    return True


def has_profiles(tdir: str) -> bool:
    return any(f.endswith(".profraw") for f in os.listdir(tdir))


def drop_corrupt_profiles(tdir: str, env: dict) -> list[str]:
    """Deletes the `.profraw` files `llvm-profdata` cannot read (T143) and returns their
    names. One bad file fails the whole merge `cargo llvm-cov report` does. The common case,
    all good, costs one merge."""
    prof = env.get("LLVM_PROFDATA", "llvm-profdata")
    names = sorted(f for f in os.listdir(tdir) if f.endswith(".profraw"))

    def ok(files: list[str]) -> bool:
        r = subprocess.run([prof, "merge", "-o", os.devnull, *[os.path.join(tdir, f) for f in files]],
                           capture_output=True, env=env)
        return r.returncode == 0

    if not names or ok(names):
        return []
    bad = [f for f in names if not ok([f])]
    for f in bad:
        os.unlink(os.path.join(tdir, f))
    return bad


def prune_stale_binaries(deps: str, current: set[str]) -> int:
    """Deletes the executables in deps/ this build did not produce, and counts them.

    `cargo llvm-cov report` reads every executable there. An earlier tree's test binary
    (same target, another hash) carries that tree's line numbers, none executed in this run,
    and the report then marks comments and blank lines of the current tree "not executed"."""
    # By inode: cargo names a binary target by its uplifted copy (target/debug/ibex), a hard
    # link of the one in deps/ that the report reads.
    def inode(p):
        st = os.stat(p)
        return st.st_dev, st.st_ino
    keep = {inode(p) for p in current if os.path.exists(p)}
    n = 0
    for f in os.listdir(deps) if os.path.isdir(deps) else []:
        path = os.path.join(deps, f)
        if ("." not in f and os.path.isfile(path) and os.access(path, os.X_OK)
                and inode(path) not in keep):
            os.unlink(path)
            n += 1
    return n


def _test_binaries(deps: str) -> int:
    """Executables in cargo's deps directory (hash-suffixed, no extension)."""
    n = 0
    for f in os.listdir(deps) if os.path.isdir(deps) else []:
        path = os.path.join(deps, f)
        if "." not in f and os.path.isfile(path) and os.access(path, os.X_OK):
            n += 1
    return n


def enough_profiles(profraws: int, binaries: int) -> bool:
    """An instrumented binary writes a profile when it exits; far fewer profiles than
    binaries means most of the build was not instrumented. (Merge pools and build scripts
    make the two counts differ a little, hence a half, not equality.)"""
    return binaries == 0 or profraws * 2 >= binaries


def run_serial() -> bool:
    """`cargo llvm-cov` running the tests itself, one binary after another
    (`COVERCHECK_SERIAL=1`)."""
    env = _llvm_env()
    # --ignore-run-fail: the suite has two declared failures (data/suite_baseline.json).
    # Without it llvm-cov exits non-zero and writes no report, and this check silently
    # passes -- which is the failure mode that made suite.py green on everything once.
    # A heartbeat while it runs (minutes, all output captured), so a stuck test shows as
    # a stuck test: the newest test binary llvm-cov started, and for how long.
    stop = threading.Event()
    t0 = time.monotonic()

    def heartbeat():
        while not stop.wait(30):
            newest = subprocess.run(["pgrep", "-n", "-f", "llvm-cov-target/debug/deps/"],
                                    capture_output=True, text=True).stdout.strip()
            what = ""
            if newest:
                try:
                    exe = os.path.basename(open(f"/proc/{newest}/cmdline").read().split("\0")[0])
                    secs = time.time() - os.stat(f"/proc/{newest}").st_mtime
                    what = f"; running {exe} ({secs:.0f}s)"
                except OSError:
                    pass
            print(f"   ... covercheck {time.monotonic() - t0:.0f}s{what}", flush=True)

    threading.Thread(target=heartbeat, daemon=True).start()
    try:
        r = subprocess.run(["cargo", "llvm-cov", "--workspace", "--no-cfg-coverage",
                            "--ignore-run-fail",
                            "--lcov", "--output-path", LCOV],
                           cwd=REPO, capture_output=True, text=True, env=env,
                           timeout=int(os.environ.get("COVERCHECK_TIMEOUT", "1800")))
    except subprocess.TimeoutExpired:
        print("covercheck: cargo llvm-cov ran past COVERCHECK_TIMEOUT -- a test is hung")
        return False
    finally:
        stop.set()
    if not os.path.exists(LCOV):
        print("covercheck: cargo llvm-cov produced no report")
        print((r.stderr or r.stdout)[-400:])
    return True


def read_lcov(paths: set[str]) -> tuple[dict[str, set[int]], dict[str, set[int]]]:
    if not os.path.exists(LCOV):
        print("covercheck: no coverage report; skipping")
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

    result = covered(set(changed))
    if result is None:
        return 1  # hung: a gate that cannot finish has not passed
    execd, hitmap = result
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
