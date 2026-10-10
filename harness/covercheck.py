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
import json
import os
import shlex
import re
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# One report per checkout: agy runs several worktrees at once, and a shared path let one
# checkout's covercheck read another's coverage.
LCOV = os.path.join(tempfile.gettempdir(),
                    f"ibex-covercheck-{hashlib.sha1(REPO.encode()).hexdigest()[:10]}.lcov")
# Only source. Tests are expected to run; that is not the question being asked.
SRC = re.compile(r"^crates/[^/]+/src/.*\.rs$")
# What `cargo llvm-cov report` leaves out of its report (its --ignore-filename-regex, made
# relative to the workspace): a changed line in src/foo/tests.rs was never judged.
IGNORED = re.compile(r"^(.*/)?(tests|examples|benches)/|^(.*/)?(tests\.rs|[0-9a-zA-Z_-]+[_-]tests\.rs)$")
# The changed source files the report is asked about (set by `covered`).
_wanted: set[str] = set()


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
    _wanted.clear()
    _wanted.update(paths)
    ok = run_serial() if os.environ.get("COVERCHECK_SERIAL") == "1" else run_pooled()
    if not ok:
        return None
    if not os.path.exists(LCOV):
        # T143: no report is not "nothing to judge". The gate once passed this section with
        # a corrupt profile and no report at all.
        print("covercheck: no coverage report was produced; FAILING, not skipping")
        return None
    return read_lcov(paths)


# Set in the environment `instrumented_env` returns, to the instrumented target directory:
# a second call (suite.py after tools/checkin.sh exported it) returns it unchanged rather than
# nesting `llvm-cov-target` inside itself.
INSTRUMENTED = "IBEX_INSTRUMENTED"
# What suite.py leaves in the instrumented target directory after its run (T257): the test
# executables it built and ran. Its presence means the profiles beside it are that run's.
SUITE_RUN = "suite-run.json"


def instrumented_env(base: dict | None = None) -> dict:
    """The environment of the instrumented build: `cargo llvm-cov show-env`, building into
    `<target>/llvm-cov-target` as `cargo llvm-cov` does. suite.py runs the tests in it and
    leaves their profiles for covercheck (T257); tools/checkin.sh exports it for the whole
    gate (`--print-env`), so every section builds into one target directory."""
    env = _llvm_env() if base is None else dict(base)
    if env.get(INSTRUMENTED):
        return env
    env.setdefault("LLVM_COV", "/usr/bin/llvm-cov")
    env.setdefault("LLVM_PROFDATA", "/usr/bin/llvm-profdata")
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
    if "LLVM_PROFILE_FILE" not in env or "RUSTFLAGS" not in env:
        raise SystemExit("covercheck: `cargo llvm-cov show-env` failed: "
                         + (show.stderr or show.stdout).strip()[-400:])
    env[INSTRUMENTED] = env["CARGO_TARGET_DIR"]
    return env


def clear_profiles(tdir: str) -> None:
    """Old profiles would count lines an earlier tree's tests ran; an old suite-run record
    would vouch for profiles this run has not written."""
    for f in os.listdir(tdir) if os.path.isdir(tdir) else []:
        if f.endswith(".profraw") or f == SUITE_RUN:
            os.unlink(os.path.join(tdir, f))


def suite_run_reusable(tdir: str, suite) -> dict | None:
    """The record suite.py left, when its profiles are this tree's: every test executable is
    still the one it ran. `cargo test --no-run` rebuilds nothing then (a few seconds) and
    reports every artifact fresh; a source changed since, and it rebuilds (`fresh: false`)
    or names other executables, and the profiles are not this tree's."""
    try:
        rec = json.load(open(os.path.join(tdir, SUITE_RUN)))
    except (OSError, ValueError):
        return None
    if suite.test_targets() is None or not suite.build_fresh:
        return None
    if set(rec.get("executables", [])) != suite.built_executables:
        return None
    return rec


def run_pooled() -> bool:
    """The tests, instrumented, through suite.py's pool (T116): `cargo llvm-cov` runs the
    workspace's 130 test binaries one after another, which made this the slowest section
    of the gate. Same build (`cargo llvm-cov show-env`), same target directory as
    `cargo llvm-cov` uses, the same tests; failures are ignored as `--ignore-run-fail`
    ignores them (the suite section judges them), a hung binary is not.

    In the gate the suite section has already run every test in this build (T257): its
    profiles are used as they are, and nothing is built or run here again.

    False when a test binary hung: a gate that cannot finish has not passed."""
    env = instrumented_env()
    tdir = env["CARGO_TARGET_DIR"]
    os.environ.clear()
    os.environ.update(env)
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import suite  # noqa: E402 -- reads os.environ when it runs, not when imported
    rec = suite_run_reusable(tdir, suite)
    if rec is not None:
        print("covercheck: using the profiles of the suite section's run (no second build or run)",
              flush=True)
        failed_tests = rec.get("failed", {})
        r = ([], failed_tests, rec.get("passed", 0), rec.get("failed_n", 0))
    else:
        clear_profiles(tdir)
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
    t0 = time.monotonic()
    profdata = os.path.join(tdir, "covercheck.profdata")
    if os.path.exists(profdata):
        os.unlink(profdata)
    dropped = drop_corrupt_profiles(tdir, env, profdata)
    if dropped:
        print(f"covercheck: dropped {len(dropped)} corrupt profile(s) of {profraws}: "
              + ", ".join(dropped[:8]) + (" ..." if len(dropped) > 8 else ""))
    if not has_profiles(tdir):
        print("covercheck: no usable profile: no report can be made")
        return False
    if not os.path.exists(profdata):
        print("covercheck: llvm-profdata merge wrote no profile")
        return False
    t1 = time.monotonic()
    objects = report_objects(os.path.join(tdir, "debug"))
    sources = sorted(os.path.join(REPO, p) for p in _wanted
                     if not IGNORED.match(p) and os.path.exists(os.path.join(REPO, p)))
    try:
        export_lcov(profdata, objects, sources, LCOV, env)
    except RuntimeError as e:
        print(str(e)[-600:])
        return False
    print(f"covercheck: report from {profraws - len(dropped)} profiles and {len(objects)} "
          f"objects: merge {t1 - t0:.1f}s, export {time.monotonic() - t1:.1f}s")
    return True


def has_profiles(tdir: str) -> bool:
    return any(f.endswith(".profraw") for f in os.listdir(tdir))


def drop_corrupt_profiles(tdir: str, env: dict, out: str = os.devnull) -> list[str]:
    """Merges the `.profraw` files in `tdir` into `out`, deletes the ones `llvm-profdata`
    cannot read (T143) and returns their names. One bad file used to fail the whole merge
    `cargo llvm-cov report` does.

    One merge whatever the number of bad files (T254): `--failure-mode=warn` merges what it
    can read and names every file it cannot (`warning: <path>: <reason>`). The fallback this
    replaces merged each of 3557 files alone, one after another: 270 s. A file that fails
    part-way may have added the records read before the failure; those are counts a test
    really made, so the merge is not repeated without it."""
    prof = env.get("LLVM_PROFDATA", "llvm-profdata")
    names = sorted(f for f in os.listdir(tdir) if f.endswith(".profraw"))
    if not names:
        return []
    paths = {os.path.join(tdir, f): f for f in names}
    with tempfile.NamedTemporaryFile("w", prefix="covercheck-profraws-", suffix=".txt") as lst:
        lst.write("".join(p + "\n" for p in paths))
        lst.flush()
        r = subprocess.run([prof, "merge", "-sparse", "--failure-mode=warn",
                            f"--input-files={lst.name}", "-o", out],
                           capture_output=True, text=True, env=env)
    bad = []
    for line in r.stderr.splitlines():
        m = re.match(r"(?:warning|error): (.+?): ", line)
        if m and m.group(1) in paths and paths[m.group(1)] not in bad:
            bad.append(paths[m.group(1)])
    if r.returncode != 0 and len(bad) < len(names):
        # Not a bad input: the merge itself failed. No profile is written and the caller
        # says so; deleting good profiles here would hide it.
        print(f"covercheck: llvm-profdata merge failed: {r.stderr.strip()[-600:]}")
    for f in bad:
        os.unlink(os.path.join(tdir, f))
    return sorted(bad)


def report_objects(debug: str) -> list[str]:
    """The executables `cargo llvm-cov report` reads: those in debug/deps, debug/ and
    debug/examples. Each once: debug/ibex is a hard link of a file in deps/."""
    seen, objects = set(), []
    for sub in ("deps", "", "examples"):
        d = os.path.join(debug, sub)
        for f in sorted(os.listdir(d)) if os.path.isdir(d) else []:
            path = os.path.join(d, f)
            if "." in f or not os.path.isfile(path) or not os.access(path, os.X_OK):
                continue
            st = os.stat(path)
            if (st.st_dev, st.st_ino) not in seen:
                seen.add((st.st_dev, st.st_ino))
                objects.append(path)
    return objects


_SF = re.compile(rb"^SF:(.*)$", re.M)
_DA = re.compile(rb"^DA:(\d+),(\d+)", re.M)


def export_lcov(profdata: str, objects: list[str], sources: list[str], out: str, env: dict,
                jobs: int | None = None) -> None:
    """Writes an lcov report of `sources` to `out`: `jobs` `llvm-cov export`s in parallel,
    each over a share of the objects, with the counts of a line several exports carry added.

    `cargo llvm-cov report` runs one export over all objects, single-threaded (43 s for 342
    objects); this takes a few seconds. A function linked into several objects has one set
    of counters in the merged profile, so a line's sum is a multiple of the one export's
    count: zero where it is zero, which is all covercheck asks. Raises RuntimeError when an
    export fails for another reason than an object without coverage, which the one export
    skips too."""
    real = {os.path.realpath(s) for s in sources}
    counts: dict[str, dict[bytes, int]] = {}
    if not sources or not objects:
        open(out, "w").close()
        return
    cov = env.get("LLVM_COV", "llvm-cov")

    def one(group: list[str]) -> tuple[str, subprocess.CompletedProcess]:
        cmd = [cov, "export", "-format=lcov", f"-instr-profile={profdata}", group[0]]
        for o in group[1:]:
            cmd += ["-object", o]
        return group[0], subprocess.run([*cmd, "-sources", *sources], capture_output=True, env=env)

    # One export per worker over a group of objects, largest first round the groups so they
    # take about as long. Within a group llvm-cov counts a function once, as the one export
    # does; across groups the counts are added. Fewer, larger exports: the lcov text each
    # writes for engine.rs is what costs, not the export.
    jobs = min(jobs or os.cpu_count() or 8, len(objects))
    by_size = sorted(objects, key=lambda o: -os.path.getsize(o))
    groups = [by_size[i::jobs] for i in range(jobs)]
    with ThreadPoolExecutor(max_workers=jobs) as pool:
        results = list(pool.map(one, groups))
    for obj, r in results:
        if r.returncode != 0:
            if b"no coverage data found" in r.stderr:
                continue
            raise RuntimeError(f"covercheck: llvm-cov export {obj} failed: "
                               + r.stderr.decode(errors="replace"))
        # llvm-cov exports *every* file of an object when none of the -sources is in it.
        # Such an output holds none of them, so its first file says which case this is.
        first = r.stdout.find(b"SF:")
        if first < 0:
            continue
        end = r.stdout.find(b"\n", first)
        if os.path.realpath(r.stdout[first + 3:end].decode()) not in real:
            continue
        for block in r.stdout.split(b"end_of_record"):
            m = _SF.search(block)
            if not m:
                continue
            sf = m.group(1).decode()
            if os.path.realpath(sf) not in real:
                continue
            cur = counts.setdefault(sf, {})
            for ln, cnt in _DA.findall(block):
                cur[ln] = cur.get(ln, 0) + int(cnt)
    with open(out, "w") as f:
        for sf in sorted(counts):
            f.write(f"SF:{sf}\n")
            for ln in sorted(counts[sf], key=int):
                f.write(f"DA:{int(ln)},{counts[sf][ln]}\n")
            f.write("end_of_record\n")


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


def print_env() -> int:
    """`--print-env`: the instrumented build's environment as shell `export`s, for
    tools/checkin.sh to `eval` so the whole gate builds into one target directory (T257)."""
    env = instrumented_env()
    for k in sorted(env):
        if os.environ.get(k) != env[k]:
            print(f"export {k}={shlex.quote(env[k])}")
    return 0


def main() -> int:
    if sys.argv[1:] == ["--print-env"]:
        return print_env()
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
