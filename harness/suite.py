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

The tests run in parallel (T116), each in a process of its own (T260). Each crate has one
integration-test binary since T260 (`tests/it/main.rs`, plus the few files that need their
own process), so a process per binary would no longer bound a hung test, isolate one test
from another or spread the work: the suite builds with `cargo test --no-run`, lists each
test binary's tests (`--list`), and runs every test as `<binary> --exact <name>`,
`SUITE_JOBS` at once, longest first, as cargo would: from the package's directory, with
cargo's `CARGO_*` variables. (Not `cargo test -p`: cargo holds the build directory's lock
while the tests run, and parallel invocations queue behind it.) Each test is killed after
`SUITE_TIMEOUT` seconds. Doc tests run through one `cargo test --doc`. A failing test is
re-run alone the same way. `SUITE_SERIAL=1` runs the single `cargo test --workspace` of
before.

Keys are `crate/target::test`, as the baseline names them: `ibex-rt/it::h3_end_to_end::x`
for a test of tests/it/h3_end_to_end.rs, `ibex-rt/request_allocations::x` for a file with
a binary of its own, `ibex-rt/lib::proxy::tests::x` for a unit test.

The tests run once per gate, instrumented (T257): in the build `cargo llvm-cov` makes
(`<target>/llvm-cov-target`, covercheck.instrumented_env), and the profiles they write are
left for covercheck, which then only merges and judges them. `COVERCHECK=0` runs the plain
build instead, the quick loop.

Usage:  python3 harness/suite.py            # gate
        python3 harness/suite.py --accept   # rewrite the baseline from this run
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASELINE = os.path.join(REPO, "data", "suite_baseline.json")

# The names must exclude the backtick cargo wraps the line in: a greedy \S+ swallows it,
# `cargo test --test resolver_behavior\`` then matches no target, exits 0, and every real
# failure is silently reclassified as a flake. That made the gate pass everything once.
TARGET_RE = re.compile(r"^\s+`?-p ([^\s`]+) --test ([^\s`]+)`?\s*$")
FAIL_RE = re.compile(r"^test (\S+) \.\.\. FAILED\s*$", re.M)
# `     Running tests/foo.rs (target/debug/deps/foo-0123abcd)`, one per test binary; a test
# target is named by its binary (`tests/it/main.rs` is `it`), a unit-test one by its source.
RUNNING_RE = re.compile(r"^\s+Running (unittests )?(?:\S+/)?([^/\s]+?)(?:\.rs)? \((\S+)\)\s*$")
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
            target = m.group(2)
            if not m.group(1):
                target = re.sub(r"-[0-9a-f]+$", "", os.path.basename(m.group(3)))
            continue
        f = FAIL_RE.match(line)
        if f and target:
            failed.setdefault(target, set()).add(f.group(1))
    return failed


RESULT_RE = re.compile(r"^test result: \w+\. (\d+) passed; (\d+) failed", re.M)
# One process per test (T260) waits more than it computes: most tests wait on ibex, a
# backend or a timer. Measured 2026-10-10, instrumented, wall with reruns (load 20-50 from
# other builds): 64 cores 8 jobs 165 s, 16 89 s, 32 56 s, 64 41 s; 8 cores (taskset) 8 jobs
# 151 s, 16 88 s, 32 58 s. Load flakes were seen at every setting, as before. 32 is the
# fastest setting measured on 8 cores and within 15 s of 64 on 64 cores, which leaves room
# for the other gate or build sharing the machine.
JOBS = int(os.environ.get("SUITE_JOBS", "32"))
# A test that runs longer than this is killed and reported as failing, so a deadlock shows
# up as a named failure instead of a gate that never ends. `SUITE_TIMEOUT` raises it.
TARGET_TIMEOUT = int(os.environ.get("SUITE_TIMEOUT", "300"))
HEARTBEAT = 15
# Set by covercheck.instrumented_env to the instrumented target directory.
INSTRUMENTED_KEY = "IBEX_INSTRUMENTED"


def say(msg: str) -> None:
    print(msg, flush=True)


def run_bounded(cmd: list[str], cwd: str, env: dict | None) -> tuple[int, str]:
    """Runs `cmd` with its output, killed after `TARGET_TIMEOUT` seconds: its whole process
    group, since under `cargo test` the hung process is cargo's child and killing cargo
    alone leaves it running. A timeout returns -9."""
    # stdin is /dev/null: inherited, it is whatever ran the gate (a socket under an agent's
    # shell), and the ibex processes the tests start inherit it in turn --
    # fd_hygiene counted it as a socket ibex had left open, and failed every run.
    p = subprocess.Popen(cmd, cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, text=True, start_new_session=True)
    try:
        out, _ = p.communicate(timeout=TARGET_TIMEOUT)
        return p.returncode, out
    except subprocess.TimeoutExpired:
        os.killpg(p.pid, 9)
        out, _ = p.communicate()
        return -9, out or ""
# Tests that measure the process or race the clock: run one at a time after the parallel
# pool, on a machine as quiet as the serial suite left it. Each was seen failing only under
# the pool's load and passing alone (2026-10-03); a name here is not an excuse -- a failure
# in the serial pass is a failure like any other. An entry is a target (`crate/target`,
# every test of it) or a module of one (`crate/it::module`), matched on `::` boundaries.
# canonical_haproxy_35_e2e left the list (T259): its stick counters are read once the
# answer has arrived and the engine is idle, no longer after a fixed number of passes.
SERIAL_TARGETS = {
    "ibex-rt/request_allocations",     # counts allocations and bytes per request
    "ibex-rt/memory_baseline",         # reads the child's VmRSS and `show pools` after fixed idle periods
    "ibex-rt/cli_applet",              # `show pools` waits a fixed 20 engine steps (T116)
    # Failed only in gates that shared the machine with another gate, passed alone (2026-10-05):
    "ibex-rt/it::fd_hygiene",          # counts /proc/<pid>/fd after the server closes (T217)
}


def is_serial(key: str) -> bool:
    """Whether the test `crate/target::test` is in `SERIAL_TARGETS`."""
    return any(key == s or key.startswith(s + "::") for s in SERIAL_TARGETS)


def listed_tests(listed: str, ignored: str) -> list[str]:
    """The tests a binary runs by default: `--list --format terse` less `--ignored`'s."""
    def names(out: str) -> list[str]:
        return [ln[:-len(": test")] for ln in out.splitlines() if ln.endswith(": test")]
    skip = set(names(ignored))
    return [n for n in names(listed) if n not in skip]


def test_verdict(rc: int, out: str) -> str:
    """One test's process: "ok", "failed", "hung" (killed after `TARGET_TIMEOUT`), or "not
    run" -- `--exact <name>` matching nothing runs nothing and exits 0, and counting that as a
    pass is how a renamed test would go silently unrun."""
    if rc == -9:
        return "hung"
    counts = RESULT_RE.findall(out)
    if rc == 0:
        return "ok" if any(int(p) + int(f) == 1 for p, f in counts) else "not run"
    return "failed"


# The pool of profiles the instrumented test processes merge into, per binary (`%Nm`).
PROFILE_POOL = 16


def pooled_profile(path: str) -> str:
    """`LLVM_PROFILE_FILE` for one process per test: `cargo llvm-cov`'s `%p` (a profile per
    process) would write one file per test, thousands of megabytes-large files; a `%Nm`
    pool merges the processes of one binary online into at most N files."""
    path = re.sub(r"%p-?", "", path)
    path = re.sub(r"%\d*m", "", path)
    stem, ext = os.path.splitext(path)
    return f"{stem.rstrip('-')}-%{PROFILE_POOL}m{ext}"


def target_dir() -> str:
    return os.environ.get("CARGO_TARGET_DIR") or os.path.join(REPO, "target")


built_executables: set[str] = set()
# Whether the last `test_targets` build rebuilt nothing (cargo reports every artifact fresh).
build_fresh = False


def test_targets() -> list[tuple[str, str, list[str], str, dict]] | None:
    """Builds every test target and lists them: (package, target, selector args for `cargo
    test`, executable, the package's metadata).

    `None` when the build fails (the caller reports it, as the serial run would)."""
    meta = json.loads(subprocess.run(["cargo", "metadata", "--no-deps", "--format-version", "1"],
                                     cwd=REPO, capture_output=True, text=True, check=True).stdout)
    pkgs = {p["manifest_path"]: p for p in meta["packages"]}
    say("suite: building the tests")
    t0 = time.monotonic()
    p = subprocess.run(["cargo", "test", "--workspace", "--no-run", "--message-format=json"],
                       cwd=REPO, capture_output=True, text=True)
    say(f"suite: built in {time.monotonic() - t0:.0f}s")
    if p.returncode != 0:
        print(p.stderr[-2000:])
        return None
    found = []
    # covercheck reports on these and nothing else (older builds' binaries share deps/).
    built_executables.clear()
    global build_fresh
    build_fresh = True
    for line in p.stdout.splitlines():
        m = json.loads(line) if line.startswith("{") else {}
        if m.get("reason") == "compiler-artifact" and not m.get("fresh", True):
            build_fresh = False
        if m.get("reason") == "compiler-artifact" and m.get("executable"):
            built_executables.add(m["executable"])
        if m.get("reason") != "compiler-artifact" or not m["profile"]["test"] or not m.get("executable"):
            continue
        kind, name = m["target"]["kind"][0], m["target"]["name"]
        p = pkgs[m["manifest_path"]]
        if kind in ("lib", "rlib", "proc-macro", "cdylib", "staticlib"):
            found.append((p["name"], "lib", ["--lib"], m["executable"], p))
        elif kind in ("bin", "test", "example", "bench"):
            # A test target keeps its bare name: the baseline's keys are `pkg/target::test`.
            key = name if kind == "test" else f"{kind}:{name}"
            found.append((p["name"], key, [f"--{kind}", name], m["executable"], p))
    return found


def cargo_env(p: dict) -> dict:
    """The environment `cargo test` runs a test binary in (cargo's `fill_env`)."""
    env = dict(os.environ)
    ver = p["version"].split("-")[0].split("+")[0].split(".")
    env.update({
        "CARGO": env.get("CARGO", "cargo"),
        "CARGO_MANIFEST_DIR": os.path.dirname(p["manifest_path"]),
        "CARGO_MANIFEST_PATH": p["manifest_path"],
        "CARGO_PKG_NAME": p["name"],
        "CARGO_PKG_VERSION": p["version"],
        "CARGO_PKG_VERSION_MAJOR": ver[0],
        "CARGO_PKG_VERSION_MINOR": ver[1] if len(ver) > 1 else "0",
        "CARGO_PKG_VERSION_PATCH": ver[2] if len(ver) > 2 else "0",
        "CARGO_PKG_VERSION_PRE": p["version"].split("-", 1)[1] if "-" in p["version"] else "",
        "CARGO_PKG_AUTHORS": ":".join(p.get("authors") or []),
        "CARGO_PKG_DESCRIPTION": p.get("description") or "",
        "CARGO_PKG_HOMEPAGE": p.get("homepage") or "",
        "CARGO_PKG_REPOSITORY": p.get("repository") or "",
        "CARGO_PKG_LICENSE": p.get("license") or "",
        "CARGO_PKG_LICENSE_FILE": p.get("license_file") or "",
        "CARGO_PKG_RUST_VERSION": p.get("rust_version") or "",
        "CARGO_PKG_README": p.get("readme") or "",
    })
    return env


def list_jobs(targets) -> list[tuple]:
    """One job per test: (package, target, test, command, cwd, env). The binaries are listed
    in parallel; a binary that cannot list its tests is one failing job named `<list>`."""
    def one(t):
        pkg, key, _sel, exe, p = t
        cwd, env = os.path.dirname(p["manifest_path"]), cargo_env(p)
        if env.get("LLVM_PROFILE_FILE"):
            env["LLVM_PROFILE_FILE"] = pooled_profile(env["LLVM_PROFILE_FILE"])
        outs = []
        for extra in ([], ["--ignored"]):
            r = subprocess.run([exe, "--list", "--format", "terse", *extra], cwd=cwd, env=env,
                               stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=120)
            if r.returncode != 0:
                return [(pkg, key, "<list>", [exe, "--list"], cwd, env)]
            outs.append(r.stdout)
        return [(pkg, key, name, [exe, "--exact", name], cwd, env) for name in listed_tests(*outs)]
    with ThreadPoolExecutor(max_workers=max(JOBS, 8)) as pool:
        return [j for js in pool.map(one, targets) for j in js]


def run_parallel(doc: bool = True) -> tuple[list[tuple], dict[str, set[str]], int, int] | None:
    """Runs every test, each in its own process, `JOBS` at once. Returns the failing jobs
    (package, target, test, command, cwd, env), the failing tests of each target (keyed by
    target), and the totals of tests passed and failed. `doc=False` leaves the doc tests out
    (covercheck: `cargo llvm-cov` does not instrument them)."""
    targets = test_targets()
    if targets is None:
        print("suite: the workspace's tests do not build")
        return None
    jobs = list_jobs(targets)
    if doc:
        jobs.append(("workspace", "doc", "<doc>", ["cargo", "test", "--workspace", "--doc", "--no-fail-fast"],
                     REPO, doc_env()))
    say(f"suite: {len(jobs)} tests in {len(targets)} test binaries" + (" and the doc tests" if doc else ""))
    # Longest first, from the last run's durations: the slowest test sets the floor.
    times_path = os.path.join(target_dir(), "suite-durations.json")
    try:
        last = json.load(open(times_path))
    except (OSError, ValueError):
        last = {}
    key = lambda j: f"{j[0]}/{j[1]}::{j[2]}"  # noqa: E731
    jobs.sort(key=lambda j: -last.get(key(j), 1000.0))

    running: dict[str, float] = {}
    done = [0]
    lock = threading.Lock()

    def one(job):
        name = key(job)
        t0 = time.monotonic()
        with lock:
            running[name] = t0
        rc, out = run_bounded(job[3], job[4], job[5])
        if rc == -9:
            say(f"   {name}: killed after {TARGET_TIMEOUT}s (SUITE_TIMEOUT) -- hung")
        with lock:
            del running[name]
            done[0] += 1
        return job, rc, out, time.monotonic() - t0

    # Progress: how many tests are done and which are running for how long, so a stuck
    # test is visible while it is stuck rather than when the gate is given up on.
    stop = threading.Event()

    def heartbeat():
        while not stop.wait(HEARTBEAT):
            with lock:
                now = time.monotonic()
                slow = sorted(running.items(), key=lambda kv: kv[1])[:4]
                busy = ", ".join(f"{n} {now - t:.0f}s" for n, t in slow)
                say(f"   ... {done[0]}/{len(jobs)} tests done; running: {busy or '-'}")

    threading.Thread(target=heartbeat, daemon=True).start()
    pooled = [j for j in jobs if not is_serial(key(j))]
    serial = [j for j in jobs if is_serial(key(j))]
    try:
        with ThreadPoolExecutor(max_workers=JOBS) as pool:
            results = list(pool.map(one, pooled))
        results += [one(j) for j in serial]
    finally:
        stop.set()
    failing, failed_tests, passed, failed_n, durations = [], {}, 0, 0, {}
    for job, rc, out, secs in results:
        pkg, tgt, test = job[0], job[1], job[2]
        durations[key(job)] = round(secs, 2)
        if tgt == "doc":
            for p_, f_ in RESULT_RE.findall(out):
                passed += int(p_)
                failed_n += int(f_)
            if rc != 0:
                failing.append(job)
                failed_tests["doc"] = set(FAIL_RE.findall(out)) or {"<hung>" if rc == -9 else "<target>"}
            continue
        verdict = test_verdict(rc, out)
        if verdict == "ok":
            passed += 1
            continue
        failed_n += 1
        failing.append(job)
        if verdict != "failed":
            say(f"   {key(job)}: {verdict}")
        # `<hung>` beside the name: covercheck fails on a hung test (its profile is lost).
        failed_tests.setdefault(tgt, set()).update({test} | ({"<hung>"} if verdict == "hung" else set()))
    try:
        json.dump(durations, open(times_path, "w"))
    except OSError:
        pass
    say(slow_targets_line(durations))
    return failing, failed_tests, passed, failed_n


def doc_env() -> dict | None:
    """The doc tests' environment. Instrumented (T257), their profiles go to a directory of
    their own that covercheck does not read: `cargo llvm-cov` without `--doctests`, which
    covercheck judged with before, does not count what a doc test runs."""
    tdir = os.environ.get(INSTRUMENTED_KEY)
    if not tdir:
        return None
    return dict(os.environ, LLVM_PROFILE_FILE=os.path.join(tdir, "doctest-profiles", "%p-%m.profraw"))


def instrument() -> str | None:
    """Switches this process to the instrumented build, `cargo llvm-cov`'s (T257), so the one
    run of the tests both judges them and leaves the profiles covercheck reads; the gate
    used to build and run every target a second time for that. Returns the instrumented
    target directory, or None when `COVERCHECK=0` asks for the plain build (the quick loop)."""
    if os.environ.get("COVERCHECK", "1") != "1":
        return None
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import covercheck  # noqa: E402
    env = covercheck.instrumented_env(dict(os.environ))
    os.environ.clear()
    os.environ.update(env)
    tdir = env["CARGO_TARGET_DIR"]
    os.makedirs(tdir, exist_ok=True)
    covercheck.clear_profiles(tdir)
    shutil.rmtree(os.path.join(tdir, "doctest-profiles"), ignore_errors=True)
    return tdir


def record_run(tdir: str, failed_tests: dict[str, set[str]], passed: int, failed_n: int) -> None:
    """Tells covercheck which executables wrote the profiles in `tdir` (covercheck.SUITE_RUN)."""
    rec = {"executables": sorted(built_executables), "passed": passed, "failed_n": failed_n,
           "failed": {k: sorted(v) for k, v in failed_tests.items()}}
    with open(os.path.join(tdir, "suite-run.json"), "w") as f:
        json.dump(rec, f, indent=1)


# A test slower than this is named after every run (informational, not a failure), so a
# new slow test is seen the day it lands: the pool's wall time is at least its slowest test.
SLOW_TARGET = 10.0


def slow_targets_line(durations: dict[str, float]) -> str:
    slow = sorted(((s, n) for n, s in durations.items() if s > SLOW_TARGET), reverse=True)
    if not slow:
        return f"suite: slow tests (over {SLOW_TARGET:.0f}s): none"
    return f"suite: slow tests (over {SLOW_TARGET:.0f}s): " + ", ".join(f"{n} {s:.1f}s" for s, n in slow)


def confirm_cmd(cmd: list[str], runs: int, cwd: str = REPO, env: dict | None = None,
                test: str | None = None) -> tuple[set[str], int]:
    """Re-runs one test (`test`, the command running it alone) or one target alone `runs`
    times.

    Returns the tests that failed in any of those runs, and how many runs failed. A run of a
    target that fails without naming a test (a crash, a timeout) counts as the whole target
    failing."""
    failed: set[str] = set()
    bad_runs = 0
    for _ in range(runs):
        rc, out = run_bounded(cmd, cwd, env)
        if test is not None:
            verdict = test_verdict(rc, out)
            if verdict != "ok":
                bad_runs += 1
                if test not in failed:
                    # The first failure's message, so a red gate says what failed.
                    why = [ln.strip() for ln in out.splitlines()
                           if "panicked at" in ln or ln.lstrip().startswith(("left:", "right:"))
                           or "assertion" in ln][:4]
                    say(f"   {test}: {verdict} alone" + "".join(f"\n      {w[:300]}" for w in why))
                failed.add(test)
            continue
        if rc == -9:
            say(f"   {' '.join(cmd)}: killed after {TARGET_TIMEOUT}s alone -- hung")
            bad_runs += 1
            failed.add("<hung>")
            continue
        names = set(FAIL_RE.findall(out))
        if rc != 0:
            bad_runs += 1
            failed |= names or {"<target>"}
    return failed, bad_runs


def main() -> int:
    accept = "--accept" in sys.argv
    doc = json.load(open(BASELINE)) if os.path.exists(BASELINE) else {}
    base = doc.get("known_failures", {})
    base_flaky = doc.get("known_flaky", {})
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import layout  # noqa: E402
        for k in sorted({**base, **base_flaky}):
            if layout.resolve_key(k) is None:
                print(f"suite: baseline entry names no test in the sources: {k}")
    except Exception as e:  # informational; harness/test_layout.py fails on these
        print(f"suite: could not check the baseline's names: {e}")

    if os.environ.get("SUITE_SERIAL") == "1":
        print("suite: running every test target in the workspace (serial)")
        out = run(["cargo", "test", "--workspace", "--no-fail-fast"])
        targets = failing_targets(out)
        if not targets and "error:" in out and "targets failed" in out:
            print("suite: could not parse cargo's failing-target list; treating as failure")
            return 1
        in_parallel = failed_by_target(out)
        # (package, target, failed in the run, command, cwd, env, test)
        units = [(pkg, t, in_parallel.get(t, set()), ["cargo", "test", "-p", pkg, "--test", t, "--no-fail-fast"],
                  REPO, None, None) for pkg, t in targets]
    else:
        tdir = instrument()
        say(f"suite: running every test in the workspace in a process of its own, {JOBS} at a time, "
            f"{TARGET_TIMEOUT}s each at most, "
            + ("instrumented (the profiles are covercheck's)" if tdir else "not instrumented (COVERCHECK=0)"))
        r = run_parallel()
        if r is None:
            return 1
        failing, in_parallel, passed, failed_n = r
        if tdir:
            # Before the reruns below: they run instrumented too, and write profiles of
            # their own beside the parallel run's. That is harmless -- llvm-profdata sums
            # the counts, and covercheck asks only whether a line's count is zero.
            record_run(tdir, in_parallel, passed, failed_n)
        print(f"suite: {passed} tests passed, {failed_n} failed, in the parallel run")
        units = [(pkg, tgt, in_parallel.get("doc", set()) if tgt == "doc" else {test}, cmd, cwd, env,
                  None if tgt == "doc" else test)
                 for pkg, tgt, test, cmd, cwd, env in failing]

    confirmed: dict[str, str] = {}
    flaky: dict[str, str] = {}
    for pkg, target, seen, cmd, cwd, env, test in units:
        # A test (or target) whose parallel failures are all declared known failures is
        # confirmed by one alone run that reproduces them; anything else gets the full
        # `ALONE_RUNS`.
        all_known = bool(seen) and all(f"{pkg}/{target}::{n}" in base for n in seen)
        still, bad_runs = confirm_cmd(cmd, 1 if all_known else ALONE_RUNS, cwd, env, test)
        runs = 1 if all_known else ALONE_RUNS
        if all_known and still != seen:
            more, more_bad = confirm_cmd(cmd, ALONE_RUNS - 1, cwd, env, test)
            still |= more
            bad_runs += more_bad
            runs = ALONE_RUNS
        # A test whose `known_flaky` entry excuses it and that failed in some alone runs but
        # not all is that flake (the lib proxy test fails alone 1 run in 3 under load); one
        # that fails every alone run is a failure like any other.
        excused: set[str] = set()
        if 0 < bad_runs < runs:
            excused = {n for n in still if f"{pkg}/{target}::{n}" in base_flaky}
            for name in sorted(excused):
                flaky[f"{pkg}/{target}::{name}"] = ""
                print(f"   {pkg}/{target}::{name}: fails alone in {bad_runs}/{runs} runs -- "
                      "known flaky")
            still -= excused
        for name in still:
            confirmed[f"{pkg}/{target}::{name}"] = ""
        if still:
            print(f"   {pkg}/{target}" + (f"::{test}" if test else "") + f": fails alone in {bad_runs}/{runs} runs")
        # A target whose parallel results could not be read: flaky only if it then passed
        # alone every time.
        only_parallel = (seen or (set() if still or excused else {"<target>"})) - still - excused
        for name in sorted(only_parallel):
            flaky[f"{pkg}/{target}::{name}"] = ""
            print(f"   {pkg}/{target}::{name}: failed in the parallel run, passes alone "
                  f"{runs}/{runs} -- flaky")

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
