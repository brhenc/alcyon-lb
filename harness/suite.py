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

The targets run in parallel (T116): `cargo test` runs its test binaries one after another,
and with 129 of them the gate spent 100 s on a 64-core machine mostly idle. The suite builds
with `cargo test --no-run` and runs each test binary itself, `SUITE_JOBS` at once, longest
first, as cargo would: from the package's directory, with cargo's `CARGO_*` variables. (Not
`cargo test -p` per target: cargo holds the build directory's lock while the tests run,
and parallel invocations queue behind it.) Doc tests run through `cargo test --doc`, and a
failing target is re-run alone through `cargo test`, as before. `SUITE_SERIAL=1` runs the
single `cargo test --workspace` of before.

Usage:  python3 harness/suite.py            # gate
        python3 harness/suite.py --accept   # rewrite the baseline from this run
"""
from __future__ import annotations

import json
import os
import re
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


RESULT_RE = re.compile(r"^test result: \w+\. (\d+) passed; (\d+) failed", re.M)
JOBS = int(os.environ.get("SUITE_JOBS", "8"))
# A test binary that runs longer than this is killed and reported as failing, so a deadlock
# shows up as a named failure instead of a gate that never ends. The slowest binary takes
# about 13 s; `SUITE_TIMEOUT` raises it.
TARGET_TIMEOUT = int(os.environ.get("SUITE_TIMEOUT", "300"))
HEARTBEAT = 15


def say(msg: str) -> None:
    print(msg, flush=True)


def run_bounded(cmd: list[str], cwd: str, env: dict | None) -> tuple[int, str]:
    """Runs `cmd` with its output, killed after `TARGET_TIMEOUT` seconds: its whole process
    group, since under `cargo test` the hung process is cargo's child and killing cargo
    alone leaves it running. A timeout returns -9."""
    p = subprocess.Popen(cmd, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         text=True, start_new_session=True)
    try:
        out, _ = p.communicate(timeout=TARGET_TIMEOUT)
        return p.returncode, out
    except subprocess.TimeoutExpired:
        os.killpg(p.pid, 9)
        out, _ = p.communicate()
        return -9, out or ""
# Targets that measure the process or race the clock: run one at a time after the parallel
# pool, on a machine as quiet as the serial suite left it. Each was seen failing only under
# the pool's load and passing alone (2026-10-03); a name here is not an excuse -- a failure
# in the serial pass is a failure like any other.
SERIAL_TARGETS = {
    "ibex-rt/request_allocations",     # counts allocations and bytes per request
    "ibex-rt/canonical_haproxy_35_e2e",  # stick counters read across scopes on a timer
    "ibex-rt/cli_applet",              # `show pools` waits a fixed 20 engine steps (T116)
}


def target_dir() -> str:
    return os.environ.get("CARGO_TARGET_DIR") or os.path.join(REPO, "target")


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
    for line in p.stdout.splitlines():
        m = json.loads(line) if line.startswith("{") else {}
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


def run_parallel(doc: bool = True) -> tuple[list[tuple[str, str, list[str]]], dict[str, set[str]], int, int] | None:
    """Runs every target, `JOBS` at once. Returns the failing targets, the failing tests of
    each (keyed by target), and the totals of tests passed and failed. `doc=False` leaves the
    doc tests out (covercheck: `cargo llvm-cov` does not instrument them)."""
    targets = test_targets()
    if targets is None:
        print("suite: the workspace's tests do not build")
        return None
    # (package, target, selector, command, cwd, env)
    jobs = [(pkg, key, sel, [exe], os.path.dirname(p["manifest_path"]), cargo_env(p))
            for pkg, key, sel, exe, p in targets]
    if doc:
        jobs.append(("workspace", "doc", ["--doc"], ["cargo", "test", "--workspace", "--doc", "--no-fail-fast"],
                     REPO, None))
    # Longest first, from the last run's durations: the slowest target sets the floor.
    times_path = os.path.join(target_dir(), "suite-durations.json")
    try:
        last = json.load(open(times_path))
    except (OSError, ValueError):
        last = {}
    jobs.sort(key=lambda j: -last.get(f"{j[0]}/{j[1]}", 1000.0))

    running: dict[str, float] = {}
    done = [0]
    lock = threading.Lock()

    def one(job):
        name = f"{job[0]}/{job[1]}"
        t0 = time.monotonic()
        with lock:
            running[name] = t0
        rc, out = run_bounded(job[3], job[4], job[5])
        if rc == -9:
            # A hang names no failing test: the target fails.
            say(f"   {name}: killed after {TARGET_TIMEOUT}s (SUITE_TIMEOUT) -- hung")
        with lock:
            del running[name]
            done[0] += 1
        return job, rc, out, time.monotonic() - t0

    # Progress: how many targets are done and which are running for how long, so a stuck
    # test is visible while it is stuck rather than when the gate is given up on.
    stop = threading.Event()

    def heartbeat():
        while not stop.wait(HEARTBEAT):
            with lock:
                now = time.monotonic()
                slow = sorted(running.items(), key=lambda kv: kv[1])[:4]
                busy = ", ".join(f"{n} {now - t:.0f}s" for n, t in slow)
                say(f"   ... {done[0]}/{len(jobs)} targets done; running: {busy or '-'}")

    threading.Thread(target=heartbeat, daemon=True).start()
    pooled = [j for j in jobs if f"{j[0]}/{j[1]}" not in SERIAL_TARGETS]
    serial = [j for j in jobs if f"{j[0]}/{j[1]}" in SERIAL_TARGETS]
    try:
        with ThreadPoolExecutor(max_workers=JOBS) as pool:
            results = list(pool.map(one, pooled))
        results += [one(j) for j in serial]
    finally:
        stop.set()
    failing, failed_tests, passed, failed_n, durations = [], {}, 0, 0, {}
    for (pkg, key, sel, _cmd, _cwd, _env), rc, out, secs in results:
        durations[f"{pkg}/{key}"] = round(secs, 2)
        for p_, f_ in RESULT_RE.findall(out):
            passed += int(p_)
            failed_n += int(f_)
        if rc != 0:
            # Re-run alone through `cargo test`, as the serial suite does.
            failing.append((pkg, key, sel))
            failed_tests[key] = set(FAIL_RE.findall(out)) or ({"<hung>"} if rc == -9 else {"<target>"})
    try:
        json.dump(durations, open(times_path, "w"))
    except OSError:
        pass
    return failing, failed_tests, passed, failed_n


def confirm_cmd(cmd: list[str], runs: int) -> tuple[set[str], int]:
    """Re-runs one target alone `runs` times.

    Returns the tests that failed in any of those runs, and how many runs failed. A run that
    fails without naming a test (a crash, a timeout) counts as the whole target failing."""
    failed: set[str] = set()
    bad_runs = 0
    for _ in range(runs):
        rc, out = run_bounded(cmd, REPO, None)
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

    if os.environ.get("SUITE_SERIAL") == "1":
        print("suite: running every test target in the workspace (serial)")
        out = run(["cargo", "test", "--workspace", "--no-fail-fast"])
        targets = failing_targets(out)
        if not targets and "error:" in out and "targets failed" in out:
            print("suite: could not parse cargo's failing-target list; treating as failure")
            return 1
        in_parallel = failed_by_target(out)
        commands = {(pkg, t): ["cargo", "test", "-p", pkg, "--test", t, "--no-fail-fast"] for pkg, t in targets}
    else:
        say(f"suite: running every test target in the workspace, {JOBS} at a time, "
            f"{TARGET_TIMEOUT}s each at most")
        r = run_parallel()
        if r is None:
            return 1
        failing, in_parallel, passed, failed_n = r
        print(f"suite: {passed} tests passed, {failed_n} failed, in the parallel run")
        targets = [(pkg, key) for pkg, key, _ in failing]
        commands = {(pkg, key): (["cargo", "test", "--workspace", "--doc", "--no-fail-fast"] if key == "doc"
                                 else ["cargo", "test", "-p", pkg, *args, "--no-fail-fast"])
                    for pkg, key, args in failing}

    confirmed: dict[str, str] = {}
    flaky: dict[str, str] = {}
    for pkg, target in targets:
        # A target whose parallel failures are all declared known failures is confirmed by
        # one alone run that reproduces them; anything else gets the full `ALONE_RUNS`.
        seen = in_parallel.get(target, set())
        all_known = bool(seen) and all(f"{pkg}/{target}::{n}" in base for n in seen)
        still, bad_runs = confirm_cmd(commands[(pkg, target)], 1 if all_known else ALONE_RUNS)
        runs = 1 if all_known else ALONE_RUNS
        if all_known and still != seen:
            more, more_bad = confirm_cmd(commands[(pkg, target)], ALONE_RUNS - 1)
            still |= more
            bad_runs += more_bad
            runs = ALONE_RUNS
        for name in still:
            confirmed[f"{pkg}/{target}::{name}"] = ""
        if still:
            print(f"   {pkg}/{target}: fails alone in {bad_runs}/{runs} runs")
        # A target whose parallel results could not be read: flaky only if it then passed
        # alone every time.
        only_parallel = in_parallel.get(target, set() if still else {"<target>"}) - still
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
