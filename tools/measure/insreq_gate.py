#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
"""The gate's quick instructions-per-request check (checkin.sh stage `insreq-quick`).

Only the exclusive measuring gate on main measured ins/req, so 32 merges went in unmeasured
and the next measured gate found keepalive +1.8% and rules +2.5% (11-21; AGENTS.md section 8
allows +0.5%). This runs in every other gate: a release-perf alcyon of the tree under test
against the reference's, insreq.sh ab1 on keepalive and rules, on counts slot B
(/tmp/alcyon-load-n1.lock, CPUs 12-14). Counts only, never a timing claim.

    tools/measure/insreq_gate.py [--ref SHA] [--cand-sha SHA | --cand-bin PATH]
                                 [-n N] [--rounds R] [--budget PCT]

The reference: --ref, else ALCYON_MEASURE_REF, else the last row of data/measurements.jsonl
that measured ins/req on a clean ancestor of HEAD and passed its own ins/req check (a row over
measure.INS_MAX_RISE_PCT against its own ref, as 2eea785f's, is not a baseline: taking it
would make the regression it found the new normal).

The reference binary is cached in $ALCYON_INSREQ_REF_DIR (default $ALCYON_TARGETS/insreq-ref)
by commit *and* compiler (`rustc -vV`): measure.py's cache keys by commit only, so a binary an
older rustc built would be reused after a toolchain bump (1.100 moved c246669a's keepalive from
35,062 to 35,135). A miss is one fat-LTO build from `git archive`, under a lock per key.

The candidate is `cargo build --profile release-perf --bin alcyon` of this tree into
$CARGO_TARGET_DIR (measure.py ensure_alcyon_binary), or --cand-bin, or --cand-sha (built and
cached like the reference).

Judged: the minimum over rounds of instructions:u per request, as the measuring gate judges.
FAIL (exit 1) when either scenario is over +budget% (default 0.5). Exit 2: could not measure.
If the game (wwm.exe) runs, one line says so; the verdict is the same (user, 11-21).
"""

import argparse
import fcntl
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Callable, Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import measure  # noqa: E402

REPO = measure.REPO_ROOT
SCENARIOS = ("keepalive", "rules")
CLIENT = "ab1"
# Chosen from the spread measured 11-21 (tools/measure/README.md, "insreq-quick").
DEFAULT_N = 10000
DEFAULT_ROUNDS = 3
DEFAULT_BUDGET_PCT = 0.5
SLOT_B_LOCK = "/tmp/alcyon-load-n1.lock"
SLOT_B_CPUS = "12,13,14"


def pick_ref(records: List[Dict], is_ancestor: Callable[[str], bool],
             max_rise_pct: float = measure.INS_MAX_RISE_PCT) -> Optional[str]:
    """The sha of the last clean, passing ins/req measurement that `is_ancestor`, or None."""
    for r in reversed(records):
        sha = r.get("sha")
        if not sha or r.get("dirty") or "kind" in r:
            continue
        ok = True
        for sc in SCENARIOS:
            cur, ref = r.get(f"ins_per_req_{sc}"), r.get(f"ins_per_req_{sc}_ref")
            if not cur or not ref or cur > ref * (1 + max_rise_pct / 100):
                ok = False
        if ok and is_ancestor(sha):
            return sha
    return None


def judge(cand: Dict[str, int], ref: Dict[str, int]) -> Dict[str, float]:
    """Per scenario, the rise of cand over ref in percent."""
    return {sc: (cand[sc] - ref[sc]) * 100.0 / ref[sc] for sc in ref}


def _git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=REPO, check=True, capture_output=True,
                          text=True).stdout.strip()


def _is_ancestor(sha: str) -> bool:
    return subprocess.run(["git", "merge-base", "--is-ancestor", sha, "HEAD"], cwd=REPO,
                          capture_output=True).returncode == 0


def reference(arg: Optional[str]) -> str:
    want = arg or os.environ.get("ALCYON_MEASURE_REF")
    if want:
        return _git("rev-parse", "--verify", f"{want}^{{commit}}")
    sha = pick_ref(measure.load_previous_measurements(measure.DATA_DIR / "measurements.jsonl"),
                   _is_ancestor)
    if not sha:
        raise SystemExit("insreq-quick: no passing ins/req measurement of an ancestor in "
                         "data/measurements.jsonl; set ALCYON_MEASURE_REF")
    return sha


def rustc_key() -> str:
    out = subprocess.run(["rustc", "-vV"], cwd=REPO, check=True, capture_output=True,
                         text=True).stdout
    return hashlib.sha256(out.encode()).hexdigest()[:10]


def cache_dir() -> Path:
    if os.environ.get("ALCYON_INSREQ_REF_DIR"):
        return Path(os.environ["ALCYON_INSREQ_REF_DIR"])
    base = os.environ.get("ALCYON_TARGETS") or os.path.join(
        os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache"), "alcyon", "targets")
    return Path(base) / "insreq-ref"


def build_env(target: Path) -> Dict[str, str]:
    # The plain env: an instrumented (llvm-cov) RUSTFLAGS would measure the profiler.
    env = {k: v for k, v in os.environ.items()
           if k not in ("RUSTFLAGS", "LLVM_PROFILE_FILE", "ALCYON_INSTRUMENTED",
                        "CARGO_ENCODED_RUSTFLAGS") and not k.startswith("CARGO_LLVM_COV")}
    env["CARGO_TARGET_DIR"] = str(target)
    env.setdefault("CARGO_INCREMENTAL", "0")
    return env


def cached_binary(sha: str) -> Path:
    """A release-perf alcyon of `sha`, built by this rustc, cached by both."""
    cache = cache_dir()
    cache.mkdir(parents=True, exist_ok=True)
    key = f"{sha[:12]}-rustc{rustc_key()}"
    bin_path = cache / f"alcyon-perf-{key}"
    with open(cache / f"{key}.lock", "w") as lk:
        fcntl.flock(lk, fcntl.LOCK_EX)
        if bin_path.exists():
            print(f"insreq-quick: {sha[:12]}: cached {bin_path}")
            return bin_path
        src = cache / f"src-{key}"
        shutil.rmtree(src, ignore_errors=True)
        src.mkdir()
        arch = subprocess.Popen(["git", "archive", sha], cwd=REPO, stdout=subprocess.PIPE)
        subprocess.run(["tar", "-x", "-C", str(src)], stdin=arch.stdout, check=True)
        if arch.wait() != 0:
            raise RuntimeError(f"git archive {sha} failed")
        print(f"insreq-quick: building {sha[:12]} (release-perf, fat LTO)", flush=True)
        t0 = time.time()
        # A reference from before the rename (2026-11-08) has no `alcyon` binary.
        res = subprocess.run(["cargo", "build", "--profile", "release-perf", "--bin", "alcyon",
                              "--offline"], cwd=src, env=build_env(cache / "target"),
                             capture_output=True, text=True)
        shutil.rmtree(src, ignore_errors=True)
        if res.returncode != 0:
            raise RuntimeError(f"build of {sha[:12]} failed: {res.stderr[-2000:]}")
        tmp = bin_path.with_suffix(".tmp")
        shutil.copy2(cache / "target" / "release-perf" / "alcyon", tmp)
        tmp.rename(bin_path)
        print(f"insreq-quick: built {sha[:12]} in {time.time() - t0:.0f}s")
    for old in sorted(cache.glob("alcyon-perf-*"), key=lambda q: q.stat().st_mtime)[:-6]:
        old.unlink()
    return bin_path


def tree_binary() -> Path:
    t0 = time.time()
    target = measure.get_target_dir()
    res = subprocess.run(["cargo", "build", "--profile", "release-perf", "--bin", "alcyon"],
                         cwd=REPO, env=build_env(target), capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"release-perf build of the tree failed: {res.stderr[-2000:]}")
    print(f"insreq-quick: tree built (release-perf) in {time.time() - t0:.0f}s: "
          f"{target / 'release-perf' / 'alcyon'}")
    return target / "release-perf" / "alcyon"


def measure_side(label: str, binary: Path, n: int, rounds: int, out: str) -> Dict[str, int]:
    res = {}
    insreq = REPO / "tools" / "measure" / "insreq.sh"
    env = dict(os.environ, ALCYON_MEASURE_CPUS=SLOT_B_CPUS)
    for sc in SCENARIOS:
        body = REPO / "tools" / "measure" / "scenarios" / f"{sc}.body"
        p = subprocess.run(["bash", str(insreq), f"{sc}-{label}", str(binary), str(body), CLIENT,
                            str(n), str(rounds), out], capture_output=True, text=True, env=env)
        o = p.stdout + p.stderr
        counts = [c // n for c in measure.parse_insreq(o)]
        if len(counts) != rounds:
            raise RuntimeError(f"insreq.sh {sc} {label}: {len(counts)} of {rounds} rounds: {o[-1500:]}")
        spread = (max(counts) - min(counts)) * 100.0 / min(counts)
        print(f"insreq-quick:   {sc:<9} {label:<4} rounds {counts} min {min(counts)}"
              f" spread {spread:.2f}%", flush=True)
        res[sc] = min(counts)
    return res


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--ref")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--cand-sha")
    g.add_argument("--cand-bin")
    ap.add_argument("-n", type=int, default=int(os.environ.get("ALCYON_INSREQ_N", DEFAULT_N)))
    ap.add_argument("--rounds", type=int,
                    default=int(os.environ.get("ALCYON_INSREQ_ROUNDS", DEFAULT_ROUNDS)))
    ap.add_argument("--budget", type=float, default=DEFAULT_BUDGET_PCT)
    ap.add_argument("--lock-wait", type=int, default=1800,
                    help="seconds to wait for slot B before giving up (exit 2)")
    a = ap.parse_args()

    t0 = time.time()
    try:
        ref_sha = reference(a.ref)
        if subprocess.run(["pgrep", "-x", "wwm.exe"], capture_output=True).returncode == 0:
            print("insreq-quick: note: wwm.exe (the game) is running; measured anyway, "
                  "counts are not timing")
        print(f"insreq-quick: ref {ref_sha[:12]}, ab1 N={a.n} x {a.rounds} rounds, budget "
              f"+{a.budget}%, slot B CPUs {SLOT_B_CPUS}", flush=True)
        if a.cand_bin:
            cand_bin, cand_label = Path(a.cand_bin), a.cand_bin
        elif a.cand_sha:
            cand_bin, cand_label = cached_binary(_git("rev-parse", a.cand_sha)), a.cand_sha
        else:
            cand_bin, cand_label = tree_binary(), "this tree"
        ref_bin = cached_binary(ref_sha)
        t_build = time.time() - t0
        lk = os.open(SLOT_B_LOCK, os.O_RDWR | os.O_CREAT, 0o666)
        t_lock = time.time()
        while True:
            try:
                fcntl.flock(lk, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.time() - t_lock > a.lock_wait:
                    print(f"insreq-quick: slot B ({SLOT_B_LOCK}) held for {a.lock_wait}s; not measured")
                    return 2
                time.sleep(5)
        t_wait = time.time() - t_lock
        try:
            with tempfile.TemporaryDirectory(prefix="insreq-quick-") as out:
                cand = measure_side("cand", cand_bin, a.n, a.rounds, out)
                ref = measure_side("ref", ref_bin, a.n, a.rounds, out)
        finally:
            os.close(lk)
    except (RuntimeError, subprocess.CalledProcessError) as e:
        print(f"insreq-quick: could not measure: {e}")
        return 2
    rise = judge(cand, ref)
    bad = [sc for sc in SCENARIOS if rise[sc] > a.budget]
    for sc in SCENARIOS:
        print(f"insreq-quick: {sc:<9} {cand_label}: {cand[sc]} ins/req, ref {ref_sha[:12]}: "
              f"{ref[sc]}, {rise[sc]:+.2f}% ({'OVER' if sc in bad else 'within'} +{a.budget}%)")
    print(f"insreq-quick: time: builds {t_build:.0f}s, slot B wait {t_wait:.0f}s, "
          f"measuring {time.time() - t_lock - t_wait:.0f}s")
    print(f"insreq-quick: {'FAIL' if bad else 'PASS'}"
          + (f": {', '.join(bad)} over +{a.budget}% against {ref_sha[:12]}" if bad else ""))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
