#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

"""The gate's stage results, kept per source tree (T267).

tools/checkin.sh runs its stages (`--list`) and records each one's result here: pass, fail
or skip, its duration, the failures it noted and the end of its log. `--rerun-failed` then
reruns only the stages that have not passed on the same tree, and the verdict combines
every stage's last attempt on that tree.

The tree is the key, and nothing from another key is ever reused:
  - the commit, and a clean worktree (`git status --porcelain` empty apart from the files
    the gate itself writes, GATE_WRITES). A dirty tree gets no key: nothing is reusable.
  - the env that changes a verdict: COVERCHECK, ALCYON_GATE_SKIP_MEASURE, and the base
    covercheck judges against (ALCYON_COVERCHECK_BASE, or the default that follows the
    branch: the same commit judged against a base that moved is another verdict).

Every attempt is kept, so a stage that failed and then passed is shown as such in the
verdict ("PASS on attempt 2; attempt 1 FAIL ..."): a flake is reported, not laundered.

State: $ALCYON_GATE_STATE (default ~/.cache/alcyon/gate-state)/<key>.json, the log excerpts
under <key>/. Shared by every worktree: two worktrees on the same clean commit are the
same tree.
"""
from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import json
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)

# Files the gate rewrites itself; they do not make a tree dirty.
GATE_WRITES = {"data/measurements.jsonl"}

# Dependencies between stages that are not cargo's business (cargo rebuilds what a stage
# needs on its own: smoke's `cargo build --bin alcyon` builds alcyon when the target does not
# hold one from this tree). The one that is not: covercheck reads the profiles the suite's
# instrumented run left in the instrumented target (T257). Run alone, it reuses them only
# when PROFILES_MARK says the suite wrote them for this key and suite-run.json is still the
# one it wrote; otherwise the suite runs with it.
DEPS = {"covercheck": "suite"}
# T608: stages carried from the parent's full gate when the diff is only crates/*/tests/**.
# Each one runs no file under crates/*/tests/ (checked by reading it): smoke runs the built
# alcyon on reg-test configs, diff-fuzz the built alcyon against HAProxy, surface prints counts.
# Not carried, whatever the diff: tripwire (hashes protected tests), suite, covercheck, oracles,
# findings, haproxy (these run cargo test), lint (--all-targets compiles tests), harness-tests,
# measure, stray.
CARRY = ["smoke", "diff-fuzz", "surface"]
TESTS_ONLY = re.compile(r"^crates/[^/]+/tests/.+")
PROFILES_MARK = "gate-tree.json"
SUITE_RUN = "suite-run.json"

EXCERPT_LINES = 300
LIST_RE = re.compile(r"NEW FAILURES|NO test executes")
DETAIL_RE = re.compile(r"FAIL|NO test|panicked|hung|flaky|error|fails alone|regression")


def state_dir() -> str:
    return os.environ.get("ALCYON_GATE_STATE") or os.path.expanduser("~/.cache/alcyon/gate-state")


def _git(repo: str, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=repo, capture_output=True, text=True)


def tree_key(repo: str = REPO, env: dict | None = None,
             rev: str = "HEAD") -> tuple[str | None, str]:
    """(key, description), or (None, why) for a tree whose results must not be kept."""
    env = os.environ if env is None else env
    st = _git(repo, "status", "--porcelain")
    if st.returncode != 0:
        return None, "git status failed: " + st.stderr.strip()
    paths = [p for line in st.stdout.splitlines() for p in line[3:].split(" -> ")]
    dirty = [p for p in paths if p.strip('"') not in GATE_WRITES]
    if dirty:
        shown = ", ".join(dirty[:5]) + (" ..." if len(dirty) > 5 else "")
        return None, f"dirty tree ({shown})"
    head = _git(repo, "rev-parse", rev).stdout.strip()
    sys.path.insert(0, HERE)
    import covercheck  # noqa: E402
    try:
        base = covercheck.default_base(repo, dict(env), rev)
    except SystemExit as e:
        return None, str(e)
    ident = {
        "commit": head,
        "COVERCHECK": env.get("COVERCHECK") or "1",
        "ALCYON_GATE_SKIP_MEASURE": env.get("ALCYON_GATE_SKIP_MEASURE") or "",
        "covercheck_base": base,
    }
    key = hashlib.sha256(json.dumps(ident, sort_keys=True).encode()).hexdigest()[:16]
    desc = (f"commit {head[:12]}, covercheck base {base[:12]}, COVERCHECK={ident['COVERCHECK']}"
            f", ALCYON_GATE_SKIP_MEASURE={ident['ALCYON_GATE_SKIP_MEASURE'] or 'unset'}")
    return key, desc


@contextlib.contextmanager
def _locked(sdir: str, key: str):
    os.makedirs(sdir, exist_ok=True)
    with open(os.path.join(sdir, f"{key}.lock"), "w") as lk:
        fcntl.flock(lk, fcntl.LOCK_EX)
        yield


def load(sdir: str, key: str) -> dict:
    try:
        with open(os.path.join(sdir, f"{key}.json")) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {"key": key, "stages": {}}


def _detail(log: str) -> str:
    try:
        lines = open(log, errors="replace").read().splitlines()
    except OSError:
        return ""
    # The list under suite's "NEW FAILURES" or covercheck's "NO test executes" is what failed
    # the stage; the lines above it name baselined failures too.
    for i, x in enumerate(lines):
        m = LIST_RE.search(x)
        if m:
            items = []
            for y in lines[i + 1:]:
                if not y.startswith(" "):
                    break
                items.append(y.strip())
            if items:
                return f"{m.group(0)}: " + "; ".join(items[:6])[:400]
    picked = [x.strip() for x in lines
              if DETAIL_RE.search(x) and not x.startswith(("!! FAILED", "==="))]
    return "; ".join(picked[:4])[:400]


def record(sdir: str, key: str, stage: str, status: str, secs: int, log: str,
           fails: list[str], carried_from: str = "") -> dict:
    """Appends one attempt of `stage` on tree `key`; keeps the end of its log."""
    with _locked(sdir, key):
        st = load(sdir, key)
        attempts = st["stages"].setdefault(stage, [])
        n = len(attempts) + 1
        ldir = os.path.join(sdir, key)
        os.makedirs(ldir, exist_ok=True)
        kept = os.path.join(ldir, f"{stage}.{n}.log")
        try:
            lines = open(log, errors="replace").readlines()
        except OSError:
            lines = []
        with open(kept, "w") as f:
            f.writelines(lines[-EXCERPT_LINES:])
        a = {"n": n, "status": status, "secs": int(secs), "at": time.strftime("%F %T"),
             "fails": fails, "detail": _detail(log) if status == "fail" else "", "log": kept}
        if carried_from:
            a["carried_from"] = carried_from
        attempts.append(a)
        tmp = os.path.join(sdir, f"{key}.json.tmp")
        with open(tmp, "w") as f:
            json.dump(st, f, indent=1)
        os.replace(tmp, os.path.join(sdir, f"{key}.json"))
        return a


def _last(st: dict, stage: str) -> dict | None:
    a = st["stages"].get(stage) or []
    return a[-1] if a else None


def plan_rerun(st: dict, stages: list[str]) -> list[str]:
    """The stages that failed, or did not run, in the gates on this tree."""
    return [s for s in stages if (_last(st, s) or {}).get("status") not in ("pass", "skip")]


def _suite_run_sha(tdir: str) -> str | None:
    try:
        with open(os.path.join(tdir, SUITE_RUN), "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except OSError:
        return None


def mark_profiles(key: str, tdir: str) -> None:
    """After the suite ran: the profiles and suite-run.json in `tdir` are tree `key`'s."""
    sha = _suite_run_sha(tdir)
    if sha is None:
        return
    with open(os.path.join(tdir, PROFILES_MARK), "w") as f:
        json.dump({"key": key, "suite_run_sha256": sha}, f)


def profiles_ok(key: str | None, tdir: str) -> bool:
    if key is None:
        return False
    try:
        mark = json.load(open(os.path.join(tdir, PROFILES_MARK)))
    except (OSError, ValueError):
        return False
    sha = _suite_run_sha(tdir)
    return mark.get("key") == key and sha is not None and mark.get("suite_run_sha256") == sha


def with_deps(selected: list[str], stages: list[str], key: str | None,
              tdir: str) -> tuple[list[str], list[str]]:
    """`selected` plus what it needs (DEPS), in the gate's order, and why each was added."""
    sel = set(selected)
    notes = []
    for stage, dep in DEPS.items():
        if stage in sel and dep not in sel and not profiles_ok(key, tdir):
            sel.add(dep)
            notes.append(f"{stage} needs the {dep}'s profiles from this tree and {tdir} "
                         f"does not hold them: running the {dep} too")
    return [s for s in stages if s in sel], notes


def carry(repo: str, sdir: str, key: str, stages: list[str],
          env: dict | None = None) -> tuple[list[str], str]:
    """T608: records and returns the CARRY stages that need no run on tree `key`, and why not
    when there are none ("" when the diff simply is not tests-only). Only HEAD^ is looked at, never further back."""
    pkey, why = tree_key(repo, env, "HEAD^")
    if pkey is None:
        return [], f"no parent tree key: {why}"
    diff = _git(repo, "diff", "--name-only", "--no-renames", "HEAD^", "HEAD")
    if diff.returncode != 0:
        return [], "git diff HEAD^ HEAD failed"
    outside = [p for p in diff.stdout.splitlines() if not TESTS_ONLY.match(p)]
    if outside:
        return [], ""  # the ordinary case: say nothing
    pst = load(sdir, pkey)
    missing = plan_rerun(pst, stages)
    if missing:
        return [], f"the parent {pkey} was not gated in full (not passed: {', '.join(missing)})"
    carried = []
    with _locked(sdir, key):
        st = load(sdir, key)
        for s in (c for c in CARRY if c in stages):
            mine = _last(st, s)
            if mine is not None and not mine.get("carried_from"):
                continue  # this tree has a result of its own
            carried.append(s)
    for s in carried:
        if _last(load(sdir, key), s) is None:
            src = _last(pst, s)
            record(sdir, key, s, src["status"], 0, "", [], carried_from=pkey)
    return carried, ""


def _fmt(a: dict) -> str:
    s = (f"{a['status'].upper()} (carried from {a['carried_from']})" if a.get("carried_from")
         else f"{a['status'].upper()} ({a['secs']}s)")
    if a["status"] == "fail":
        what = a.get("detail") or ", ".join(a.get("fails") or [])
        s += (f": {what}" if what else "") + f"  [{a['log']}]"
    return s


def verdict(st: dict, stages: list[str], ran: list[str]) -> tuple[bool, list[str]]:
    """Every stage's last attempt on this tree, with the failed attempts before it."""
    lines = []
    failing: list[str] = []
    rerun, flaky = [], []
    for s in stages:
        attempts = st["stages"].get(s) or []
        mark = "  (this run)" if s in ran else ""
        if not attempts:
            lines.append(f"  {s:<14} not run on this tree")
            failing.append(f"  - {s}: not run on this tree")
            continue
        last = attempts[-1]
        if len(attempts) > 1:
            rerun.append(s)
        earlier = [a for a in attempts[:-1] if a["status"] == "fail"]
        if last["status"] in ("pass", "skip"):
            head = (f"{last['status'].upper()} on attempt {last['n']} ({last['secs']}s)"
                    if earlier else _fmt(last))
            if earlier:
                flaky.append(s)
        else:
            head = (f"FAIL on attempt {last['n']}: " if len(attempts) > 1 else "") + _fmt(last)
            failing += [f"  - {f}" for f in last.get("fails") or [s]]
        hist = "".join(f"; attempt {a['n']} {_fmt(a)}" for a in earlier)
        lines.append(f"  {s:<14} {head}{hist}{mark}")
    parts = []
    if rerun:
        parts.append(f"{len(rerun)} stage{'s' if len(rerun) != 1 else ''} rerun on this tree: "
                     + ", ".join(rerun))
    if flaky:
        parts.append(f"{len(flaky)} passed only on a rerun: " + ", ".join(flaky))
    if not failing:
        lines.append("checkin: PASS" + (f" ({'; '.join(parts)})" if parts else ""))
        return True, lines
    lines.append(f"checkin: FAIL ({len(failing)})")
    lines += failing
    if parts:
        lines.append("checkin: " + "; ".join(parts))
    return False, lines


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("key", help="print the tree key (exit 1 and why, when there is none)")
    for name in ("plan", "deps", "verdict", "record", "mark-profiles", "carry"):
        p = sub.add_parser(name)
        p.add_argument("--key", required=True)
        p.add_argument("--stages", default="")
        p.add_argument("--select", default="")
        p.add_argument("--ran", default="")
        p.add_argument("--tdir", default="")
        p.add_argument("--stage")
        p.add_argument("--status", choices=("pass", "fail", "skip"))
        p.add_argument("--secs", type=int, default=0)
        p.add_argument("--log", default="")
        p.add_argument("--fail", action="append", default=[])
    a = ap.parse_args()
    if a.cmd == "key":
        key, desc = tree_key()
        print(key or desc)
        return 0 if key else 1
    split = lambda s: [x for x in s.split(",") if x]  # noqa: E731
    sdir = state_dir()
    if a.cmd == "plan":
        print(" ".join(plan_rerun(load(sdir, a.key), split(a.stages))))
    elif a.cmd == "deps":
        key = None if a.key == "-" else a.key
        sel, notes = with_deps(split(a.select), split(a.stages), key, a.tdir)
        for n in notes:
            print(f"checkin: {n}", file=sys.stderr)
        print(" ".join(sel))
    elif a.cmd == "carry":
        done, why = carry(REPO, sdir, a.key, split(a.stages))
        if why:
            print(f"checkin: nothing taken from the parent's gate: {why}", file=sys.stderr)
        print(" ".join(done))
    elif a.cmd == "record":
        record(sdir, a.key, a.stage, a.status, a.secs, a.log, a.fail)
    elif a.cmd == "mark-profiles":
        mark_profiles(a.key, a.tdir)
    elif a.cmd == "verdict":
        ok, lines = verdict(load(sdir, a.key), split(a.stages), split(a.ran))
        print("\n".join(lines))
        return 0 if ok else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
