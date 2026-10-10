#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

"""Tests for the gate's per-tree stage results (T267): tools/checkin.sh --only / --rerun-failed.

Run:  python3 -m unittest harness/test_gatestate.py

A gate that failed one stage used to be rerun whole (~6-15 min) to retry that stage. A
stage's result is now kept per source tree, and `--rerun-failed` reruns only the stages
that have not passed on that same tree. What must hold: a result from another commit, a
dirty tree or another verdict-changing env is never reused; covercheck never judges
profiles another tree wrote; a stage that failed and then passed is shown, not hidden.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import gatestate  # noqa: E402

STAGES = ["tripwire", "suite", "covercheck", "smoke", "lint"]


def git(repo: str, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True,
                          text=True).stdout.strip()


class Repo:
    """A throwaway repository on `main` with one source file and data/measurements.jsonl."""

    def __init__(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.path = self.tmp.name
        git(self.path, "init", "-q", "-b", "main")
        git(self.path, "config", "user.email", "t@example.invalid")
        git(self.path, "config", "user.name", "t")
        git(self.path, "config", "commit.gpgsign", "false")
        self.write("crates/x/src/lib.rs", "fn a() {}\n")
        self.write("data/measurements.jsonl", "{}\n")
        self.commit("root")

    def write(self, rel: str, text: str) -> None:
        p = os.path.join(self.path, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(text)

    def commit(self, msg: str) -> str:
        git(self.path, "add", ".")
        git(self.path, "commit", "-q", "-m", msg)
        return git(self.path, "rev-parse", "HEAD")

    def close(self) -> None:
        self.tmp.cleanup()


ENV = {"IBEX_COVERCHECK_BASE": "HEAD"}


class TestTreeKey(unittest.TestCase):
    def setUp(self) -> None:
        self.r = Repo()

    def tearDown(self) -> None:
        self.r.close()

    def key(self, **env: str):
        return gatestate.tree_key(self.r.path, {**ENV, **env})[0]

    def test_same_clean_tree_same_key(self):
        self.assertIsNotNone(self.key())
        self.assertEqual(self.key(), self.key())

    def test_a_new_commit_changes_the_key(self):
        k1 = self.key()
        self.r.write("crates/x/src/lib.rs", "fn a() {}\nfn b() {}\n")
        self.r.commit("second")
        self.assertNotEqual(self.key(), k1)

    def test_a_modified_file_makes_the_tree_dirty(self):
        self.r.write("crates/x/src/lib.rs", "fn a() { }\n")
        key, why = gatestate.tree_key(self.r.path, ENV)
        self.assertIsNone(key)
        self.assertIn("crates/x/src/lib.rs", why)

    def test_an_untracked_file_makes_the_tree_dirty(self):
        self.r.write("crates/x/tests/new.rs", "#[test] fn t() {}\n")
        self.assertIsNone(self.key())

    def test_the_files_the_gate_writes_do_not(self):
        k1 = self.key()
        self.r.write("data/measurements.jsonl", "{}\n{\"run\": 2}\n")
        self.assertEqual(self.key(), k1)

    def test_verdict_changing_env_changes_the_key(self):
        k1 = self.key()
        self.assertNotEqual(self.key(IBEX_GATE_SKIP_MEASURE="1"), k1)
        self.assertNotEqual(self.key(COVERCHECK="0"), k1)
        self.assertEqual(self.key(COVERCHECK="1"), k1)  # the default, spelled out
        before = git(self.r.path, "rev-parse", "HEAD")
        self.r.write("crates/x/src/lib.rs", "fn a() {}\nfn c() {}\n")
        self.r.commit("third")
        k3 = self.key()
        self.assertNotEqual(self.key(IBEX_COVERCHECK_BASE=before), k3)

    def test_covercheck_default_base_is_part_of_the_key(self):
        # Without an override, the base covercheck judges against follows the branch: the
        # same commit judged against another base is another verdict.
        env = {"IBEX_COVERCHECK_BASE": ""}
        root = git(self.r.path, "rev-parse", "HEAD")
        git(self.r.path, "checkout", "-q", "-b", "topic")
        self.r.write("crates/x/src/lib.rs", "fn a() {}\nfn t() {}\n")
        t1 = self.r.commit("topic 1")
        self.r.write("crates/x/src/lib.rs", "fn a() {}\nfn t() {}\nfn u() {}\n")
        self.r.commit("topic 2")
        k_topic = gatestate.tree_key(self.r.path, env)[0]
        git(self.r.path, "branch", "-f", "main", t1)  # topic 1 merged: the base moves
        self.assertNotEqual(gatestate.tree_key(self.r.path, env)[0], k_topic)
        git(self.r.path, "branch", "-f", "main", root)
        self.assertEqual(gatestate.tree_key(self.r.path, env)[0], k_topic)


class StateCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name
        self.log = os.path.join(self.dir, "stage.log")
        with open(self.log, "w") as f:
            f.write("line\n")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def rec(self, stage: str, status: str, fails=(), key: str = "k1", log: str | None = None):
        return gatestate.record(self.dir, key, stage, status, 3, log or self.log, list(fails))

    def state(self, key: str = "k1"):
        return gatestate.load(self.dir, key)


class TestRerunFailed(StateCase):
    def test_no_earlier_gate_runs_everything(self):
        self.assertEqual(gatestate.plan_rerun(self.state(), STAGES), STAGES)

    def test_reruns_exactly_the_failed_stages(self):
        for s in STAGES:
            self.rec(s, "fail" if s in ("suite", "lint") else "pass")
        self.assertEqual(gatestate.plan_rerun(self.state(), STAGES), ["suite", "lint"])

    def test_reruns_the_stages_that_did_not_run(self):
        self.rec("tripwire", "pass")
        self.rec("suite", "pass")
        self.assertEqual(gatestate.plan_rerun(self.state(), STAGES), ["covercheck", "smoke", "lint"])

    def test_a_skipped_stage_is_not_rerun(self):
        for s in STAGES:
            self.rec(s, "skip" if s == "smoke" else "pass")
        self.assertEqual(gatestate.plan_rerun(self.state(), STAGES), [])

    def test_the_last_attempt_counts(self):
        for s in STAGES:
            self.rec(s, "pass")
        self.rec("suite", "fail")
        self.assertEqual(gatestate.plan_rerun(self.state(), STAGES), ["suite"])
        self.rec("suite", "pass")
        self.assertEqual(gatestate.plan_rerun(self.state(), STAGES), [])

    def test_another_key_is_not_reused(self):
        for s in STAGES:
            self.rec(s, "pass", key="old-commit")
        self.assertEqual(gatestate.plan_rerun(self.state("new-commit"), STAGES), STAGES)

    def test_the_log_excerpt_is_kept(self):
        a = self.rec("suite", "fail", ["workspace suite"])
        self.assertTrue(os.path.isfile(a["log"]))
        self.assertTrue(a["log"].startswith(self.dir))


class TestVerdict(StateCase):
    def verdict(self, ran=()):
        return gatestate.verdict(self.state(), STAGES, list(ran))

    def test_pass_when_every_stage_passed(self):
        for s in STAGES:
            self.rec(s, "skip" if s == "smoke" else "pass")
        ok, lines = self.verdict(STAGES)
        self.assertTrue(ok)
        self.assertEqual(lines[-1], "checkin: PASS")

    def test_fail_lists_each_failure(self):
        for s in STAGES:
            self.rec(s, "fail" if s == "suite" else "pass", ["workspace suite"] if s == "suite" else ())
        ok, lines = self.verdict(STAGES)
        self.assertFalse(ok)
        self.assertIn("checkin: FAIL (1)", lines)
        self.assertIn("  - workspace suite", lines)

    def test_a_stage_never_run_on_this_tree_fails_the_verdict(self):
        for s in STAGES[:-1]:
            self.rec(s, "pass")
        ok, lines = self.verdict(["tripwire"])
        self.assertFalse(ok)
        self.assertIn("  - lint: not run on this tree", lines)

    def test_combined_over_runs(self):
        for s in STAGES:
            self.rec(s, "fail" if s == "suite" else "pass", ["workspace suite"] if s == "suite" else ())
        self.rec("suite", "pass")
        ok, lines = self.verdict(["suite"])
        self.assertTrue(ok)
        self.assertEqual(lines[-1], "checkin: PASS (1 stage rerun on this tree: suite; "
                                    "1 passed only on a rerun: suite)")


class TestAttemptHistory(StateCase):
    def test_a_flake_is_shown_not_hidden(self):
        with open(self.log, "w") as f:
            f.write("suite: NEW FAILURES\n"
                    "   ibex-rt/idle_pool_shared::burst (flaky: parallel run only)\n"
                    "!! FAILED: workspace suite\n")
        for s in STAGES:
            self.rec(s, "fail" if s == "suite" else "pass", ["workspace suite"] if s == "suite" else ())
        self.rec("suite", "pass")
        ok, lines = gatestate.verdict(self.state(), STAGES, ["suite"])
        line = next(x for x in lines if x.lstrip().startswith("suite"))
        self.assertIn("PASS on attempt 2", line)
        self.assertIn("attempt 1 FAIL", line)
        self.assertIn("ibex-rt/idle_pool_shared::burst (flaky: parallel run only)", line)

    def test_the_new_failures_are_the_detail_not_the_baselined_ones(self):
        # Gate 1 of the demonstration: the detail named three baselined failures and not
        # the one test that failed the stage.
        with open(self.log, "w") as f:
            f.write("   slz/t267_demo: fails alone in 3/3 runs\n"
                    "   ibex-dns/resolver_behavior: fails alone in 1/1 runs\n"
                    "suite: 3 confirmed failing, 0 flaky, 2 + 2 baselined\n"
                    "suite: NEW FAILURES\n"
                    "   slz/t267_demo::t267_demo\n"
                    "!! FAILED: workspace suite\n")
        a = self.rec("suite", "fail", ["workspace suite"])
        self.assertEqual(a["detail"], "NEW FAILURES: slz/t267_demo::t267_demo")

    def test_every_failed_attempt_is_listed(self):
        self.rec("lint", "fail", ["clippy"])
        self.rec("lint", "fail", ["clippy"])
        self.rec("lint", "pass")
        _ok, lines = gatestate.verdict(self.state(), ["lint"], ["lint"])
        line = next(x for x in lines if x.lstrip().startswith("lint"))
        self.assertIn("PASS on attempt 3", line)
        self.assertIn("attempt 1 FAIL", line)
        self.assertIn("attempt 2 FAIL", line)


class TestCovercheckNeedsSuite(StateCase):
    def setUp(self) -> None:
        super().setUp()
        self.tdir = os.path.join(self.dir, "llvm-cov-target")
        os.makedirs(self.tdir)

    def suite_run(self, text: str = '{"executables": ["a"]}') -> None:
        with open(os.path.join(self.tdir, "suite-run.json"), "w") as f:
            f.write(text)

    def test_covercheck_alone_pulls_in_the_suite_without_profiles(self):
        sel, notes = gatestate.with_deps(["covercheck"], STAGES, "k1", self.tdir)
        self.assertEqual(sel, ["suite", "covercheck"])
        self.assertTrue(notes)

    def test_covercheck_alone_reuses_this_trees_profiles(self):
        self.suite_run()
        gatestate.mark_profiles("k1", self.tdir)
        sel, _ = gatestate.with_deps(["covercheck"], STAGES, "k1", self.tdir)
        self.assertEqual(sel, ["covercheck"])

    def test_profiles_of_another_tree_are_not_reused(self):
        self.suite_run()
        gatestate.mark_profiles("k0", self.tdir)
        sel, _ = gatestate.with_deps(["covercheck"], STAGES, "k1", self.tdir)
        self.assertEqual(sel, ["suite", "covercheck"])

    def test_a_suite_run_since_by_another_gate_invalidates_them(self):
        self.suite_run()
        gatestate.mark_profiles("k1", self.tdir)
        self.suite_run('{"executables": ["b"]}')  # an older checkin.sh's suite, same target
        sel, _ = gatestate.with_deps(["covercheck"], STAGES, "k1", self.tdir)
        self.assertEqual(sel, ["suite", "covercheck"])

    def test_no_key_never_reuses(self):
        self.suite_run()
        gatestate.mark_profiles("k1", self.tdir)
        sel, _ = gatestate.with_deps(["covercheck"], STAGES, None, self.tdir)
        self.assertEqual(sel, ["suite", "covercheck"])

    def test_order_follows_the_gate(self):
        sel, _ = gatestate.with_deps(["lint", "covercheck"], STAGES, "k1", self.tdir)
        self.assertEqual(sel, ["suite", "covercheck", "lint"])

    def test_without_covercheck_nothing_is_added(self):
        sel, _ = gatestate.with_deps(["lint"], STAGES, "k1", self.tdir)
        self.assertEqual(sel, ["lint"])


class TestCheckinDriver(unittest.TestCase):
    """tools/checkin.sh itself, in a throwaway repository, with every stage replaced by a
    script in $IBEX_CHECKIN_FAKE (`<stage>`; missing means pass). Each run appends the stages
    it ran to $IBEX_CHECKIN_FAKE/ran."""

    def setUp(self) -> None:
        self.r = Repo()
        root = os.path.dirname(HERE)
        for rel in ("tools/checkin.sh", "harness/gatestate.py", "harness/covercheck.py"):
            os.makedirs(os.path.join(self.r.path, os.path.dirname(rel)), exist_ok=True)
            shutil.copy2(os.path.join(root, rel), os.path.join(self.r.path, rel))
        self.r.commit("gate")
        self.aux = tempfile.TemporaryDirectory()
        self.fake = os.path.join(self.aux.name, "fake")
        os.makedirs(self.fake)
        self.env = dict(os.environ, IBEX_CHECKIN_FAKE=self.fake,
                        IBEX_GATE_STATE=os.path.join(self.aux.name, "state"),
                        IBEX_GATE_HISTORY=os.path.join(self.aux.name, "history.tsv"),
                        CARGO_TARGET_DIR=os.path.join(self.aux.name, "target"),
                        IBEX_COVERCHECK_BASE="HEAD", PYTHONDONTWRITEBYTECODE="1")
        self.env.pop("IBEX_GATE_SKIP_MEASURE", None)
        self.env.pop("COVERCHECK", None)

    def tearDown(self) -> None:
        self.r.close()
        self.aux.cleanup()

    def stage(self, name: str, body: str) -> None:
        with open(os.path.join(self.fake, name), "w") as f:
            f.write(body)

    def run_gate(self, *args: str):
        ran = os.path.join(self.fake, "ran")
        if os.path.exists(ran):
            os.unlink(ran)
        p = subprocess.run(["bash", "tools/checkin.sh", *args], cwd=self.r.path, env=self.env,
                           capture_output=True, text=True, timeout=60)
        stages = open(ran).read().split() if os.path.exists(ran) else []
        return p.returncode, p.stdout + p.stderr, stages

    def all_stages(self) -> list[str]:
        p = subprocess.run(["bash", "tools/checkin.sh", "--list"], cwd=self.r.path,
                           env=self.env, capture_output=True, text=True, check=True)
        return [line.split()[0] for line in p.stdout.splitlines() if line.strip()]

    def test_list_names_the_stages(self):
        ids = self.all_stages()
        for s in ("tripwire", "harness-tests", "findings", "oracles", "suite", "covercheck",
                  "smoke", "haproxy", "lint", "measure", "surface", "stray"):
            self.assertIn(s, ids)

    def test_rerun_failed_after_a_flake_reruns_only_that_stage(self):
        self.stage("suite", "echo 'suite: NEW FAILURES'; echo '   a/b::c (flaky: parallel run only)'; exit 1\n")
        rc, out, ran = self.run_gate()
        self.assertEqual(rc, 1, out)
        self.assertEqual(ran, self.all_stages())
        self.assertIn("checkin: FAIL (1)", out)
        os.unlink(os.path.join(self.fake, "suite"))  # the flake does not recur
        rc, out, ran = self.run_gate("--rerun-failed")
        self.assertEqual(rc, 0, out)
        self.assertEqual(ran, ["suite"])
        self.assertIn("PASS on attempt 2", out)
        self.assertIn("a/b::c (flaky: parallel run only)", out)
        self.assertIn("1 stage rerun on this tree", out.splitlines()[-1])

    def test_rerun_failed_after_a_new_commit_reruns_everything(self):
        self.stage("suite", "exit 1\n")
        rc, _out, _ran = self.run_gate()
        self.assertEqual(rc, 1)
        os.unlink(os.path.join(self.fake, "suite"))
        self.r.write("crates/x/src/lib.rs", "fn a() {}\nfn fixed() {}\n")
        self.r.commit("fix")
        rc, out, ran = self.run_gate("--rerun-failed")
        self.assertEqual(rc, 0, out)
        self.assertEqual(ran, self.all_stages())

    def test_a_dirty_tree_records_nothing(self):
        self.stage("suite", "exit 1\n")
        self.r.write("crates/x/src/lib.rs", "fn dirty() {}\n")
        rc, out, _ran = self.run_gate()
        self.assertEqual(rc, 1)
        os.unlink(os.path.join(self.fake, "suite"))
        rc, out, ran = self.run_gate("--rerun-failed")
        self.assertEqual(rc, 0, out)
        self.assertEqual(ran, self.all_stages())

    def test_only_covercheck_runs_the_suite_when_its_profiles_are_not_this_trees(self):
        rc, out, ran = self.run_gate("--only", "covercheck")
        self.assertEqual(ran, ["suite", "covercheck"], out)

    def test_only_covercheck_reuses_the_suite_run_of_this_tree(self):
        # The fake suite leaves a suite-run.json, as harness/suite.py does.
        self.stage("suite", 'mkdir -p "$IBEX_INSTRUMENTED"; echo "{}" > "$IBEX_INSTRUMENTED/suite-run.json"\n')
        self.stage("covercheck", "exit 1\n")
        rc, out, _ = self.run_gate()
        self.assertEqual(rc, 1, out)
        os.unlink(os.path.join(self.fake, "covercheck"))
        rc, out, ran = self.run_gate("--rerun-failed")
        self.assertEqual(ran, ["covercheck"], out)
        self.assertEqual(rc, 0, out)

    def test_only_gives_the_combined_verdict(self):
        rc, out, ran = self.run_gate("--only", "lint,tripwire")
        self.assertEqual(ran, ["tripwire", "lint"])
        self.assertEqual(rc, 1)  # the rest never ran on this tree
        self.assertIn("  - suite: not run on this tree", out)

    def test_unknown_stage_is_refused(self):
        rc, out, ran = self.run_gate("--only", "nosuch")
        self.assertEqual(rc, 2, out)
        self.assertEqual(ran, [])

    def test_measure_gets_the_plain_env(self):
        self.stage("measure", 'echo "R=${RUSTFLAGS:-unset} L=${LLVM_PROFILE_FILE:-unset} '
                              'I=${IBEX_INSTRUMENTED:-unset} T=$CARGO_TARGET_DIR"\n')
        self.env.update(RUSTFLAGS="-Cinstrument-coverage", LLVM_PROFILE_FILE="/x/%m.profraw")
        rc, out, ran = self.run_gate("--only", "measure")
        self.assertEqual(ran, ["measure"])
        self.assertIn(f"R=unset L=unset I=unset T={self.env['CARGO_TARGET_DIR']}\n", out)


if __name__ == "__main__":
    unittest.main()
