#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

"""Tests for the base covercheck judges a change against, and which lines it calls changed.

Run:  python3 -m unittest harness/test_covercheck.py

The base used to be `origin/main`. This repository is pushed rarely, so on a local main 18
commits ahead of origin the check judged every change since the last push -- reviewed,
merged work included -- and failed on lines nobody was asking about. The base now follows
tools/measure/measure.py `reference_sha()`: what *this* branch, or *this* commit, changed.
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import covercheck  # noqa: E402


def git(repo: str, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True,
                          text=True).stdout.strip()


class Repo:
    """A throwaway repository with a `main` branch and one source file."""

    def __init__(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.path = self.tmp.name
        git(self.path, "init", "-q", "-b", "main")
        git(self.path, "config", "user.email", "t@example.invalid")
        git(self.path, "config", "user.name", "t")
        git(self.path, "config", "commit.gpgsign", "false")
        os.makedirs(os.path.join(self.path, "crates/x/src"))
        self.write("crates/x/src/lib.rs", "fn a() {}\n")
        self.commit("root")

    def write(self, rel: str, text: str) -> None:
        p = os.path.join(self.path, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(text)

    def commit(self, msg: str) -> str:
        git(self.path, "add", "crates")
        git(self.path, "commit", "-q", "-m", msg)
        return git(self.path, "rev-parse", "HEAD")

    def close(self) -> None:
        self.tmp.cleanup()


class TestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.r = Repo()
        self.env = {k: v for k, v in os.environ.items()
                    if k not in ("IBEX_COVERCHECK_BASE", "COVERCHECK_BASE")}

    def tearDown(self) -> None:
        self.r.close()

    def base(self, **env: str) -> str:
        return covercheck.default_base(self.r.path, {**self.env, **env})

    def test_clean_main_is_judged_against_its_first_parent(self):
        before = git(self.r.path, "rev-parse", "HEAD")
        self.r.write("crates/x/src/lib.rs", "fn a() {}\nfn b() {}\n")
        self.r.commit("second")
        self.assertEqual(self.base(), before)

    def test_clean_main_merge_is_judged_against_the_pre_merge_main(self):
        # A merge on main must be judged by everything it brought in, not by nothing.
        pre = git(self.r.path, "rev-parse", "HEAD")
        git(self.r.path, "checkout", "-q", "-b", "feat")
        self.r.write("crates/x/src/lib.rs", "fn a() {}\nfn feat() {}\n")
        self.r.commit("feat")
        git(self.r.path, "checkout", "-q", "main")
        self.r.write("crates/x/src/other.rs", "fn o() {}\n")
        mainline = self.r.commit("main moves on")
        git(self.r.path, "merge", "-q", "--no-ff", "-m", "merge feat", "feat")
        self.assertNotEqual(pre, mainline)
        self.assertEqual(self.base(), mainline)
        changed = covercheck.changed_lines(self.base(), self.r.path)
        self.assertEqual(changed, {"crates/x/src/lib.rs": {2}})

    def test_dirty_main_is_judged_against_head(self):
        head = git(self.r.path, "rev-parse", "HEAD")
        self.r.write("crates/x/src/lib.rs", "fn a() {}\nfn dirty() {}\n")
        self.assertEqual(self.base(), head)
        self.assertEqual(covercheck.changed_lines(self.base(), self.r.path),
                         {"crates/x/src/lib.rs": {2}})

    def test_branch_is_judged_against_its_merge_base_with_main(self):
        fork = git(self.r.path, "rev-parse", "HEAD")
        git(self.r.path, "checkout", "-q", "-b", "fix/x")
        self.r.write("crates/x/src/lib.rs", "fn a() {}\nfn one() {}\n")
        self.r.commit("one")
        self.r.write("crates/x/src/lib.rs", "fn a() {}\nfn one() {}\nfn two() {}\n")
        self.r.commit("two")
        # main moving on after the fork must not count against the branch
        git(self.r.path, "checkout", "-q", "main")
        self.r.write("crates/x/src/m.rs", "fn m() {}\n")
        self.r.commit("main")
        git(self.r.path, "checkout", "-q", "fix/x")
        self.assertEqual(self.base(), fork)
        self.assertEqual(covercheck.changed_lines(self.base(), self.r.path),
                         {"crates/x/src/lib.rs": {2, 3}})

    def test_branch_with_no_commits_of_its_own_behaves_like_main(self):
        # A fresh worktree branch sitting on main must not degrade to "nothing changed".
        before = git(self.r.path, "rev-parse", "HEAD")
        self.r.write("crates/x/src/lib.rs", "fn a() {}\nfn b() {}\n")
        self.r.commit("second")
        git(self.r.path, "checkout", "-q", "-b", "worktree-x")
        self.assertEqual(self.base(), before)

    def test_override_wins(self):
        root = git(self.r.path, "rev-list", "--max-parents=0", "HEAD")
        self.r.write("crates/x/src/lib.rs", "fn a() {}\nfn b() {}\n")
        self.r.commit("second")
        self.r.write("crates/x/src/lib.rs", "fn a() {}\nfn b() {}\nfn c() {}\n")
        self.r.commit("third")
        self.assertEqual(self.base(IBEX_COVERCHECK_BASE="HEAD~2"), root)
        # the older name still works
        self.assertEqual(self.base(COVERCHECK_BASE="HEAD~2"), root)

    def test_reindented_lines_are_not_changed(self):
        # Wrapping code in a block re-indents it; the re-indented lines do what they did
        # before and are not what the change is asking a test to run. The new lines are.
        self.r.write("crates/x/src/lib.rs", "fn a() {\n    one();\n    two();\n}\n")
        self.r.commit("base")
        self.r.write("crates/x/src/lib.rs",
                     "fn a() {\n    if go() {\n        one();\n        two();\n    }\n}\n")
        self.assertEqual(covercheck.changed_lines(self.base(), self.r.path),
                         {"crates/x/src/lib.rs": {2, 5}})

    def test_untracked_source_file_counts_as_changed(self):
        # `git diff` does not see a file nobody has added; a new module written and not yet
        # staged must still be judged.
        self.r.write("crates/x/src/new.rs", "fn n() {}\nfn m() {}\n")
        changed = covercheck.changed_lines(self.base(), self.r.path)
        self.assertEqual(changed.get("crates/x/src/new.rs"), {1, 2})


class EnoughProfiles(unittest.TestCase):
    def test_a_mostly_uninstrumented_build_is_refused(self):
        # Seen on 2026-10-03: 22 profiles from 148 binaries; the report held none of
        # ibex-sample, and covercheck exited 0 on a planted untested function.
        self.assertFalse(covercheck.enough_profiles(22, 148))

    def test_a_fully_instrumented_build_is_accepted(self):
        self.assertTrue(covercheck.enough_profiles(140, 148))
        self.assertTrue(covercheck.enough_profiles(0, 0))


class StaleBinaries(unittest.TestCase):
    """`cargo llvm-cov report` reads every executable in deps/, and an earlier tree's test
    binaries stay there under other hashes. Their coverage maps carry that tree's line
    numbers, all unexecuted: the gate on 5553218 reported doc comments and blank lines as
    "changed lines no test executes" (306 binaries for 152 targets). Only what this build
    produced may reach the report."""

    def test_only_the_binaries_this_build_produced_are_kept(self):
        with tempfile.TemporaryDirectory() as root:
            deps = os.path.join(root, "deps")
            os.mkdir(deps)

            def exe(name):
                path = os.path.join(deps, name)
                open(path, "w").close()
                os.chmod(path, 0o755)
                return path
            tests = {exe("reload-1111111111111111"), exe("ibex-2222222222222222")}
            exe("reload-3333333333333333")
            exe("ibex-4444444444444444")
            open(os.path.join(deps, "libibex_rt-5555555555555555.rlib"), "w").close()
            # The binary the integration tests spawn: cargo names it by its uplifted path,
            # a hard link of the one in deps/.
            in_deps = exe("ibex-6666666666666666")
            uplifted = os.path.join(root, "ibex")
            os.link(in_deps, uplifted)
            self.assertEqual(covercheck.prune_stale_binaries(deps, tests | {uplifted}), 2)
            self.assertEqual(sorted(os.listdir(deps)),
                             sorted([os.path.basename(p) for p in tests | {in_deps}]
                                    + ["libibex_rt-5555555555555555.rlib"]))


if __name__ == "__main__":
    unittest.main()


class CorruptProfiles(unittest.TestCase):
    """T143: one corrupt .profraw made `llvm-profdata merge` fail, no report was written,
    and covercheck printed "skipping" -- the gate counted the section as passed."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        src = os.path.join(cls.tmp.name, "p.rs")
        with open(src, "w") as f:
            f.write("fn main() { println!(\"x\"); }\n")
        exe = os.path.join(cls.tmp.name, "p")
        subprocess.run(["rustc", "-C", "instrument-coverage", "-o", exe, src], check=True,
                       capture_output=True)
        cls.good = os.path.join(cls.tmp.name, "good.profraw")
        subprocess.run([exe], check=True, capture_output=True,
                       env={**os.environ, "LLVM_PROFILE_FILE": cls.good})

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def dir_with(self, n_good: int, n_bad: int) -> tempfile.TemporaryDirectory:
        d = tempfile.TemporaryDirectory()
        data = open(self.good, "rb").read()
        for i in range(n_good):
            with open(os.path.join(d.name, f"g{i}.profraw"), "wb") as f:
                f.write(data)
        for i in range(n_bad):
            with open(os.path.join(d.name, f"b{i}.profraw"), "wb") as f:
                f.write(b"\0" * 64 + data[:20])  # header is corrupt
        return d

    def test_corrupt_profiles_are_dropped_and_counted(self):
        d = self.dir_with(3, 2)
        self.addCleanup(d.cleanup)
        dropped = covercheck.drop_corrupt_profiles(d.name, covercheck._llvm_env())
        self.assertEqual(sorted(dropped), ["b0.profraw", "b1.profraw"])
        self.assertEqual(sorted(os.listdir(d.name)), ["g0.profraw", "g1.profraw", "g2.profraw"])

    def test_clean_profiles_are_left_alone(self):
        d = self.dir_with(2, 0)
        self.addCleanup(d.cleanup)
        self.assertEqual(covercheck.drop_corrupt_profiles(d.name, covercheck._llvm_env()), [])
        self.assertEqual(len(os.listdir(d.name)), 2)

    def test_no_usable_profile_is_a_failure_not_a_skip(self):
        d = self.dir_with(0, 2)
        self.addCleanup(d.cleanup)
        self.assertEqual(len(covercheck.drop_corrupt_profiles(d.name, covercheck._llvm_env())), 2)
        self.assertFalse(covercheck.has_profiles(d.name))


class MissingReport(unittest.TestCase):
    def test_no_lcov_file_is_a_failure_not_a_skip(self):
        old = covercheck.LCOV
        with tempfile.TemporaryDirectory() as t:
            covercheck.LCOV = os.path.join(t, "none.lcov")
            orig = covercheck.run_pooled
            covercheck.run_pooled = lambda: True  # tests "ran" and wrote nothing
            try:
                self.assertIsNone(covercheck.covered({"a.rs"}))
            finally:
                covercheck.run_pooled = orig
                covercheck.LCOV = old
