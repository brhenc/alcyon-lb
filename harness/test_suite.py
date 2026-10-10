#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

"""Tests for suite.py: the report of slow tests (T259), and running each test in a process
of its own (T260).

Run:  python3 -m unittest harness/test_suite.py

The pool's wall time is its slowest test, so suite.py names every test over 10 s after
each run: a new slow test is seen the day it lands rather than when the gate has crept up.
"""
from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import suite  # noqa: E402


class SlowTargets(unittest.TestCase):
    def test_names_tests_over_10s_slowest_first(self):
        line = suite.slow_targets_line({"ibex-rt/it::a": 3.0, "ibex-rt/it::b::t": 12.25,
                                        "ibex-rt/c::t": 70.5, "ibex-rt/it::d": 10.0})
        self.assertEqual(line, "suite: slow tests (over 10s): ibex-rt/c::t 70.5s, ibex-rt/it::b::t 12.2s")

    def test_none(self):
        self.assertEqual(suite.slow_targets_line({"ibex-rt/it::a": 9.9}),
                         "suite: slow tests (over 10s): none")


# `<binary> --list --format terse`, and the same with `--ignored`.
LIST = """cli_show_sess::a_session: test
cli_show_sess::b_session: test
proptest_x::slow_one: test
benches::b: benchmark
"""
IGNORED = "proptest_x::slow_one: test\n"


class OneProcessPerTest(unittest.TestCase):
    def test_the_listed_tests_less_the_ignored_ones(self):
        self.assertEqual(suite.listed_tests(LIST, IGNORED),
                         ["cli_show_sess::a_session", "cli_show_sess::b_session"])

    def test_a_run_that_ran_no_test_is_not_a_pass(self):
        # `--exact <name>` with a name the binary no longer has runs nothing and exits 0.
        none = "running 0 tests\n\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out\n"
        one = "running 1 test\ntest m::t ... ok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 8 filtered out\n"
        self.assertEqual(suite.test_verdict(0, none), "not run")
        self.assertEqual(suite.test_verdict(0, one), "ok")
        self.assertEqual(suite.test_verdict(101, one.replace("... ok", "... FAILED")), "failed")
        self.assertEqual(suite.test_verdict(-9, ""), "hung")
        self.assertEqual(suite.test_verdict(134, "running 1 test\n"), "failed")

    def test_instrumented_processes_merge_into_a_pool_not_one_profile_each(self):
        # One profile per process would be one per test: thousands of files of megabytes.
        self.assertEqual(suite.pooled_profile("/t/llvm-cov-target/ibex-%p-%64m.profraw"),
                         "/t/llvm-cov-target/ibex-%16m.profraw")
        self.assertEqual(suite.pooled_profile("/t/x-%p.profraw"), "/t/x-%16m.profraw")

    def test_serial_entries_are_tests_or_prefixes(self):
        self.assertTrue(suite.is_serial("ibex-rt/it::fd_hygiene::an_idle_server_connection"))
        self.assertTrue(suite.is_serial("ibex-rt/request_allocations::sixty_thousand"))
        self.assertFalse(suite.is_serial("ibex-rt/it::fd_hygiene_x::t"))
        self.assertFalse(suite.is_serial("ibex-rt/it::http_txn::t"))

    def test_cargo_output_is_read_per_binary_with_one_binary_per_crate(self):
        out = """     Running unittests src/lib.rs (/t/debug/deps/ibex_rt-0123abcd)
test proxy::tests::x ... FAILED
     Running tests/it/main.rs (/t/debug/deps/it-89abcdef01234567)
test cli_show_sess::a ... FAILED
     Running tests/request_allocations.rs (/t/debug/deps/request_allocations-0011aabb)
test sixty ... FAILED
"""
        self.assertEqual(suite.failed_by_target(out),
                         {"lib": {"proxy::tests::x"}, "it": {"cli_show_sess::a"},
                          "request_allocations": {"sixty"}})


if __name__ == "__main__":
    unittest.main()


class KnownFlaky(unittest.TestCase):
    """A test in `known_flaky` that fails alone in some runs, not all, is the flake its entry
    excuses, not a new failure; one that fails every alone run is."""

    def run_main(self, bad_runs: int, flaky_key: str, failures: dict | None = None):
        import io
        import json
        import tempfile
        from contextlib import redirect_stdout
        from unittest import mock
        base = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        json.dump({"known_failures": failures or {}, "known_flaky": {flaky_key: "a reason"}}, base)
        base.close()
        job = ("ibex-rt", "lib", "proxy::tests::t", ["/fake/bin", "--exact", "proxy::tests::t"], "/", None)

        def confirm(cmd, runs, cwd=None, env=None, test=None):
            n = min(runs, bad_runs)
            confirm.left = getattr(confirm, "left", bad_runs)
            return ({test} if n else set()), n
        out = io.StringIO()
        with mock.patch.object(suite, "BASELINE", base.name), \
                mock.patch.object(suite, "instrument", return_value=None), \
                mock.patch.object(suite, "run_parallel", return_value=([job], {"lib": {"proxy::tests::t"}}, 10, 1)), \
                mock.patch.object(suite, "confirm_cmd", side_effect=confirm), \
                mock.patch.dict(os.environ, {"SUITE_SERIAL": "0"}), redirect_stdout(out):
            rc = suite.main()
        os.unlink(base.name)
        return rc, out.getvalue()

    def test_failing_alone_1_of_3_is_the_excused_flake(self):
        rc, out = self.run_main(1, "ibex-rt/lib::proxy::tests::t")
        self.assertEqual(rc, 0, out)
        self.assertNotIn("NEW FAILURES", out)

    def test_failing_alone_3_of_3_is_new(self):
        rc, out = self.run_main(3, "ibex-rt/lib::proxy::tests::t")
        self.assertEqual(rc, 1, out)
        self.assertIn("NEW FAILURES", out)

    def test_another_tests_flaky_entry_excuses_nothing(self):
        rc, out = self.run_main(1, "ibex-rt/lib::proxy::tests::other")
        self.assertEqual(rc, 1, out)
