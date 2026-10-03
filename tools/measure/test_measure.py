#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

"""
Unit tests for Ibex Continuous Measurement regression detector.
"""

import unittest
from measure import check_regressions, MetricDelta, Verdict


class TestRegressionDetector(unittest.TestCase):
    def test_allocations_increase_is_regression(self):
        current = {"allocs_per_request": 6}
        previous = {"allocs_per_request": 5}
        deltas, verdict = check_regressions(current, previous)
        self.assertEqual(verdict, Verdict.FAIL)
        self.assertTrue(any(d.name == "allocs_per_request" and d.is_regression for d in deltas))

    def test_allocations_equal_is_pass(self):
        current = {"allocs_per_request": 5}
        previous = {"allocs_per_request": 5}
        deltas, verdict = check_regressions(current, previous)
        self.assertEqual(verdict, Verdict.PASS)

    def test_bytes_per_request_threshold(self):
        # <= 10% increase is PASS
        current = {"bytes_per_request": 136} # 124 * 1.096
        previous = {"bytes_per_request": 124}
        deltas, verdict = check_regressions(current, previous)
        self.assertEqual(verdict, Verdict.PASS)

        # > 10% increase is FAIL
        current = {"bytes_per_request": 150} # > 124 * 1.10
        deltas, verdict = check_regressions(current, previous)
        self.assertEqual(verdict, Verdict.FAIL)
        self.assertTrue(any(d.name == "bytes_per_request" and d.is_regression for d in deltas))

    def test_vtc_pass_decrease_is_regression(self):
        # 7 -> 6 is regression
        current = {"board": {"pass": 6, "fail": 165, "skip": 89, "scope": 52}}
        previous = {"board": {"pass": 7, "fail": 164, "skip": 89, "scope": 52}}
        deltas, verdict = check_regressions(current, previous)
        self.assertEqual(verdict, Verdict.FAIL)
        self.assertTrue(any(d.name == "vtc_pass" and d.is_regression for d in deltas))

        # 7 -> 8 is PASS
        current = {"board": {"pass": 8, "fail": 163, "skip": 89, "scope": 52}}
        deltas, verdict = check_regressions(current, previous)
        self.assertEqual(verdict, Verdict.PASS)

    def test_throughput_decrease_threshold(self):
        # <= 15% decrease is PASS (spread / noise)
        current = {"rps_1conn": 8500} # 10000 * 0.85
        previous = {"rps_1conn": 10000}
        deltas, verdict = check_regressions(current, previous)
        self.assertEqual(verdict, Verdict.PASS)

        # > 15% decrease is FAIL
        current = {"rps_1conn": 8400} # < 10000 * 0.85
        deltas, verdict = check_regressions(current, previous)
        self.assertEqual(verdict, Verdict.FAIL)
        self.assertTrue(any(d.name == "rps_1conn" and d.is_regression for d in deltas))

    def test_throughput_is_judged_against_the_reference_build_of_the_same_run(self):
        # An alternating A/B against the base commit's build measured in the same run.
        # The last record does not matter: it may come from a noisier machine or moment.
        previous = {"rps_1conn": 20000, "cpu_ns_per_req_50conn": 10000}
        current = {"rps_1conn": 9200, "rps_1conn_ref": 10000,
                   "cpu_ns_per_req_50conn": 41200, "cpu_ns_per_req_50conn_ref": 40000}
        deltas, verdict = check_regressions(current, previous)
        self.assertEqual(verdict, Verdict.PASS)

        # Requests/s samples move 10% between identical builds; only a large drop fails.
        current = {"rps_1conn": 8400, "rps_1conn_ref": 10000}
        deltas, verdict = check_regressions(current, {"rps_1conn": 5000})
        self.assertEqual(verdict, Verdict.FAIL)
        d = next(d for d in deltas if d.name == "rps_1conn")
        self.assertTrue(d.is_regression)
        self.assertEqual(d.previous, "10,000 (ref)")

    def test_cpu_per_request_is_the_tight_ab_check(self):
        # ibex CPU per request at 50 connections varies about 2% between identical builds.
        current = {"cpu_ns_per_req_50conn": 41800, "cpu_ns_per_req_50conn_ref": 40000}
        deltas, verdict = check_regressions(current, {"cpu_ns_per_req_50conn": 99999})
        self.assertEqual(verdict, Verdict.FAIL)
        d = next(d for d in deltas if d.name == "cpu_ns_per_req_50conn")
        self.assertTrue(d.is_regression)

        current = {"cpu_ns_per_req_50conn": 41000, "cpu_ns_per_req_50conn_ref": 40000}
        deltas, verdict = check_regressions(current, {"cpu_ns_per_req_50conn": 1})
        self.assertEqual(verdict, Verdict.PASS)

    def test_binary_size_threshold(self):
        # <= 5% increase is PASS
        current = {"binary_bytes": 105000000}
        previous = {"binary_bytes": 100000000}
        deltas, verdict = check_regressions(current, previous)
        self.assertEqual(verdict, Verdict.PASS)

        # > 5% increase is FAIL
        current = {"binary_bytes": 106000000}
        deltas, verdict = check_regressions(current, previous)
        self.assertEqual(verdict, Verdict.FAIL)
        self.assertTrue(any(d.name == "binary_bytes" and d.is_regression for d in deltas))

    def test_no_previous_run_is_baseline_pass(self):
        current = {"allocs_per_request": 5, "rps_1conn": 10000}
        previous = None
        deltas, verdict = check_regressions(current, previous)
        self.assertEqual(verdict, Verdict.BASELINE)


if __name__ == "__main__":
    unittest.main()
