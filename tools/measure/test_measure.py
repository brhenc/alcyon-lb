#!/usr/bin/env python3
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
