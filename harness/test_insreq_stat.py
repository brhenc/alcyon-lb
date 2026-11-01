#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
"""Tests for insreq.sh's kernel-instruction counting (T568).

Run:  python3 -m unittest harness/test_insreq_stat.py
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools", "measure"))
from insreq_stat import parse_stat, summary  # noqa: E402
from measure import parse_insreq, parse_insreq_kernel  # noqa: E402


class InsreqStat(unittest.TestCase):
    def test_both_events(self):
        t = "2200000000,,instructions:u,5000,100.00,,\n150000000,,instructions:k,5000,100.00,,\n"
        self.assertEqual(parse_stat(t), (2200000000, 150000000))

    def test_kernel_not_counted_is_none(self):
        for bad in ("<not supported>", "<not counted>"):
            t = f"100,,instructions:u,1,100.00,,\n{bad},,instructions:k,0,0.00,,\n"
            self.assertEqual(parse_stat(t), (100, None))

    def test_user_only_file(self):
        self.assertEqual(parse_stat("7,,instructions:u,1,100.00,,\n"), (7, None))

    def test_no_user_count_is_an_error(self):
        self.assertRaises(ValueError, parse_stat, "<not supported>,,instructions:u,0,0.00,,\n")
        self.assertRaises(ValueError, parse_stat, "")

    def test_round_lines_keep_the_old_format_for_user_space(self):
        out = ("x round 1: 2200000000 instructions, 36666 ins/req\n"
               "x round 1 kernel: 150000000 instructions, 2500 ins/req, total 39166 ins/req\n"
               "x round 2: 2100000000 instructions, 35000 ins/req, 1.9700 client dgrams/req\n"
               "x round 2 kernel: n/a\n")
        self.assertEqual(parse_insreq(out), [2200000000, 2100000000])
        self.assertEqual(parse_insreq_kernel(out), [150000000])

    def test_summary_is_one_round_whose_user_plus_kernel_is_total(self):
        # round 2 has the least user, round 1 the least total
        rounds = [(1000, 5000), (900, 5200), (1100, 5100)]
        self.assertEqual(summary("x", rounds, 10),
                         "x summary (min total of 3): user 100, kernel 500, total 600 ins/req")

    def test_summary_without_kernel(self):
        self.assertEqual(summary("x", [(1000, None), (900, None)], 10),
                         "x summary (min of 2): user 90, kernel n/a, total n/a ins/req")


if __name__ == "__main__":
    unittest.main()
