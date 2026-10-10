#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

"""Tests for suite.py's report of slow targets (T259).

Run:  python3 -m unittest harness/test_suite.py

The pool's wall time is its slowest target, so suite.py names every target over 10 s after
each run: a new slow test is seen the day it lands rather than when the gate has crept up.
"""
from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import suite  # noqa: E402


class SlowTargets(unittest.TestCase):
    def test_names_targets_over_10s_slowest_first(self):
        line = suite.slow_targets_line({"ibex-rt/a": 3.0, "ibex-rt/b": 12.25, "ibex-rt/c": 70.5,
                                        "ibex-rt/d": 10.0})
        self.assertEqual(line, "suite: slow targets (over 10s): ibex-rt/c 70.5s, ibex-rt/b 12.2s")

    def test_none(self):
        self.assertEqual(suite.slow_targets_line({"ibex-rt/a": 9.9}),
                         "suite: slow targets (over 10s): none")


if __name__ == "__main__":
    unittest.main()
