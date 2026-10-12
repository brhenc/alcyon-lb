#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

"""Tests for the accepted-class rule of fuzz/difffuzz.py (T315).

Run:  python3 -m unittest harness/test_difffuzz.py

What must hold: a DIFF whose shape equals that of a `note:ibex-stricter` entry of the
baseline is accepted, on any input; a DIFF of another shape is not; an entry tracked by a
T-number does not make its shape an accepted class; and the committed baseline has the class.
"""
from __future__ import annotations

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "fuzz"))
import difffuzz as D  # noqa: E402

FWD = {"fwd": "e3b0c44298fc", "fwd_len": 0}
STRICTER = {"haproxy": {**FWD, "status": []}, "ibex": {**FWD, "status": ["400"]}}
TIMEOUT = {"haproxy": {**FWD, "status": []}, "ibex": {**FWD, "status": ["408"]}}


class AcceptedClass(unittest.TestCase):
    def test_shape_of_the_class_is_accepted(self):
        base = {"a": {"task": "note:ibex-stricter", "shape": STRICTER}}
        self.assertTrue(D.is_accepted(STRICTER, base))

    def test_other_shapes_are_not(self):
        base = {"a": {"task": "note:ibex-stricter", "shape": STRICTER}}
        self.assertFalse(D.is_accepted(TIMEOUT, base))
        forwarded = {"haproxy": STRICTER["haproxy"], "ibex": {"fwd": "abc", "fwd_len": 5, "status": ["400"]}}
        self.assertFalse(D.is_accepted(forwarded, base))

    def test_a_tracked_entry_is_not_a_class(self):
        base = {"a": {"task": "T291", "shape": STRICTER}}
        self.assertFalse(D.is_accepted(STRICTER, base))

    def test_committed_baseline_has_the_class(self):
        base = D.load_baseline(os.path.join(os.path.dirname(HERE), "fuzz", "known_diffs.json"))
        self.assertTrue(D.is_accepted(STRICTER, base))


if __name__ == "__main__":
    unittest.main()
