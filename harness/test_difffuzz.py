#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

"""Tests for the accepted-class rule of fuzz/difffuzz.py (T315).

Run:  python3 -m unittest harness/test_difffuzz.py

What must hold: a DIFF whose shape equals that of a `note:alcyon-stricter` entry of the
baseline is accepted, on any input; a DIFF of another shape is not; an entry tracked by a
T-number does not make its shape an accepted class; and every entry of the committed baseline
is tracked (dev11 left it no entry of the class).
"""
from __future__ import annotations

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "fuzz"))
import difffuzz as D  # noqa: E402

FWD = {"fwd": "e3b0c44298fc", "fwd_len": 0}
STRICTER = {"haproxy": {**FWD, "status": []}, "alcyon": {**FWD, "status": ["400"]}}
TIMEOUT = {"haproxy": {**FWD, "status": []}, "alcyon": {**FWD, "status": ["408"]}}


class AcceptedClass(unittest.TestCase):
    def test_shape_of_the_class_is_accepted(self):
        base = {"a": {"task": "note:alcyon-stricter", "shape": STRICTER}}
        self.assertTrue(D.is_accepted(STRICTER, base))

    def test_other_shapes_are_not(self):
        base = {"a": {"task": "note:alcyon-stricter", "shape": STRICTER}}
        self.assertFalse(D.is_accepted(TIMEOUT, base))
        forwarded = {"haproxy": STRICTER["haproxy"], "alcyon": {"fwd": "abc", "fwd_len": 5, "status": ["400"]}}
        self.assertFalse(D.is_accepted(forwarded, base))

    def test_a_tracked_entry_is_not_a_class(self):
        base = {"a": {"task": "T291", "shape": STRICTER}}
        self.assertFalse(D.is_accepted(STRICTER, base))

    def test_committed_baseline_loads_and_every_entry_is_tracked(self):
        # dev11 answers the requests the class was made for (mux-h1 fb53e904b), so the
        # committed baseline holds none of it today; the rule above stays for the next one.
        base = D.load_baseline(os.path.join(os.path.dirname(HERE), "fuzz", "known_diffs.json"))
        for key, entry in base.items():
            self.assertIn("task", entry, key)
            self.assertIn("shape", entry, key)


if __name__ == "__main__":
    unittest.main()
