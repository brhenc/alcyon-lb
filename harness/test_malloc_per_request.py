#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

"""The malloc-per-request ratchet on the release binary (harness/malloc_per_request.py).

Run:  CARGO_TARGET_DIR=... python3 -m unittest harness/test_malloc_per_request.py
(needs `cargo build --release -p ibex-rt --bin ibex`; skipped when there is no binary).
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import malloc_per_request as M  # noqa: E402

BIN = os.environ.get("IBEX_BIN") or M.default_binary()


class Verdict(unittest.TestCase):
    def test_a_count_above_its_pin_fails_and_below_asks_for_a_lower_pin(self):
        rows = [("bare", "min", "keep-alive", 4, 0, 3), ("bare", "min", "close", 2, 0, 3),
                ("bare", "ab", "close", 6, 0, 6)]
        fails, notes = M.verdict(rows)
        self.assertEqual([r[2] for r in fails], ["keep-alive"])
        self.assertEqual([r[3] for r in notes], [2])


@unittest.skipUnless(os.access(BIN, os.X_OK), f"no release binary at {BIN}")
class ShippedBinary(unittest.TestCase):
    def test_no_request_shape_allocates_more_than_its_pin(self):
        rows = M.run(BIN)
        fails, _ = M.verdict(rows)
        self.assertEqual(fails, [], f"allocations per request above the ratchet: {fails}; rows: {rows}")


if __name__ == "__main__":
    unittest.main()
