#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

"""Tests for tools/findings.py (T292): the ledger validator and the clean-hours rule.

Run:  python3 -m unittest harness/test_findings.py

What must hold: a malformed ledger (duplicate id, bad enum, a fixed row without fixed_on, a run
naming an unknown finding) is reported; an open finding is not an error; clean hours count only
runs of the method that started after its last finding, found nothing, and ran on the lineage;
and the committed CSVs themselves are valid.
"""
from __future__ import annotations

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "tools"))
import findings as F  # noqa: E402


def row(**kw):
    r = dict(id="VV-1", found="2026-10-10 10:00", method="vv-probe", severity="high",
             **{"class": "parity"})
    r.update(found_on="abc", task="T1", status="open", fixed_on="", fixed="", verified_on="",
             summary="s", note="")
    r.update(kw)
    return r


def run(**kw):
    r = dict(start="2026-10-10 12:00", method="vv-soak", commit="abc", duration_min="60",
             new_findings="0", note="")
    r.update(kw)
    return r


class Validate(unittest.TestCase):
    def test_well_formed_with_open_finding(self):
        self.assertEqual(F.validate([row()], [run()]), [])

    def test_duplicate_id(self):
        self.assertTrue(any("duplicate" in e for e in F.validate([row(), row()], [])))

    def test_bad_enum_and_id(self):
        errs = F.validate([row(id="XX-1", severity="huge", status="done")], [])
        self.assertEqual(len(errs), 3, errs)

    def test_fixed_needs_fixed_on(self):
        self.assertTrue(any("fixed_on" in e for e in F.validate([row(status="fixed")], [])))
        self.assertEqual(F.validate([row(status="fixed", fixed_on="def")], []), [])

    def test_bad_timestamp_and_run_refs(self):
        self.assertTrue(F.validate([row(found="yesterday")], []))
        self.assertTrue(F.validate([row()], [run(new_findings="VV-9")]))
        self.assertTrue(F.validate([row()], [run(new_findings="")]))
        self.assertEqual(F.validate([row()], [run(new_findings="VV-1")]), [])


class CleanHours(unittest.TestCase):
    def test_only_runs_after_last_finding(self):
        fs = [row(method="vv-soak", found="2026-10-10 12:00")]
        rs = [run(start="2026-10-10 11:00", duration_min="60"),
              run(start="2026-10-10 13:00", duration_min="90"),
              run(start="2026-10-10 15:00", duration_min="30")]
        h, since, n = F.clean_hours(fs, rs)["vv-soak"]
        self.assertEqual((h, n), (2.0, 2))
        self.assertEqual(since.strftime(F.TS), "2026-10-10 12:00")

    def test_never_found_counts_everything(self):
        h, since, n = F.clean_hours([row(method="redteam")], [run(), run(duration_min="")])["vv-soak"]
        self.assertEqual((h, since, n), (1.0, None, 2))

    def test_dirty_run_and_off_lineage_do_not_count(self):
        rs = [run(new_findings="VV-1"), run(commit="zzz"), run(commit="abc")]
        h, _, n = F.clean_hours([row()], rs, lineage=lambda c: c == "abc")["vv-soak"]
        self.assertEqual((h, n), (1.0, 1))

    def test_other_methods_do_not_reset(self):
        fs = [row(method="redteam", found="2026-10-10 20:00")]
        h, _, _ = F.clean_hours(fs, [run()])["vv-soak"]
        self.assertEqual(h, 1.0)


class MeanFix(unittest.TestCase):
    def test_mean_over_rows_with_both_times(self):
        fs = [row(status="fixed", fixed_on="x", fixed="2026-10-10 12:00"),
              row(id="VV-2", status="fixed", fixed_on="x", fixed="2026-10-10 14:00"),
              row(id="VV-3", status="fixed", fixed_on="x"), row(id="VV-4")]
        self.assertEqual(F.mean_found_to_fixed(fs), (3.0, 2))
        self.assertEqual(F.mean_found_to_fixed([row()]), (None, 0))


class Committed(unittest.TestCase):
    def test_the_committed_ledger_is_valid(self):
        self.assertEqual(F.validate(F.read_csv(F.FINDINGS), F.read_csv(F.RUNS)), [])


if __name__ == "__main__":
    unittest.main()
