#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

"""Findings ledger report: is verification converging? (T292)

Reads data/findings.csv and data/verification_runs.csv and prints
  (a) open findings by severity and class,
  (b) new findings per method per day,
  (c) per method: hours of clean running since its last new finding, counting only runs on
      the lineage of a ref (default main), and
  (d) mean time from found to fixed.

  python3 tools/findings.py            report on stdout
  python3 tools/findings.py --md       also write data/findings.md (generated, committed)
  python3 tools/findings.py --check    validate the CSVs only (the gate calls this):
                                       exit 1 on a malformed ledger; open findings are fine
  python3 tools/findings.py --no-git   count every run, whatever its commit
"""
from __future__ import annotations

import csv
import os
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FINDINGS = os.path.join(ROOT, "data", "findings.csv")
RUNS = os.path.join(ROOT, "data", "verification_runs.csv")
MD = os.path.join(ROOT, "data", "findings.md")

FINDING_COLS = ["id", "found", "method", "class", "severity", "found_on", "task", "status",
                "fixed_on", "fixed", "verified_on", "summary", "note"]
RUN_COLS = ["start", "method", "commit", "duration_min", "new_findings", "note"]
METHODS = ["vv-battery", "vv-soak", "vv-probe", "redteam", "fuzz-libfuzzer",
           "fuzz-differential", "review", "gate", "user"]
CLASSES = ["smuggling", "crash", "bypass", "dos", "leak", "parity", "perf", "flaky"]
SEVERITIES = ["critical", "high", "medium", "low"]
STATUSES = ["open", "fixed", "refuted", "wontfix", "documented"]
ID_PREFIXES = ("VV", "MY", "FZ", "RV", "GT")
TS = "%Y-%m-%d %H:%M"


def read_csv(path):
    with open(path, newline="") as fh:
        return list(csv.DictReader(fh))


def _ts(s):
    return datetime.strptime(s, TS)


def validate(findings, runs):
    """Return a list of problems; empty means the ledger is well formed."""
    errs = []
    seen = set()
    ids = set()
    for n, r in enumerate(findings, 2):
        where = "findings.csv line %d (%s)" % (n, r.get("id", "?"))
        fid = r.get("id") or ""
        pre, _, num = fid.partition("-")
        if pre not in ID_PREFIXES or not num.isdigit():
            errs.append("%s: id must be one of %s-<n>" % (where, "/".join(ID_PREFIXES)))
        if fid in seen:
            errs.append("%s: duplicate id" % where)
        seen.add(fid)
        ids.add(fid)
        for col, allowed in (("method", METHODS), ("class", CLASSES),
                             ("severity", SEVERITIES), ("status", STATUSES)):
            if r.get(col) not in allowed:
                errs.append("%s: %s %r not in %s" % (where, col, r.get(col), allowed))
        for col in ("found", "fixed"):
            v = r.get(col) or ""
            if v or col == "found":
                try:
                    _ts(v)
                except ValueError:
                    errs.append("%s: %s %r is not YYYY-MM-DD HH:MM" % (where, col, v))
        if r.get("status") == "fixed" and not (r.get("fixed_on") or "").strip():
            errs.append("%s: status fixed needs fixed_on" % where)
        if not (r.get("summary") or "").strip():
            errs.append("%s: empty summary" % where)
    for n, r in enumerate(runs, 2):
        where = "verification_runs.csv line %d" % n
        try:
            _ts(r.get("start") or "")
        except ValueError:
            errs.append("%s: start %r is not YYYY-MM-DD HH:MM" % (where, r.get("start")))
        if r.get("method") not in METHODS:
            errs.append("%s: method %r not in %s" % (where, r.get("method"), METHODS))
        d = (r.get("duration_min") or "").strip()
        if d and not d.isdigit():
            errs.append("%s: duration_min %r is not whole minutes" % (where, d))
        nf = (r.get("new_findings") or "").strip()
        if nf == "":
            errs.append("%s: new_findings must be 0 or ids" % where)
        elif nf != "0":
            for i in nf.split(";"):
                if i.strip() not in ids:
                    errs.append("%s: new_findings names unknown id %r" % (where, i.strip()))
    return errs


def on_lineage(commit, ref="main"):
    """True when `commit` is an ancestor of `ref` (or equals it). Unknown commits are False."""
    if not commit:
        return False
    try:
        rc = subprocess.run(["git", "-C", ROOT, "merge-base", "--is-ancestor", commit, ref],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode
    except OSError:
        return False
    return rc == 0


def clean_hours(findings, runs, lineage=lambda c: True):
    """{method: (hours, last_finding_ts or None, runs_counted)}.

    Hours of clean running = sum of duration_min of the runs of that method that started after
    the method's last finding, reported no new finding, and ran on a commit for which
    lineage(commit) is true. Runs without a duration count as 0 minutes.
    """
    last = {}
    for f in findings:
        t = _ts(f["found"])
        if f["method"] not in last or t > last[f["method"]]:
            last[f["method"]] = t
    # a run that reported findings is also a finding time for its method
    out = {}
    for m in METHODS:
        mins = 0
        cnt = 0
        since = last.get(m)
        for r in runs:
            if r["method"] != m:
                continue
            if r["new_findings"].strip() != "0":
                continue
            if since is not None and _ts(r["start"]) <= since:
                continue
            if not lineage(r["commit"]):
                continue
            mins += int(r["duration_min"] or 0)
            cnt += 1
        out[m] = (mins / 60.0, since, cnt)
    return out


def mean_found_to_fixed(findings):
    """(mean hours, number of findings used). Only rows with both found and fixed times."""
    ds = []
    for f in findings:
        if f["status"] == "fixed" and f.get("fixed"):
            ds.append((_ts(f["fixed"]) - _ts(f["found"])).total_seconds() / 3600.0)
    return (sum(ds) / len(ds) if ds else None, len(ds))


def report(findings, runs, lineage):
    L = []
    opn = [f for f in findings if f["status"] == "open"]
    L.append("== (a) open findings: %d of %d" % (len(opn), len(findings)))
    c = Counter((f["severity"], f["class"]) for f in opn)
    cls = [k for k in CLASSES if any(k == x[1] for x in c)]
    L.append("%-9s %s  total" % ("severity", " ".join("%9s" % k for k in cls)))
    for s in SEVERITIES:
        row = [c[(s, k)] for k in cls]
        L.append("%-9s %s  %5d" % (s, " ".join("%9d" % v for v in row), sum(row)))
    L.append("")
    L.append("== (b) new findings per method per day")
    per = defaultdict(Counter)
    for f in findings:
        per[f["found"][:10]][f["method"]] += 1
    ms = [m for m in METHODS if any(m in v for v in per.values())]
    L.append("%-10s %s" % ("day", " ".join("%17s" % m for m in ms)))
    for d in sorted(per):
        L.append("%-10s %s" % (d, " ".join("%17d" % per[d][m] for m in ms)))
    L.append("")
    L.append("== (c) clean hours since the method's last new finding (runs on the main lineage)")
    L.append("%-18s %7s  %-16s %s" % ("method", "hours", "last finding", "runs"))
    for m, (h, since, n) in clean_hours(findings, runs, lineage).items():
        if since is None and n == 0:
            continue
        L.append("%-18s %7.1f  %-16s %d" % (m, h, since.strftime(TS) if since else "never", n))
    L.append("")
    mean, n = mean_found_to_fixed(findings)
    L.append("== (d) mean time found -> fixed")
    L.append("%s over %d findings with both timestamps (%d fixed in all)"
             % ("%.1f h" % mean if mean is not None else "n/a", n,
                sum(1 for f in findings if f["status"] == "fixed")))
    return "\n".join(L)


MD_HEADER = """# Findings ledger (generated by tools/findings.py --md; do not edit by hand)

Source of truth: `data/findings.csv` (one row per finding) and `data/verification_runs.csv`
(one row per verification run). Purpose: M1 is done when the finding rate falls, not when a
checklist is ticked (T292).

**How to add rows.** Append a line to `data/findings.csv` (never delete or renumber a row; a
correction is an edited status or a later row) and, for every run you made, a line to
`data/verification_runs.csv`. Keep the id scheme: `VV-n` V&V, `MY-n` red team, `FZ-n`
differential fuzz, `RV-n` review/agent finds, `GT-n` gate-caught regressions, next free number
in your prefix. Times are local `YYYY-MM-DD HH:MM`; a time you do not know goes in `note`, not
invented. Allowed values: method {%s}, class {%s}, severity {%s}, status {%s}. A `fixed` row
needs `fixed_on`; `fixed` (time) feeds the mean time to fix. Check with
`python3 tools/findings.py --check`; the gate's harness-tests stage fails a malformed ledger,
never an open finding. Then `python3 tools/findings.py --md` and commit the CSVs and this file.

```
""" % (", ".join(METHODS), ", ".join(CLASSES), ", ".join(SEVERITIES), ", ".join(STATUSES))


def main(argv):
    if "--check" in argv:
        errs = validate(read_csv(FINDINGS), read_csv(RUNS))
        for e in errs:
            print("findings ledger: " + e)
        if errs:
            return 1
        print("findings ledger ok")
        return 0
    findings, runs = read_csv(FINDINGS), read_csv(RUNS)
    errs = validate(findings, runs)
    if errs:
        for e in errs:
            print("findings ledger: " + e, file=sys.stderr)
        return 1
    if "--no-git" in argv:
        lineage = lambda c: True
    else:
        ref = "main" if on_lineage("main", "main") else "HEAD"
        cache = {}
        lineage = lambda c: cache.setdefault(c, on_lineage(c, ref))
    text = report(findings, runs, lineage)
    print(text)
    if "--md" in argv:
        with open(MD, "w") as fh:
            fh.write(MD_HEADER + text + "\n```\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
