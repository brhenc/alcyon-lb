#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

"""Run the HTTP transaction tests against the reference HAProxy, to see when HAProxy changes.

`crates/alcyon-rt/tests/http_txn.rs` drives a proxy binary over real sockets, and every case
in it was measured against HAProxy before Alcyon was made to match (`ALCYON_TXN_BIN` selects the
binary). Run against HAProxy here, the file states what HAProxy does today. A case that
starts failing means HAProxy's behaviour moved -- the T89 case (Content-Length beside
chunked) exists for exactly this -- and the user wants to know when that happens, not to
find out from a production diff.

The cases HAProxy is known to fail live in `data/txn_oracle_baseline.json` with a reason. Any
other failure, or a baselined case that now passes, fails this check: either way the record
of what HAProxy does is out of date.

Usage:  python3 harness/txn_oracle.py [--haproxy PATH]
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASELINE = os.path.join(REPO, "data", "txn_oracle_baseline.json")
DEFAULT_HAPROXY = "/home/bhenc/reference/haproxy/haproxy"
RESULT_RE = re.compile(r"^test (\S+) \.\.\. (ok|FAILED)\s*$", re.M)


def main() -> int:
    haproxy = DEFAULT_HAPROXY
    if "--haproxy" in sys.argv:
        haproxy = sys.argv[sys.argv.index("--haproxy") + 1]
    if not os.access(haproxy, os.X_OK):
        print(f"txn oracle: no HAProxy at {haproxy}; not run")
        return 0
    version = subprocess.run([haproxy, "-v"], capture_output=True, text=True).stdout.splitlines()[0]
    base = json.load(open(BASELINE))
    print(f"txn oracle: {version}")
    print(f"txn oracle: baseline measured on {base['measured_on']}")

    env = dict(os.environ, ALCYON_TXN_BIN=haproxy)
    # http_txn.rs is the module `http_txn` of alcyon-rt's test binary `it` (T260); its cases
    # keep their bare names in the baseline.
    p = subprocess.run(["cargo", "test", "-p", "alcyon-rt", "--test", "it", "--no-fail-fast", "--", "http_txn::"],
                       cwd=REPO, env=env, capture_output=True, text=True, timeout=1800)
    results = {t.removeprefix("http_txn::"): r for t, r in RESULT_RE.findall(p.stdout + p.stderr)
               if t.startswith("http_txn::")}
    if not results:
        print("txn oracle: no test results parsed; treating as failure")
        print((p.stdout + p.stderr)[-2000:])
        return 1
    failed = {t for t, r in results.items() if r == "FAILED"}
    expected = set(base["haproxy_fails"])

    changed = sorted(failed - expected)
    fixed = sorted(t for t in expected - failed if t in results)
    print(f"txn oracle: {len(results)} cases, HAProxy fails {len(failed)} "
          f"({len(expected)} expected)")
    for t in changed:
        print(f"   HAProxy now FAILS {t} -- its behaviour changed, or the case did")
    for t in fixed:
        print(f"   HAProxy now PASSES {t} -- baselined as: {base['haproxy_fails'][t]}")
    if changed or fixed:
        print("txn oracle: HAProxy no longer matches the record; find out what moved, then "
              "update the case or data/txn_oracle_baseline.json")
        return 1
    print("txn oracle: HAProxy behaves as recorded")
    return 0


if __name__ == "__main__":
    sys.exit(main())
