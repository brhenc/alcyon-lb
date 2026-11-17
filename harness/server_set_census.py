#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
"""Ratchet: direct access to the per-server arrays of `Proxy`, outside `srv_set.rs` (T637).

docs/design/runtime-server-set-2026-11-16.md section 4.2: the per-server arrays become private
to `srv_set.rs`, so that no command can reach a server by forgetting a check. This counts, per
file of crates/alcyon-rt/src, the places that name one of those arrays (`px.server_ids`,
`p.servers.get(..)`, `proxy.ids.server_rmaint`, ...), and compares them with the committed
`harness/server_set_census.json`. A count above its baseline fails; a count below it fails too,
until `--update` lowers the baseline (a ratchet only turns one way). The goal of S1b is zero
everywhere.

    python3 harness/server_set_census.py            check against the baseline
    python3 harness/server_set_census.py --update   rewrite the baseline (only to lower it)
    python3 harness/server_set_census.py --list F   print the matching lines of file F

`.servers` is also a field of the parsed configuration (`b.servers`, `l.servers`); those
receivers are not counted.
"""
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC = ROOT / "crates/alcyon-rt/src"
BASELINE = pathlib.Path(__file__).resolve().parent / "server_set_census.json"
# Files that own the arrays or define their types.
OWNERS = {"srv_set.rs", "srv_rt.rs"}

ARRAYS = (
    "server_ids server_cookies server_statuses server_track server_weights server_send_proxy "
    "server_tfo server_send_proxy_v2 server_pp_unique_id server_backups server_name_refd "
    "server_maxconn server_actconn server_retr server_sess_rates server_check_configs "
    "server_tls server_check_tls server_puids server_forced_ids server_init_health "
    "server_cmaint server_rmaint server_fqdns server_fqdn_changed server_srv server_check_ports "
    "server_pool server_restored"
).split()
ARRAY_RE = re.compile(r"\.(?:%s)\b(?!\s*\()" % "|".join(ARRAYS))
# A proxy's `servers` (ServerAddrs); the receivers below are the parsed configuration, and
# `px.servers` in the stats page's JavaScript is a JSON field.
SERVERS_RE = re.compile(r"(?<![\w.])(\w+(?:\[[^\]]*\])?(?:\.\w+)*)\.servers\b(?!\s*:|\s*\)|\.forEach)")
CONFIG_RECV = re.compile(r"^(?:b|l|s|sec|section|self|cfg|config|users\[\w+\]|\w*\.(?:backends|listens)|be|bk)$|^(?:config|cfg)\.")


def count_line(line):
    code = line.split("//", 1)[0]
    n = len(ARRAY_RE.findall(code))
    for m in SERVERS_RE.finditer(code):
        if not CONFIG_RECV.match(m.group(1)):
            n += 1
    return n


def census():
    out = {}
    for f in sorted(SRC.glob("*.rs")):
        if f.name in OWNERS:
            continue
        n = sum(count_line(l) for l in f.read_text().splitlines())
        if n:
            out[f.name] = n
    return out


def main(argv):
    if argv[:1] == ["--list"]:
        for i, l in enumerate((SRC / argv[1]).read_text().splitlines(), 1):
            if count_line(l):
                print(f"{argv[1]}:{i}: {l.strip()}")
        return 0
    now = census()
    if argv[:1] == ["--update"]:
        BASELINE.write_text(json.dumps(now, indent=1, sort_keys=True) + "\n")
        print(f"baseline written: {sum(now.values())} accesses in {len(now)} files")
        return 0
    base = json.loads(BASELINE.read_text())
    bad = False
    for f in sorted(set(now) | set(base)):
        a, b = now.get(f, 0), base.get(f, 0)
        if a > b:
            print(f"UP    {f}: {a} > baseline {b}: use srv_set.rs, not the arrays")
            bad = True
        elif a < b:
            print(f"DOWN  {f}: {a} < baseline {b}: run --update to lower the baseline")
            bad = True
        else:
            print(f"ok    {f}: {a}")
    print(f"total {sum(now.values())} (baseline {sum(base.values())})")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
