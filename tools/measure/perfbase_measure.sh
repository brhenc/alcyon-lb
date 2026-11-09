#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
#
# perfbase.sh's measurement: tools/measure/perfbase_measure.sh <bin> <sha> <json-out>
# Runs on the slot's CPUs (ALCYON_MEASURE_CPUS from slot.sh). ab1 keepalive, ab1 rules, h2s1.
set -u
BIN=$1; SHA=$2; OUT=$3
HERE=$(cd "$(dirname "$0")" && pwd)
N=${ALCYON_PERFBASE_N:-20000}; R=5
W=$(mktemp -d /tmp/perfbase-measure.XXXXXX); trap 'rm -rf "$W"' EXIT
run() { # label scenario client n
  "$HERE/insreq.sh" "$1" "$BIN" "$HERE/scenarios/$2" "$3" "$4" "$R" "$W" > "$W/$1.out" 2>&1 || { cat "$W/$1.out" >&2; exit 1; }
  cat "$W/$1.out" >&2
}
run ab1-keepalive keepalive.body ab1 "$N"
run ab1-rules rules.body ab1 "$N"
run h2s1 tls.body h2s1 "${ALCYON_PERFBASE_N_H2:-10000}"
python3 - "$W" "$SHA" "$N" "$R" > "$OUT" <<'PY'
import json, re, sys, datetime
w, sha, n, r = sys.argv[1:]
rows = []
for lab in ("ab1-keepalive", "ab1-rules", "h2s1"):
    t = open(f"{w}/{lab}.out").read()
    m = re.search(r"summary \(min total of \d+\): user (\d+), kernel (\d+), total (\d+)", t)
    if not m:
        sys.exit(f"{lab}: no summary line")
    rows.append({"scenario": lab, "user": int(m[1]), "kernel": int(m[2]), "total": int(m[3])})
print(json.dumps({"sha": sha, "requests": int(n), "rounds": int(r), "rows": rows,
                  "at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}, indent=1))
PY
