#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
#
# T603: the measurement matrix on slot A (/tmp/alcyon-load.lock, CPUs 4-6) for one binary:
#   insreq.sh  ab1 keepalive, ab1 rules, h2s1 (min of 5; user and kernel), h3fit when asked
#   hwcounters.sh  per-request cycles/IPC/misses on the same three, throughput 1 and 50 connections
#
#   tools/measure/variants-matrix.sh <outdir> <label> <bin> <insreq|hw|tp|h3> 
#
# One flock per call (a batch under 15 minutes). A run during which wwm.exe (the user's game) was
# seen, or with the governor not `performance`, is discarded and redone once; the load average at
# start and end is printed for every run. Counts are not timing claims; tp is, and is only valid when
# the printed load is the quiet-host load of the day.
set -u
[ $# -eq 4 ] || { sed -n 5,16p "$0"; exit 2; }
OUT=$1; L=$2; BIN=$3; WHAT=$4
HERE=$(cd "$(dirname "$0")" && pwd)
S=$HERE/scenarios
mkdir -p "$OUT"
gov() { cat /sys/devices/system/cpu/cpu4/cpufreq/scaling_governor /sys/devices/system/cpu/cpu5/cpufreq/scaling_governor /sys/devices/system/cpu/cpu6/cpufreq/scaling_governor | sort -u | tr '\n' ' '; }
game() { ps -eo comm= | grep -qx wwm.exe; }
run_locked() { # name cmd...
  local name=$1; shift
  local try
  for try in 1 2; do
    game && { echo "$L $name: game running before, waiting 30 s"; sleep 30; continue; }
    [ "$(gov)" = "performance " ] || { echo "$L $name: governor $(gov), not performance" >&2; }
    echo "$L $name try $try start $(date +%H:%M:%S) loadavg $(cut -d' ' -f1-3 /proc/loadavg) governor $(gov)"
    flock -x /tmp/alcyon-load.lock "$@" > "$OUT/$L.$name.out" 2>&1
    local rc=$?
    echo "$L $name end $(date +%H:%M:%S) loadavg $(cut -d' ' -f1-3 /proc/loadavg) rc $rc"
    if game; then echo "$L $name: game seen after the run, discarded"; continue; fi
    return $rc
  done
  echo "$L $name: not obtained" >&2; return 1
}
case $WHAT in
  insreq)
    run_locked keepalive "$HERE/insreq.sh" "$L-keepalive" "$BIN" "$S/keepalive.body" ab1 20000 5 "$OUT/w"
    run_locked rules     "$HERE/insreq.sh" "$L-rules"     "$BIN" "$S/rules.body"     ab1 20000 5 "$OUT/w"
    run_locked h2s1      "$HERE/insreq.sh" "$L-h2s1"      "$BIN" "$S/tls.body"       h2s1 10000 5 "$OUT/w"
    ;;
  h3)
    run_locked h3fit "$HERE/insreq.sh" "$L-h3fit" "$BIN" "$S/h3.body" h3fit 5000 3 "$OUT/w"
    ;;
  hw)
    run_locked hw-keepalive "$HERE/hwcounters.sh" "$L" "$BIN" "$S/keepalive.body" ab1 20000 5 "$OUT/w"
    run_locked hw-rules     "$HERE/hwcounters.sh" "$L" "$BIN" "$S/rules.body"     ab1 20000 5 "$OUT/w"
    run_locked hw-h2s1      "$HERE/hwcounters.sh" "$L" "$BIN" "$S/tls.body"       h2s1 10000 5 "$OUT/w"
    ;;
  tp)
    run_locked tp1  "$HERE/hwcounters.sh" "$L" "$BIN" "$S/keepalive.body" tp1 50000 5 "$OUT/w"
    run_locked tp50 "$HERE/hwcounters.sh" "$L" "$BIN" "$S/keepalive.body" tp50 200000 5 "$OUT/w"
    ;;
  *) sed -n 5,16p "$0"; exit 2;;
esac
