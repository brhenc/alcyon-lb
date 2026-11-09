#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
#
# Where a proxy's instructions go: perf record instructions:u over one measure-bench run
# (50 keep-alive connections), reported by symbol. Companion of insreq.sh (same pinning,
# same scenario bodies, same lock rule).
#
#   tools/measure/insprof.sh <label> <proxy-bin> <scenario.body> <N> <outdir> [fp]
#
# With "fp" the record takes frame-pointer call chains (build the binary with
# RUSTFLAGS="-C force-frame-pointers=yes"; a release build without them gives no callers)
# and runs perf under `sudo -n` (the kernel refuses call chains at perf_event_paranoid 2).
# Output: <outdir>/<label>.sym.txt (self cost by symbol, with callers when "fp") and
# <label>.dso.txt. Samples with a kernel address under instructions:u are the syscall
# boundary: count them as "syscalls", not as the proxy's own code. The period is 100000:
# 10000 was throttled by perf_event_max_sample_rate on this host and lost 60% of the samples.
set -u
if [ $# -lt 5 ]; then sed -n '5,20p' "$0"; exit 2; fi
LABEL=$1; BIN=$2; BODY=$3; N=$4; OUT=$5; CG=${6:-}
mkdir -p "$OUT" || exit 1
BENCH=${MEASURE_BENCH:-$HOME/ibex-targets/gate-slot1/release/measure-bench}
IFS=, read -r CPU_P CPU_C CPU_B <<< "${ALCYON_MEASURE_CPUS:-4,5,6}"
port() { python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])'; }
FE=$(port); BE=$(port)
CFG=$OUT/$LABEL.cfg
sed -e "s/@FE@/$FE/g; s/@BE@/$BE/g" "$BODY" > "$CFG" || exit 1
taskset -c "$CPU_B" "$BENCH" backend "$BE" >/dev/null 2>&1 & BEPID=$!
sleep 0.3
taskset -c "$CPU_P" "$BIN" -f "$CFG" > "$OUT/$LABEL.proxy.log" 2>&1 & P=$!
for _ in $(seq 1 50); do (exec 3<>/dev/tcp/127.0.0.1/"$FE") 2>/dev/null && break; sleep 0.1; done
taskset -c "$CPU_C" "$BENCH" fixed 127.0.0.1:"$FE" 50 2000 > /dev/null 2>&1
REC=(perf record -q -e instructions:u -c 100000 -p "$P" -o "$OUT/$LABEL.data")
if [ "$CG" = fp ]; then REC=(sudo -n perf record -q -e instructions:u --call-graph fp -c 100000 -p "$P" -o "$OUT/$LABEL.data"); fi
"${REC[@]}" -- taskset -c "$CPU_C" "$BENCH" fixed 127.0.0.1:"$FE" 50 "$N" > "$OUT/$LABEL.client" 2>&1
kill "$P"; wait "$P" 2>/dev/null; kill "$BEPID"; wait "$BEPID" 2>/dev/null
[ "$CG" = fp ] && sudo -n chown "$USER": "$OUT/$LABEL.data"
# The report is outside any lock the caller holds: with call chains it can take minutes.
perf report -i "$OUT/$LABEL.data" --no-children --sort symbol --stdio --percent-limit 0.05 2>/dev/null | grep -v '^#' | grep -v '^$' > "$OUT/$LABEL.sym.txt"
perf report -i "$OUT/$LABEL.data" --no-children --sort dso --stdio 2>/dev/null | grep -v '^#' | grep -v '^$' > "$OUT/$LABEL.dso.txt"
echo "$LABEL: $(perf report -i "$OUT/$LABEL.data" --stdio 2>/dev/null | grep -m1 'Event count') -> $OUT/$LABEL.sym.txt (proxy pid $P and backend pid $BEPID stopped)"
