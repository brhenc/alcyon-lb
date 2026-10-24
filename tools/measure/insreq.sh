#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
#
# Instructions per request (perf stat instructions:u) of one proxy binary on one scenario.
# Works for ibex and for haproxy, so the oracle can be measured with the same backend and client.
#
#   tools/measure/insreq.sh <label> <proxy-bin> <scenario.body> <client: mb50|ab1> <N> <rounds> <outdir>
#
#   client mb50: measure-bench, 50 keep-alive connections, N requests (what the gate uses)
#   client ab1:  ab -k -c 1, N requests (one connection, the T447 figure)
#
# The scenario body is a config with @FE@ and @BE@ for the two ports (tools/measure/scenarios/).
# Pins the proxy to CPU 4, the client to 5, the backend to 6 (as measure.py); IBEX_MEASURE_CPUS
# "a,b,c" overrides. Warms up with 2000 requests, then counts the proxy process's user-space
# instructions over each round and prints instructions per request. Takes no lock: hold
# `flock -x /tmp/ibex-load.lock` around a batch, and keep a batch under 15 minutes. Needs
# $HOME/ibex-targets/gate-slot1/release/measure-bench (MEASURE_BENCH overrides).
set -u
if [ $# -ne 7 ]; then sed -n '5,20p' "$0"; exit 2; fi
LABEL=$1; BIN=$2; BODY=$3; CL=$4; N=$5; ROUNDS=$6; OUT=$7
mkdir -p "$OUT" || exit 1
BENCH=${MEASURE_BENCH:-$HOME/ibex-targets/gate-slot1/release/measure-bench}
IFS=, read -r CPU_P CPU_C CPU_B <<< "${IBEX_MEASURE_CPUS:-4,5,6}"
port() { python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])'; }
FE=$(port); BE=$(port)
CFG=$OUT/$LABEL.cfg
sed -e "s/@FE@/$FE/g; s/@BE@/$BE/g" "$BODY" > "$CFG" || exit 1
taskset -c "$CPU_B" "$BENCH" backend "$BE" >/dev/null 2>&1 & BEPID=$!
sleep 0.3
taskset -c "$CPU_P" "$BIN" -f "$CFG" > "$OUT/$LABEL.proxy.log" 2>&1 & P=$!
for _ in $(seq 1 50); do (exec 3<>/dev/tcp/127.0.0.1/"$FE") 2>/dev/null && break; sleep 0.1; done
client() {
  case $CL in
    mb50) taskset -c "$CPU_C" "$BENCH" fixed 127.0.0.1:"$FE" 50 "$1" ;;
    ab1)  taskset -c "$CPU_C" ab -k -q -c 1 -n "$1" "http://127.0.0.1:$FE/" ;;
    *) echo "unknown client $CL" >&2; return 1 ;;
  esac
}
client 2000 > "$OUT/$LABEL.warm.out" 2>&1
for r in $(seq 1 "$ROUNDS"); do
  perf stat -x, -e instructions:u -p "$P" -o "$OUT/$LABEL.r$r.stat" -- \
    bash -c "$(declare -f client); BENCH=$BENCH CL=$CL FE=$FE CPU_C=$CPU_C; client $N" > "$OUT/$LABEL.r$r.client" 2>&1
  INS=$(grep instructions "$OUT/$LABEL.r$r.stat" | cut -d, -f1)
  echo "$LABEL round $r: $INS instructions, $((INS / N)) ins/req"
done
kill "$P"; wait "$P" 2>/dev/null; kill "$BEPID"; wait "$BEPID" 2>/dev/null
echo "$LABEL done (proxy pid $P and backend pid $BEPID stopped)"
