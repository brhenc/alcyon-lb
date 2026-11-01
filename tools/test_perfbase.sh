#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
#
# Tests for tools/measure/perfbase.sh and tools/measure/slot.sh (T576), with stub build and
# measure commands, in a private /tmp/t576-test.XXXX directory (never the real locks or targets).
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2
PB=$(pwd)/tools/measure/perfbase.sh
SL=$(pwd)/tools/measure/slot.sh
W=$(mktemp -d /tmp/t576-test.XXXXXX)
trap 'for p in $(cat "$W"/*.pid 2>/dev/null); do kill "$p" 2>/dev/null; done; rm -rf "$W"' EXIT
PASS=0; FAIL=0
ok()  { echo "ok   $1"; PASS=$((PASS + 1)); }
bad() { echo "FAIL $1"; FAIL=$((FAIL + 1)); }
[ -x "$PB" ] && [ -x "$SL" ] || { echo "FAIL tools/measure/perfbase.sh or slot.sh missing"; exit 1; }

export IBEX_PERFBASE_DIR=$W/pb IBEX_PERFBASE_BOARDS=$W/boards IBEX_SLOT_LOCK_DIR=$W IBEX_SLOT_POLL_SECS=0.2
unset IBEX_MEASURE_SLOT_D
export IBEX_PERFBASE_BUILD_CMD="echo x >> $W/builds; sleep 1; mkdir -p \$CARGO_TARGET_DIR/release-perf; printf '#!/bin/sh\n' > \$CARGO_TARGET_DIR/release-perf/ibex; chmod +x \$CARGO_TARGET_DIR/release-perf/ibex"
export IBEX_PERFBASE_MEASURE_CMD='echo m >> '$W'/measures; printf "{\"sha\":\"%s\",\"rounds\":5,\"rows\":[{\"scenario\":\"s\",\"user\":1,\"kernel\":2,\"total\":3}]}" "$2" > "$3"'

# Real commits to archive: the current HEAD and its ancestors.
mapfile -t SHAS < <(git rev-list -n 8 HEAD)

"$PB" "${SHAS[0]}" > "$W/a.log" 2>&1 & p1=$!
"$PB" "${SHAS[0]}" > "$W/b.log" 2>&1 & p2=$!
wait $p1; r1=$?; wait $p2; r2=$?
[ "$r1" = 0 ] && [ "$r2" = 0 ] || { bad "concurrent calls failed: $r1 $r2"; cat "$W/a.log" "$W/b.log"; }
[ "$(wc -l < "$W/builds")" = 1 ] && ok "two concurrent calls build once" || bad "built $(wc -l < "$W/builds") times"
[ "$(wc -l < "$W/measures")" = 1 ] && ok "two concurrent calls measure once" || bad "measured $(wc -l < "$W/measures") times"
S=$(git rev-parse --short=12 "${SHAS[0]}")
[ -s "$W/boards/insreq-$S.json" ] && grep -q "release-perf/ibex" "$W/a.log" && ok "JSON written, binary path printed" || bad "no JSON or path"

t0=$(date +%s.%N)
"$PB" "${SHAS[0]}" > "$W/c.log" 2>&1
t1=$(date +%s.%N)
if [ "$(wc -l < "$W/builds")" = 1 ] && [ "$(wc -l < "$W/measures")" = 1 ] && awk -v a="$t0" -v b="$t1" 'BEGIN{exit !(b-a<0.5)}' \
   && grep -q "release-perf/ibex" "$W/c.log" && grep -q "ins/req" "$W/c.log"; then ok "second call reuses both, instantly, prints path and table"
else bad "second call rebuilt or was slow"; cat "$W/c.log"; fi

for i in 1 2 3 4 5 6 7; do IBEX_PERFBASE_BUILD_CMD="${IBEX_PERFBASE_BUILD_CMD}" "$PB" --no-measure "${SHAS[$i]}" >/dev/null 2>&1; sleep 0.05; done
n=$(ls -d "$W"/pb/*/ | wc -l)
[ "$n" = 5 ] && [ ! -d "$W/pb/$S" ] && ok "pruning keeps 5 builds, the oldest went" || { bad "kept $n builds"; ls "$W/pb"; }

# Slot helper: B, then C, then refuse; D only when enabled.
echo "$$" > /dev/null
slot() { "$SL" "$@" 2>/dev/null; }
r=$(slot -- bash -c 'echo $IBEX_MEASURE_SLOT $IBEX_MEASURE_CPUS')
[ "$r" = "B 12,13,14" ] && ok "free: slot B" || bad "first slot '$r'"
(exec 9>>"$W/ibex-load-n1.lock"; flock 9; sleep 30) & echo $! > "$W/hb.pid"
sleep 0.3
r=$(slot -- bash -c 'echo $IBEX_MEASURE_SLOT $IBEX_MEASURE_CPUS')
[ "$r" = "C 20,21,22" ] && ok "B held: slot C" || bad "second slot '$r'"
(exec 9>>"$W/ibex-load-n2.lock"; flock 9; sleep 30) & echo $! > "$W/hc.pid"
sleep 0.3
slot -- true; rc=$?
[ "$rc" = 75 ] && ok "B and C held: refused (75)" || bad "rc $rc with B and C held"
r=$(IBEX_MEASURE_SLOT_D=1 slot -- bash -c 'echo $IBEX_MEASURE_SLOT $IBEX_MEASURE_CPUS')
[ "$r" = "D 28,29,30" ] && ok "IBEX_MEASURE_SLOT_D=1: slot D" || bad "slot D '$r'"
kill "$(cat "$W/hb.pid")"; sleep 0.3
r=$(slot --wait -- bash -c 'echo $IBEX_MEASURE_SLOT')
[ "$r" = B ] && ok "--wait gets B once it is released" || bad "--wait '$r'"

echo "test_perfbase: $PASS passed, $FAIL failed"
[ $FAIL -eq 0 ]
