#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
#
# Tests for tools/gate.sh (T253). Runs fake gates (ALCYON_GATE_CMD) on locks and targets
# under a private /tmp/t253-test.XXXX directory; never touches /tmp/ibex-gate*.lock.
#
#   tools/test_gate.sh            test tools/gate.sh
#   T253_LEGACY=1 tools/test_gate.sh disowned
#                                 run the disowned-child case against the old form,
#                                 `flock <lock> <cmd>`, which it must fail
#
# Cases: disowned, overlap, serial, exclusive, disk, report, env, rc, args, touch, prune (default: all).
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2
GATE=$(pwd)/tools/gate.sh
W=$(mktemp -d /tmp/t253-test.XXXXXX)
STRAY=()   # PIDs of background processes this test started; killed by PID at the end
cleanup() {
  local p
  for p in "${STRAY[@]}"; do kill "$p" 2>/dev/null; done
  for p in $(cat "$W"/*.pid 2>/dev/null); do kill "$p" 2>/dev/null; done
  rm -rf "$W"
}
trap cleanup EXIT

export ALCYON_GATE_LOCK_PREFIX=$W/gate
export ALCYON_GATE_TARGET_BASE=$W/targets
export ALCYON_GATE_MIN_FREE_GB=0
export ALCYON_GATE_POLL_SECS=0.2
unset ALCYON_GATE_SKIP_MEASURE CARGO_TARGET_DIR

PASS=0; FAIL=0
ok()   { echo "ok   $1"; PASS=$((PASS + 1)); }
bad()  { echo "FAIL $1"; FAIL=$((FAIL + 1)); }
now()  { date +%s.%N; }

# A fake gate: records its start and end time in $W/<name>.{start,end}.
fake() { echo "now(){ date +%s.%N; }; now > $W/$1.start; sleep $2; now > $W/$1.end; ${3:-true}"; }
# Start a gate in the background, output to $W/<name>.log.
bg_gate() {
  local name=$1; shift
  "$@" > "$W/$name.log" 2>&1 &
  echo $! > "$W/$name.gatepid"
}
wait_gate() { wait "$(cat "$W/$1.gatepid")"; }
before() { awk -v a="$(cat "$1")" -v b="$(cat "$2")" 'BEGIN { exit !(a <= b) }'; }

t_disowned() {
  # The gate's command leaves a daemon behind. The next gate must not wait for it.
  local cmd="sleep 30 </dev/null >/dev/null 2>&1 & echo \$! > $W/daemon.pid; disown; exit 0"
  local t0 rc
  if [ "${T253_LEGACY:-}" = 1 ]; then
    flock "$ALCYON_GATE_LOCK_PREFIX.lock" bash -c "$cmd"
    t0=$SECONDS
    timeout 5 flock "$ALCYON_GATE_LOCK_PREFIX.lock" true; rc=$?
  else
    ALCYON_GATE_SLOTS=1 ALCYON_GATE_CMD="$cmd" "$GATE" > "$W/d1.log" 2>&1
    t0=$SECONDS
    ALCYON_GATE_SLOTS=1 ALCYON_GATE_CMD=true timeout 5 "$GATE" > "$W/d2.log" 2>&1; rc=$?
  fi
  if [ $rc -eq 0 ] && kill -0 "$(cat "$W/daemon.pid")" 2>/dev/null; then
    ok "disowned: next gate ran in $((SECONDS - t0))s while the daemon (pid $(cat "$W/daemon.pid")) still lives"
  else
    bad "disowned: next gate blocked (rc=$rc) by a daemon the previous gate left behind"
  fi
  kill "$(cat "$W/daemon.pid")" 2>/dev/null
}

t_overlap() {
  export ALCYON_GATE_SLOTS=2
  bg_gate o1 env ALCYON_GATE_CMD="$(fake o1 2)" "$GATE"
  sleep 0.5
  bg_gate o2 env ALCYON_GATE_CMD="$(fake o2 2)" "$GATE"
  wait_gate o1; wait_gate o2
  unset ALCYON_GATE_SLOTS
  if before "$W/o2.start" "$W/o1.end" && grep -q 'slot=1$' "$W/o1.log" && grep -q 'slot=2$' "$W/o2.log"; then
    ok "overlap: two gates ran side by side on slots 1 and 2"
  else
    bad "overlap: gates did not overlap on two slots"; cat "$W/o1.log" "$W/o2.log"
  fi
}

t_serial() {
  export ALCYON_GATE_SLOTS=1
  bg_gate s1 env ALCYON_GATE_CMD="$(fake s1 1.5)" "$GATE"
  sleep 0.5
  bg_gate s2 env ALCYON_GATE_CMD="$(fake s2 0.1)" "$GATE"
  wait_gate s1; wait_gate s2
  unset ALCYON_GATE_SLOTS
  if before "$W/s1.end" "$W/s2.start"; then ok "serial: with one slot the second gate waited"
  else bad "serial: second gate started before the first ended"; fi
}

t_exclusive() {
  export ALCYON_GATE_SLOTS=2
  bg_gate x1 env ALCYON_GATE_CMD="$(fake x1 2)" "$GATE"
  sleep 0.3
  bg_gate x2 env ALCYON_GATE_CMD="$(fake x2 3)" "$GATE"
  sleep 0.3
  bg_gate xe env ALCYON_GATE_CMD="$(fake xe 0.5)" "$GATE" --exclusive
  sleep 0.3
  # Arrives while the exclusive gate waits: must not take slot 1 when x1 frees it.
  bg_gate x3 env ALCYON_GATE_CMD="$(fake x3 0.1)" "$GATE"
  wait_gate x1; wait_gate x2; wait_gate xe; wait_gate x3
  unset ALCYON_GATE_SLOTS
  if before "$W/x1.end" "$W/xe.start" && before "$W/x2.end" "$W/xe.start" \
     && before "$W/xe.end" "$W/x3.start" && grep -q 'slot=1,2$' "$W/xe.log"; then
    ok "exclusive: waited for both slots, held both, and a later gate did not jump ahead"
  else
    bad "exclusive: ordering wrong"; tail -n 3 "$W"/x?.log
  fi
}

t_disk() {
  local rc
  ALCYON_GATE_MIN_FREE_GB=999999999 ALCYON_GATE_CMD="touch $W/ran" "$GATE" > "$W/disk.log" 2>&1; rc=$?
  if [ $rc -eq 3 ] && [ ! -e "$W/ran" ] && grep -q 'REFUSED' "$W/disk.log"; then
    ok "disk: refused at once (rc=3) and ran nothing"
  else bad "disk: rc=$rc"; cat "$W/disk.log"; fi
}

t_report() {
  # Slot 1 held the old way by a process that is not a gate; the waiting gate names it.
  flock "$ALCYON_GATE_LOCK_PREFIX.lock" sleep 30 </dev/null >/dev/null 2>&1 &
  local holder=$! child
  STRAY+=("$holder")
  sleep 0.3
  child=$(ps -o pid= --ppid "$holder" | tr -d ' ')
  STRAY+=($child)
  ALCYON_GATE_SLOTS=1 ALCYON_GATE_REPORT_SECS=1 ALCYON_GATE_CMD=true timeout 3 "$GATE" > "$W/rep.log" 2>&1
  kill "$holder" $child 2>/dev/null; wait "$holder" 2>/dev/null
  if grep -q "HELD BY PID $holder, WHICH IS NOT A GATE" "$W/rep.log"; then
    ok "report: a non-gate holder is named in capitals with its PID"
  else bad "report: holder $holder not reported"; cat "$W/rep.log"; fi
  # A gate holding the slot is reported as a gate, in lower case.
  bg_gate r1 env ALCYON_GATE_SLOTS=1 ALCYON_GATE_CMD="sleep 2.5" "$GATE"
  sleep 0.3
  ALCYON_GATE_SLOTS=1 ALCYON_GATE_REPORT_SECS=1 ALCYON_GATE_CMD=true "$GATE" > "$W/rep2.log" 2>&1
  wait_gate r1
  if grep -q "held by pid $(cat "$W/r1.gatepid") " "$W/rep2.log" && ! grep -q 'NOT A GATE' "$W/rep2.log"; then
    ok "report: a gate holding the slot is reported as a gate"
  else bad "report: gate holder misreported"; cat "$W/rep2.log"; fi
}

t_env() {
  local o
  o=$(ALCYON_GATE_SLOTS=1 ALCYON_GATE_CMD='echo "M=$ALCYON_GATE_SKIP_MEASURE T=$CARGO_TARGET_DIR X=$FOO"' \
      "$GATE" FOO=bar 2>&1)
  if grep -q "^M=1 T=$W/targets/gate-slot1 X=bar$" <<<"$o"; then ok "env: skip-measure forced, slot target, extra env passed"
  else bad "env"; echo "$o"; fi
  o=$(ALCYON_GATE_SLOTS=1 ALCYON_GATE_CMD='echo "M=${ALCYON_GATE_SKIP_MEASURE:-unset}"' "$GATE" --exclusive 2>&1)
  if grep -q "^M=unset$" <<<"$o"; then ok "env: --exclusive does not force skip-measure"
  else bad "env exclusive"; echo "$o"; fi
}

t_rc() {
  local o rc
  o=$(ALCYON_GATE_CMD='exit 7' "$GATE" 2>&1); rc=$?
  if [ $rc -eq 7 ] && grep -q 'rc=7 slot=1$' <<<"$o"; then ok "rc: the command's exit status is printed and returned"
  else bad "rc: got $rc"; echo "$o"; fi
}

t_args() {
  # --only / --rerun-failed reach checkin.sh (T267); the lock and slot rules are unchanged.
  local o
  o=$(ALCYON_GATE_SLOTS=1 ALCYON_GATE_CMD='echo "A=$* M=$ALCYON_GATE_SKIP_MEASURE"' "$GATE" --rerun-failed 2>&1)
  if grep -q "^A=--rerun-failed M=1$" <<<"$o"; then ok "args: --rerun-failed passed through"
  else bad "args: --rerun-failed"; echo "$o"; fi
  o=$(ALCYON_GATE_SLOTS=1 ALCYON_GATE_CMD='echo "A=$*"' "$GATE" --only suite,covercheck -- FOO=1 2>&1)
  if grep -q "^A=--only suite,covercheck$" <<<"$o"; then ok "args: --only passed through"
  else bad "args: --only"; echo "$o"; fi
}

t_touch() {
  # The slot's target is touched unless the last gate in it was this worktree's and
  # nothing has built in it since: a rerun of covercheck alone must find the suite's build
  # fresh, or covercheck rebuilds and reruns every test.
  local o t=$W/targets/gate-slot1
  rm -rf "$t"
  o=$(ALCYON_GATE_SLOTS=1 ALCYON_GATE_CMD=true "$GATE" 2>&1)
  if grep -q "gate: touching" <<<"$o"; then ok "touch: a target this worktree has not built is touched"
  else bad "touch: first"; echo "$o"; fi
  o=$(ALCYON_GATE_SLOTS=1 ALCYON_GATE_CMD=true "$GATE" 2>&1)
  if grep -q "gate: not touching" <<<"$o"; then ok "touch: the same worktree again is not touched"
  else bad "touch: second"; echo "$o"; fi
  sleep 1.1
  mkdir -p "$t/llvm-cov-target/debug/.fingerprint/other-1234" && : > "$t/llvm-cov-target/debug/.fingerprint/other-1234/x"
  o=$(ALCYON_GATE_SLOTS=1 ALCYON_GATE_CMD=true "$GATE" 2>&1)
  if grep -q "gate: touching" <<<"$o"; then ok "touch: a build since (another gate) makes it touch"
  else bad "touch: after another build"; echo "$o"; fi
  echo other > "$t/.gate-last-tree"
  o=$(ALCYON_GATE_SLOTS=1 ALCYON_GATE_CMD=true "$GATE" 2>&1)
  if grep -q "gate: touching" <<<"$o"; then ok "touch: another worktree's marker makes it touch"
  else bad "touch: other marker"; echo "$o"; fi
}

t_prune() {
  # T570: a slot's target must not grow with every gate. The gate builds non-incrementally,
  # removes the slot's incremental sessions once, deletes old profiles before a full run, and
  # after a successful full gate that rebuilt the workspace deletes the workspace crates'
  # debug artifacts it did not rebuild. Third-party artifacts and release builds stay.
  local t=$W/targets/gate-slot1 o d old
  rm -rf "$t"
  for d in debug llvm-cov-target/debug; do
    mkdir -p "$t/$d/incremental/alcyon_proto-1abc" "$t/$d/deps" "$t/$d/.fingerprint/alcyon-proto-0123456789abcdef" \
             "$t/$d/build/alcyon-proto-0123456789abcdef"
    : > "$t/$d/incremental/alcyon_proto-1abc/s"
    : > "$t/$d/deps/libalcyon_proto-0123456789abcdef.rlib"
    : > "$t/$d/deps/libalcyon_proto-fedcba9876543210.rlib"
    : > "$t/$d/deps/libserde-0123456789abcdef.rlib"
    : > "$t/$d/deps/it-0123456789abcdef"
  done
  mkdir -p "$t/release/deps"; : > "$t/release/deps/libalcyon_proto-0123456789abcdef.rlib"
  : > "$t/llvm-cov-target/old-1.profraw"; : > "$t/llvm-cov-target/doctest-profiles-x.profraw"
  # Everything above is old; the fake gate "rebuilds" one proto rlib and the it binary.
  find "$t" -exec touch -d '2020-01-01' {} +
  local cmd='for d in debug llvm-cov-target/debug; do : > $CARGO_TARGET_DIR/$d/deps/libalcyon_proto-fedcba9876543210.rlib; : > $CARGO_TARGET_DIR/$d/deps/it-0123456789abcdef; done; echo "INC=$CARGO_INCREMENTAL"; : > $CARGO_TARGET_DIR/llvm-cov-target/new.profraw'
  o=$(ALCYON_GATE_SLOTS=1 ALCYON_GATE_CMD="$cmd" "$GATE" 2>&1)
  if grep -q '^INC=0$' <<<"$o"; then ok "prune: the gate builds with CARGO_INCREMENTAL=0"
  else bad "prune: CARGO_INCREMENTAL"; echo "$o"; fi
  if [ ! -e "$t/debug/incremental" ] && [ ! -e "$t/llvm-cov-target/debug/incremental" ]; then
    ok "prune: incremental sessions removed"
  else bad "prune: incremental dirs survive"; fi
  if [ ! -e "$t/llvm-cov-target/old-1.profraw" ] && [ ! -e "$t/llvm-cov-target/doctest-profiles-x.profraw" ] \
     && [ -e "$t/llvm-cov-target/new.profraw" ]; then ok "prune: old profiles deleted before the run, the run's kept"
  else bad "prune: profraw"; ls "$t/llvm-cov-target"; fi
  old=0
  for d in debug llvm-cov-target/debug; do
    [ -e "$t/$d/deps/libalcyon_proto-0123456789abcdef.rlib" ] && old=1
    [ -e "$t/$d/.fingerprint/alcyon-proto-0123456789abcdef" ] && old=1
    [ -e "$t/$d/build/alcyon-proto-0123456789abcdef" ] && old=1
    [ -e "$t/$d/deps/libalcyon_proto-fedcba9876543210.rlib" ] || old=1
    [ -e "$t/$d/deps/it-0123456789abcdef" ] || old=1
    [ -e "$t/$d/deps/libserde-0123456789abcdef.rlib" ] || old=1
  done
  if [ $old -eq 0 ] && [ -e "$t/release/deps/libalcyon_proto-0123456789abcdef.rlib" ]; then
    ok "prune: stale workspace artifacts gone; fresh, third-party and release ones kept"
  else bad "prune: artifacts"; find "$t" -type f | sort; fi
  # A failed gate, and a partial one (--only), prune nothing.
  : > "$t/debug/deps/libalcyon_proto-aaaaaaaaaaaaaaaa.rlib"; touch -d 2020-01-01 "$t/debug/deps/libalcyon_proto-aaaaaaaaaaaaaaaa.rlib"
  ALCYON_GATE_SLOTS=1 ALCYON_GATE_CMD='exit 1' "$GATE" >/dev/null 2>&1
  ALCYON_GATE_SLOTS=1 ALCYON_GATE_CMD=true "$GATE" --only suite >/dev/null 2>&1
  if [ -e "$t/debug/deps/libalcyon_proto-aaaaaaaaaaaaaaaa.rlib" ]; then ok "prune: a failed or partial gate prunes nothing"
  else bad "prune: pruned after a failed/partial gate"; fi
}

CASES=${*:-disowned overlap serial exclusive disk report env rc args touch prune}
for c in $CASES; do "t_$c"; done
echo "test_gate: $PASS passed, $FAIL failed"
[ $FAIL -eq 0 ]
