#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
#
# tools/gate.sh [--exclusive] [--log FILE] [--only ID[,ID..] | --rerun-failed] [--] [VAR=value ...]
#
# The one way to run the gate (./tools/checkin.sh). It takes the gate lock itself, and
# nothing it starts holds that lock (T253). --only and --rerun-failed go to checkin.sh
# (T267: rerun only the stages that failed on this tree); the lock and slot rules are the same.
#
# Why: the gate used to be run as `flock /tmp/alcyon-gate.lock ./tools/checkin.sh`. flock hands
# the locked fd to its command and to everything that command starts. On 2026-10-10 cargo
# started an sccache server during a gate; the daemon inherited the fd, outlived the gate,
# and 14 queued gates waited on a lock no gate held. Here the lock fds are closed in every
# child (`{fd}>&-`), so a daemon a build or test leaves behind cannot keep a slot.
#
# Slots: ALCYON_GATE_SLOTS (default 1) gates may run side by side. Slot K has its own lock
# and its own target directory:
#   slot 1:  /tmp/alcyon-gate.lock          (the historical lock, so old-style
#                                           `flock -o /tmp/alcyon-gate.lock ...` waiters and
#                                           this script exclude each other)
#   slot K:  /tmp/alcyon-gate.slot<K>.lock
#   target:  ~/ibex-targets/gate-slot<K>
# Inside the slot the worktree's *.rs and *.toml are touched, so the slot's target never
# trusts mtimes another worktree left in it -- unless the last gate in the slot was this
# worktree's and nothing has built in the target since (<target>/.gate-last-tree, written
# when a gate ends, older than every fingerprint): then cargo's mtimes are this worktree's
# own, and not touching keeps the suite's build fresh, which is what lets covercheck rerun
# alone on the suite's profiles (T267).
#
# T570: a slot's target must not grow with every gate. Every gate touches all sources, so
# incremental compilation only ever added a session (51 GB in one slot) and every worktree has
# its own hashed copies of the workspace crates (190 copies of each). The gate therefore builds
# with CARGO_INCREMENTAL=0, deletes the slot's */incremental, and, when it touched the sources
# for a full run (so every workspace crate is rebuilt), deletes *.profraw from before the run
# and, after that run passes, the workspace crates' debug artifacts (deps, .fingerprint, build)
# it did not rebuild. Third-party artifacts and release builds stay. Only the slot's target.
#
# --exclusive (the supervisor's measuring gate on main) takes every slot, in order, after
# announcing itself on /tmp/alcyon-gate.exclusive.lock so non-exclusive gates stop taking
# slots that free up meanwhile. Without --exclusive, ALCYON_GATE_SKIP_MEASURE=1 is forced.
#
# Refuses (exit 3) when the target filesystem has less than ALCYON_GATE_MIN_FREE_GB
# (default 40) free; it does not wait for disk.
#
# While waiting it prints, every ALCYON_GATE_REPORT_SECS (default 300), who holds each slot:
# PID, command, cwd and age, found by scanning /proc/*/fd read-only. A holder that is not
# a gate (no argument naming checkin.sh or gate.sh in itself or its ancestors) is flagged in capitals.
# It never kills or signals anything.
#
# Ends with `gate: rc=N slot=K`, and exits N.
#
# Overrides used by tools/test_gate.sh only (not for normal use):
#   ALCYON_GATE_LOCK_PREFIX  (default /tmp/alcyon-gate)  slot1 = <prefix>.lock, slotK = <prefix>.slot<K>.lock
#   ALCYON_GATE_TARGET_BASE  (default ~/ibex-targets)  slot K target = <base>/gate-slot<K>
#   ALCYON_GATE_CMD          a bash command run instead of ./tools/checkin.sh
#   ALCYON_GATE_POLL_SECS    (default 5) how often a waiting gate retries the slots
set -uo pipefail

usage() { sed -n '5,5p;7,10p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2; }

EXCLUSIVE=0
LOG=""
EXTRA_ENV=()
CHECKIN_ARGS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --exclusive) EXCLUSIVE=1 ;;
    --log) [ $# -ge 2 ] || usage; LOG=$2; shift ;;
    --only) [ $# -ge 2 ] || usage; CHECKIN_ARGS+=(--only "$2"); shift ;;
    --rerun-failed) CHECKIN_ARGS+=(--rerun-failed) ;;
    --) shift; break ;;
    -h|--help) usage ;;
    *=*) break ;;
    *) echo "gate: unknown argument: $1" >&2; usage ;;
  esac
  shift
done
for a in "$@"; do
  case "$a" in
    [A-Za-z_]*=*) EXTRA_ENV+=("$a") ;;
    *) echo "gate: extra arguments must be VAR=value, got: $a" >&2; exit 2 ;;
  esac
done

if [ -n "$LOG" ]; then
  exec >>"$LOG" 2>&1 || { echo "gate: cannot write $LOG" >&2; exit 2; }
fi

cd "$(dirname "$0")/.." || exit 2
REPO=$(pwd)

SLOTS=${ALCYON_GATE_SLOTS:-1}
case "$SLOTS" in ''|*[!0-9]*|0) echo "gate: ALCYON_GATE_SLOTS must be a positive integer" >&2; exit 2 ;; esac
PREFIX=${ALCYON_GATE_LOCK_PREFIX:-/tmp/alcyon-gate}
TARGET_BASE=${ALCYON_GATE_TARGET_BASE:-$HOME/ibex-targets}
MIN_FREE_GB=${ALCYON_GATE_MIN_FREE_GB:-40}
REPORT_SECS=${ALCYON_GATE_REPORT_SECS:-300}
POLL_SECS=${ALCYON_GATE_POLL_SECS:-5}
INTENT_LOCK=$PREFIX.exclusive.lock

slot_lock() { if [ "$1" -eq 1 ]; then echo "$PREFIX.lock"; else echo "$PREFIX.slot$1.lock"; fi; }
slot_target() { echo "$TARGET_BASE/gate-slot$1"; }
ts() { date '+%F %T'; }

# --- disk -----------------------------------------------------------------------------
mkdir -p "$TARGET_BASE" || { echo "gate: cannot create $TARGET_BASE" >&2; exit 2; }
FREE_GB=$(df -BG --output=avail "$TARGET_BASE" | tail -1 | tr -dc '0-9')
if [ "${FREE_GB:-0}" -lt "$MIN_FREE_GB" ]; then
  echo "gate: REFUSED: ${FREE_GB}G free on the filesystem of $TARGET_BASE, need ${MIN_FREE_GB}G (ALCYON_GATE_MIN_FREE_GB)."
  echo "gate: free disk first; this script does not wait for it."
  echo "gate: rc=3 slot=none"
  exit 3
fi

# --- who holds a lock (read-only /proc scan) ------------------------------------------
# A process holds the lock when one of its fds is the lock file and that fd's fdinfo shows
# a granted lock ("lock:" without "->"). Waiters have the file open too but no lock line.
is_gate_lineage() {
  local p=$1 n=0
  while [ "$p" -gt 1 ] && [ $n -lt 64 ]; do
    # One of its arguments is the gate script itself (not merely text that mentions it).
    tr '\0' '\n' < "/proc/$p/cmdline" 2>/dev/null | grep -qxE '(.*/)?(checkin|gate)\.sh' && return 0
    p=$(sed 's/.*) //' "/proc/$p/stat" 2>/dev/null | awk '{print $2}') || return 1
    [ -n "$p" ] || return 1
    n=$((n + 1))
  done
  return 1
}
report_holders() {
  local lock=$1 f p fd cmd cwd age found=0
  for f in $(find /proc/[0-9]*/fd -maxdepth 1 -lname "$lock" 2>/dev/null); do
    p=${f#/proc/}; p=${p%%/*}; fd=${f##*/}
    grep -qE '^lock:[[:space:]]+[0-9]+: FLOCK' "/proc/$p/fdinfo/$fd" 2>/dev/null || continue
    cmd=$(tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null | cut -c1-160)
    cwd=$(readlink "/proc/$p/cwd" 2>/dev/null || echo '?')
    age=$(ps -o etimes= -p "$p" 2>/dev/null | tr -d ' ')
    found=1
    if is_gate_lineage "$p"; then
      echo "gate:   held by pid $p (${age:-?}s): $cmd  [cwd $cwd]"
    else
      echo "gate:   HELD BY PID $p, WHICH IS NOT A GATE (A LEFTOVER DAEMON?) (${age:-?}s): $cmd  [cwd $cwd]"
    fi
  done
  [ $found -eq 1 ] || echo "gate:   no holder found (free, or held by a process this user cannot see)"
}
report_all() {
  local k
  echo "gate: $(ts) still waiting; slot holders:"
  for k in $(seq 1 "$SLOTS"); do
    echo "gate:  slot $k ($(slot_lock "$k")):"
    report_holders "$(slot_lock "$k")"
  done
}

# --- acquire --------------------------------------------------------------------------
declare -A FD=()
HELD=()
CLOSE=()   # redirections that close every lock fd in a child
INTENT_FD=""
T_WAIT=$SECONDS
NEXT_REPORT=$((SECONDS + REPORT_SECS))
maybe_report() {
  if [ "$SECONDS" -ge "$NEXT_REPORT" ]; then report_all; NEXT_REPORT=$((SECONDS + REPORT_SECS)); fi
}
# flock -n on an fd, polled, so the periodic report keeps printing while we wait.
wait_lock_fd() {
  local fd=$1
  until flock -n "$fd"; do maybe_report; sleep "$POLL_SECS"; done
}

echo "gate: $(ts) $REPO, ${SLOTS} slot(s)$([ $EXCLUSIVE = 1 ] && echo ', exclusive')"
if [ $EXCLUSIVE = 1 ]; then
  exec {INTENT_FD}>"$INTENT_LOCK" || exit 2
  wait_lock_fd "$INTENT_FD"
  for k in $(seq 1 "$SLOTS"); do
    exec {fd}>"$(slot_lock "$k")" || exit 2
    wait_lock_fd "$fd"
    FD[$k]=$fd; HELD+=("$k")
  done
else
  exec {INTENT_FD}>"$INTENT_LOCK" || exit 2
  got=""
  while [ -z "$got" ]; do
    # An exclusive gate is waiting for the slots: do not take one that frees up.
    if flock -n -s "$INTENT_FD"; then
      flock -u "$INTENT_FD"
      for k in $(seq 1 "$SLOTS"); do
        exec {fd}>"$(slot_lock "$k")" || exit 2
        if flock -n "$fd"; then got=$k; FD[$k]=$fd; HELD+=("$k"); break; fi
        exec {fd}>&-
      done
    fi
    [ -n "$got" ] && break
    maybe_report
    sleep "$POLL_SECS"
  done
  exec {INTENT_FD}>&-
  INTENT_FD=""
fi
for k in "${HELD[@]}"; do CLOSE+=("${FD[$k]}"); done
[ -n "$INTENT_FD" ] && CLOSE+=("$INTENT_FD")
SLOT=${HELD[0]}
SLOT_LABEL=$(IFS=,; echo "${HELD[*]}")
echo "gate: $(ts) slot ${SLOT_LABEL} acquired after $((SECONDS - T_WAIT))s"

# Run "$@" with every lock fd closed, so nothing it starts can hold a slot.
run_closed() {
  local redir="" fd
  for fd in "${CLOSE[@]}"; do redir+=" ${fd}>&-"; done
  eval "\"\$@\" $redir"
}

# --- run ------------------------------------------------------------------------------
export CARGO_TARGET_DIR ALCYON_GATE_SLOT CARGO_INCREMENTAL
CARGO_INCREMENTAL=0
CARGO_TARGET_DIR=$(slot_target "$SLOT")
# Per-slot ports for stages with fixed ones (diff-fuzz): two gates side by side collided on
# 18400 (2026-11-01, "Address already in use").
ALCYON_GATE_SLOT=$SLOT
mkdir -p "$CARGO_TARGET_DIR"
[ $EXCLUSIVE = 1 ] || export ALCYON_GATE_SKIP_MEASURE=1
echo "gate: CARGO_TARGET_DIR=$CARGO_TARGET_DIR ALCYON_GATE_SKIP_MEASURE=${ALCYON_GATE_SKIP_MEASURE:-} ${EXTRA_ENV[*]}"

# A measuring gate pauses the local-model queue (cores 32-47 and the GPU) at its next safe
# point and resumes it on exit; without the harness on this machine this does nothing.
# ALCYON_MUSE_PAUSE names the command, empty to skip.
MUSE_PAUSE=${ALCYON_MUSE_PAUSE-$HOME/ibex-worktrees/qwen/muse-pause}
if [ $EXCLUSIVE = 1 ] && [ -z "${ALCYON_GATE_SKIP_MEASURE:-}" ] && [ -n "$MUSE_PAUSE" ] && [ -x "$MUSE_PAUSE" ]; then
  if MUSE_ID=$("$MUSE_PAUSE" on --reason "gate measure $REPO" --max-minutes 120); then
    trap '"$MUSE_PAUSE" off --id "$MUSE_ID" >/dev/null' EXIT
    echo "gate: local-model queue paused ($MUSE_ID)"
  else
    echo "gate: WARNING: the local-model queue could not be paused; measurements may be noisy"
  fi
fi

# The slot's target is shared with other worktrees; make cargo rebuild from this one's
# sources, unless the last gate here was this worktree's and nothing has built since.
MARK=$CARGO_TARGET_DIR/.gate-last-tree
built_since() {
  local d
  for d in "$CARGO_TARGET_DIR"/*/.fingerprint "$CARGO_TARGET_DIR"/llvm-cov-target/*/.fingerprint; do
    [ -d "$d" ] || continue
    [ -z "$(find "$d" -newer "$MARK" -print -quit 2>/dev/null)" ] || return 0
  done
  return 1
}
if [ -f "$MARK" ] && [ "$(cat "$MARK")" = "$REPO" ] && ! built_since; then
  echo "gate: not touching sources: the last gate in this slot was this worktree's, and nothing has built here since"
else
  echo "gate: touching sources: this slot's target was last built from another worktree, or by an unfinished gate"
  git ls-files -z -- '*.rs' '*.toml' | run_closed xargs -0 touch
  TOUCHED=1
fi
rm -f "$MARK"   # an interrupted gate leaves no mark

# T570: no incremental sessions (the build is non-incremental now); profiles of an earlier
# run would count lines its tests ran, and only a full run on touched sources rebuilds and
# reruns everything (a covercheck-only rerun needs the suite's profiles).
rm -rf "$CARGO_TARGET_DIR/debug/incremental" "$CARGO_TARGET_DIR"/llvm-cov-target/*/incremental \
       "$CARGO_TARGET_DIR"/*/incremental
FULL=0
[ ${#CHECKIN_ARGS[@]} -eq 0 ] && [ "${TOUCHED:-0}" = 1 ] && FULL=1
RUN_REF=$CARGO_TARGET_DIR/.gate-run-start
: > "$RUN_REF"
if [ $FULL = 1 ]; then
  find "$CARGO_TARGET_DIR" -name '*.profraw' -delete 2>/dev/null
fi

# Deletes the workspace crates' debug artifacts older than the start of this run.
prune_stale() {
  local names rx d
  names=$(cargo metadata --no-deps --format-version 1 --offline 2>/dev/null | python3 -I -c '
import json, sys
m = json.load(sys.stdin)
n = {t["name"].replace("-", "_") for p in m["packages"] for t in p["targets"]}
n |= {p["name"].replace("-", "_") for p in m["packages"]}
n -= {"build_script_build", "build_script_main"}
print("|".join(sorted(n)))') || return 0
  [ -n "$names" ] || return 0
  rx="(lib)?($names)-[0-9a-f]{16}(\\..*)?"
  for d in "$CARGO_TARGET_DIR/debug" "$CARGO_TARGET_DIR/llvm-cov-target/debug"; do
    [ -d "$d" ] || continue
    find "$d/deps" "$d/.fingerprint" "$d/build" -mindepth 1 -maxdepth 1 ! -newer "$RUN_REF" \
      -regextype posix-extended -regex ".*/$(sed 's/_/[-_]/g' <<<"$rx")" \
      -exec rm -rf {} + 2>/dev/null
  done
}

if [ -n "${ALCYON_GATE_CMD:-}" ]; then
  run_closed env "${EXTRA_ENV[@]}" bash -c "$ALCYON_GATE_CMD" gate "${CHECKIN_ARGS[@]}"
else
  run_closed env "${EXTRA_ENV[@]}" ./tools/checkin.sh "${CHECKIN_ARGS[@]}"
fi
RC=$?
if [ $RC -eq 0 ] && [ $FULL = 1 ]; then
  n0=$(du -sk "$CARGO_TARGET_DIR" 2>/dev/null | cut -f1)
  prune_stale
  echo "gate: pruned stale workspace artifacts: $(( (n0 - $(du -sk "$CARGO_TARGET_DIR" 2>/dev/null | cut -f1)) / 1024 )) MB freed"
fi
rm -f "$RUN_REF"
echo "$REPO" > "$MARK"
echo "gate: $(ts) rc=$RC slot=$SLOT_LABEL"
exit $RC
