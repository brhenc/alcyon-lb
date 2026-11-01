#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
#
# One release-perf build and one insreq measurement of a main commit, shared by every agent.
#
#   tools/measure/perfbase.sh [--no-measure] <main-sha>
#
# Builds `--profile release-perf --bin ibex` of <main-sha> once into
# ~/ibex-targets/perfbase/<sha>/ (from a `git archive` under perfbase/src-<sha>, not the caller's
# tree), under flock -x perfbase/<sha>.lock so concurrent callers wait for the one build and reuse
# it. Then (unless --no-measure) runs insreq.sh ab1 keepalive, ab1 rules and h2s1 (min of 5; user
# and kernel) on the first free counts slot (tools/measure/slot.sh) and writes
# ~/ibex-worktrees/boards/insreq-<sha>.json. Prints the binary path and the table. A second call
# for the same sha prints both at once. Keeps the 5 newest shas' builds, deletes older ones
# (only under perfbase/). Counts only, never a timing claim.
#
# Env: IBEX_PERFBASE_DIR (~/ibex-targets/perfbase), IBEX_PERFBASE_BOARDS (~/ibex-worktrees/boards),
# IBEX_PERFBASE_KEEP (5), IBEX_PERFBASE_BUILD_CMD (run in the source dir with CARGO_TARGET_DIR set;
# default cargo build --profile release-perf --bin ibex --offline), IBEX_PERFBASE_MEASURE_CMD
# (stub: called as `cmd <bin> <sha> <json-out>`), IBEX_PERFBASE_N (requests per round, 20000).
set -u
NOM=0
[ "${1:-}" = --no-measure ] && { NOM=1; shift; }
[ $# -eq 1 ] || { sed -n '5,17p' "$0"; exit 2; }
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
SHA=$(git -C "$REPO" rev-parse --verify --short=12 "$1^{commit}") || { echo "perfbase: no such commit $1" >&2; exit 2; }
BASE=${IBEX_PERFBASE_DIR:-$HOME/ibex-targets/perfbase}
BOARDS=${IBEX_PERFBASE_BOARDS:-$HOME/ibex-worktrees/boards}
mkdir -p "$BASE" "$BOARDS" || exit 1
T=$BASE/$SHA
BIN=$T/release-perf/ibex
JSON=$BOARDS/insreq-$SHA.json

(
  flock -x 8
  if [ ! -x "$BIN" ]; then
    SRC=$BASE/src-$SHA
    rm -rf "$SRC"; mkdir -p "$SRC" || exit 1
    git -C "$REPO" archive "$SHA" | tar -x -C "$SRC" || exit 1
    echo "perfbase: building $SHA" >&2
    if [ -n "${IBEX_PERFBASE_BUILD_CMD:-}" ]; then
      (cd "$SRC" && CARGO_TARGET_DIR=$T bash -c "$IBEX_PERFBASE_BUILD_CMD") || { rm -rf "$SRC"; exit 1; }
    else
      (cd "$SRC" && CARGO_TARGET_DIR=$T cargo build --profile release-perf --bin ibex --offline) || { rm -rf "$SRC"; exit 1; }
    fi
    rm -rf "$SRC"
    [ -x "$BIN" ] || { echo "perfbase: build left no $BIN" >&2; exit 1; }
    # Prune: keep the newest IBEX_PERFBASE_KEEP build dirs (by mtime), only under $BASE.
    n=0
    for d in $(ls -1dt "$BASE"/*/ 2>/dev/null); do
      d=${d%/}
      [ -d "$d/release-perf" ] || continue
      n=$((n + 1))
      if [ $n -gt "${IBEX_PERFBASE_KEEP:-5}" ]; then rm -rf "$d" "$d.lock"; fi
    done
  fi
) 8>>"$BASE/$SHA.lock" || exit 1
echo "perfbase: binary $BIN"
[ $NOM = 1 ] && exit 0

(
  flock -x 8
  if [ ! -s "$JSON" ]; then
    if [ -n "${IBEX_PERFBASE_MEASURE_CMD:-}" ]; then
      "$HERE/slot.sh" --wait -- bash -c "$IBEX_PERFBASE_MEASURE_CMD" _ "$BIN" "$SHA" "$JSON.tmp" || exit 1
    else
      "$HERE/slot.sh" --wait -- bash "$HERE/perfbase_measure.sh" "$BIN" "$SHA" "$JSON.tmp" || exit 1
    fi
    mv "$JSON.tmp" "$JSON"
  fi
) 8>>"$BASE/$SHA.measure.lock" || exit 1
echo "perfbase: $JSON"
python3 - "$JSON" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
print(f"{'scenario':<16}{'user':>10}{'kernel':>10}{'total':>10}  ins/req (min total of {d.get('rounds','?')})")
for r in d["rows"]:
    print(f"{r['scenario']:<16}{r['user']:>10}{r['kernel']:>10}{r['total']:>10}")
PY
