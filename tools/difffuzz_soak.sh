#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
#
# tools/difffuzz_soak.sh [MINUTES]    (default 60)
#
# Long differential-fuzz run (T293): the generator in rounds against a release ibex and the
# reference HAProxy, end to end (fuzz/difffuzz.py soak). Runs under the shared load lock
# (a red-team measurement holds it exclusive and we wait) at nice 19 on cores 48-55.
# New DIFFs (not in fuzz/known_diffs.json, or a known input whose shape changed) go to
#   ~/ibex-worktrees/review/difffuzz/<date>-<sha>.md      (outside the repository)
# One summary line goes to stdout. Exit 0: nothing new; 1: new DIFFs; 2: could not run.
#
# Env: IBEX_BIN (default: a release build of this checkout in $DIFFFUZZ_TARGET),
#      DIFFFUZZ_TARGET (default ~/ibex-targets/difffuzz), DIFFFUZZ_SEED (default: day number,
#      so each night explores other seeds), DIFFFUZZ_OUT (report dir), DIFFFUZZ_CORES (48-55).
# The row for data/verification_runs.csv (T292's ledger), appended when that file exists:
#   date,kind,subject,sha,cases,new_diffs,minutes,report
#   e.g. 2026-10-12,difffuzz,ibex-vs-haproxy,ed6dfb8,41230,0,60,
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2
MIN=${1:-60}
case "$MIN" in ''|*[!0-9.]*) echo "usage: $0 [MINUTES]" >&2; exit 2 ;; esac
T=${DIFFFUZZ_TARGET:-$HOME/ibex-targets/difffuzz}
OUTDIR=${DIFFFUZZ_OUT:-$HOME/ibex-worktrees/review/difffuzz}
CORES=${DIFFFUZZ_CORES:-48-55}
SEED=${DIFFFUZZ_SEED:-$(( $(date +%s) / 86400 * 1000 ))}
SHA=$(git rev-parse --short HEAD)
free_gb=$(df -BG --output=avail "$HOME" | tail -1 | tr -dc '0-9')
[ "$free_gb" -ge 40 ] || { echo "difffuzz-soak: only ${free_gb}G free on /home" >&2; exit 2; }
export CARGO_TARGET_DIR=$T CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=4
if [ -z "${IBEX_BIN:-}" ]; then
  nice -n 19 cargo build -q --release -p ibex-rt --bin ibex 2>&1 | grep -E '^error' && exit 2
  IBEX_BIN=$T/release/ibex
fi
nice -n 19 cargo build -q --release --manifest-path fuzz/Cargo.toml 2>&1 | grep -E '^error' && exit 2
mkdir -p "$OUTDIR"
OUT=$OUTDIR/$(date +%F)-$SHA.md
exec 9>>/tmp/ibex-load.lock
# -o: the lock is not inherited by the children, only this script holds it while it waits
RES=$(mktemp /tmp/difffuzz-soak.XXXXXX)
flock -o -s 9 nice -n 19 taskset -c "$CORES" python3 fuzz/difffuzz.py soak \
  --ibex "$IBEX_BIN" --gen "$T/release/ibex-fuzz" --minutes "$MIN" --seed "$SEED" --iters 500 \
  --workers 6 --base-port 18500 --out "$OUT" > "$RES" 2>&1
RC=$?
LINE=$(tail -n 1 "$RES"); rm -f "$RES"
echo "$LINE"
CASES=$(sed -n 's/^difffuzz-soak: \([0-9]*\) cases.*/\1/p' <<<"$LINE")
NEW=$(sed -n 's/.* \([0-9]*\) new DIFFs.*/\1/p' <<<"$LINE")
if [ -f data/verification_runs.csv ]; then
  echo "$(date +%F),difffuzz,ibex-vs-haproxy,$SHA,${CASES:-0},${NEW:-0},$MIN,$([ "${NEW:-0}" != 0 ] && echo "$OUT")" >> data/verification_runs.csv
fi
exit "$RC"
