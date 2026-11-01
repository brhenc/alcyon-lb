#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
#
# First free counts-only measure slot (instruction counts, never timing claims; slot A,
# /tmp/ibex-load.lock CPUs 4-6, stays the only slot for timing). Holds the slot's lock while
# the command runs and exports IBEX_MEASURE_CPUS (what insreq.sh reads) and IBEX_MEASURE_SLOT.
#
#   tools/measure/slot.sh [--wait] -- <cmd> [args...]
#
#   B  /tmp/ibex-load-n1.lock  CPUs 12,13,14  (node 1)
#   C  /tmp/ibex-load-n2.lock  CPUs 20,21,22  (node 2; load on 16-23)
#   D  /tmp/ibex-load-n3.lock  CPUs 28,29,30  (node 3, shared with another project; only
#                                              when IBEX_MEASURE_SLOT_D=1)
#
# Tries B, C, D in order without blocking. All held: exit 75 (EX_TEMPFAIL) and the command is not
# run; with --wait, retry every IBEX_SLOT_POLL_SECS (default 5) until one frees up.
# IBEX_SLOT_LOCK_DIR replaces /tmp for the lock files (tests).
set -u
WAIT=0
[ "${1:-}" = --wait ] && { WAIT=1; shift; }
[ "${1:-}" = -- ] && shift
[ $# -ge 1 ] || { sed -n '5,19p' "$0"; exit 2; }
D=${IBEX_SLOT_LOCK_DIR:-/tmp}
SLOTS="B:$D/ibex-load-n1.lock:12,13,14 C:$D/ibex-load-n2.lock:20,21,22"
[ "${IBEX_MEASURE_SLOT_D:-}" = 1 ] && SLOTS="$SLOTS D:$D/ibex-load-n3.lock:28,29,30"
while :; do
  for s in $SLOTS; do
    IFS=: read -r name lock cpus <<< "$s"
    exec 9>>"$lock" || continue
    if flock -n 9; then
      export IBEX_MEASURE_CPUS=$cpus IBEX_MEASURE_SLOT=$name
      echo "slot.sh: slot $name (CPUs $cpus)" >&2
      # The child inherits fd 9 and so the lock; it is released when the last holder exits.
      "$@"; exit $?
    fi
    exec 9>&-
  done
  if [ $WAIT = 0 ]; then echo "slot.sh: every counts slot is held" >&2; exit 75; fi
  sleep "${IBEX_SLOT_POLL_SECS:-5}"
done
