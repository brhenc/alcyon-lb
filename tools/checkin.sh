#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
# Supervisor check-in: one command, everything needed to judge agy's progress.
#
# Uses its own target directory so it never contends with a build agy is running.
# Read-only with respect to the repository.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

# In a linked worktree (an agent's), the default would be the same directory the main
# checkout's run uses. Two checkouts building into one target directory overwrite each
# other's test binaries, and each run then tests the other's code. Refuse instead.
if [ -z "${CARGO_TARGET_DIR:-}" ] && [ "$(git rev-parse --git-dir)" != "$(git rev-parse --git-common-dir)" ]; then
  echo "checkin: this is a linked worktree; set CARGO_TARGET_DIR to a directory of its own" >&2
  echo "         (for example CARGO_TARGET_DIR=/home/bhenc/ibex-targets/<task> ./tools/checkin.sh)" >&2
  exit 2
fi
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-/tmp/ibex-checkin-target}

# Every step below pipes into grep, and a pipeline's exit status is the last command's.
# `pipefail` does not help when nothing checks the result: this script had no exit-code
# handling at all, so it returned 0 whatever happened. It printed
# "Verdict: FAIL (1 regression detected!)" and exited 0 in the same run that found a
# 20% throughput drop. AGENTS.md calls this script "the project's definition of still
# standing", and agents are asked to paste its output -- but anyone checking $? instead
# of reading two hundred lines got a green that meant nothing. Collect the failures and
# exit on them.
FAILED=()
note_fail() { FAILED+=("$1"); echo "!! FAILED: $1"; }
# Each section header carries the time since the gate started, so a slow or stuck section
# can be told from a long one while it runs (T116), and how long that section took on the
# last few runs: past the "stuck after" mark, look at the processes rather than wait. The
# history is per machine, not per checkout, so a fresh worktree has it too.
GATE_T0=$SECONDS
GATE_HISTORY=${IBEX_GATE_HISTORY:-$HOME/.cache/ibex/checkin-sections.tsv}
mkdir -p "$(dirname "$GATE_HISTORY")" 2>/dev/null || true
SECTION_NAME=""
SECTION_T0=0
section() {
  local now=$((SECONDS - GATE_T0)) hint=""
  if [ -n "$SECTION_NAME" ]; then
    printf '%s\t%s\n' "$SECTION_NAME" $((now - SECTION_T0)) >> "$GATE_HISTORY" 2>/dev/null || true
  fi
  SECTION_NAME=$1
  SECTION_T0=$now
  hint=$(section_hint "$1")
  echo "=== $1 === [+${now}s]${hint:+  ($hint)}"
}
# From the section's last seven runs: the median, and "stuck" at twice the longest (at
# least a minute). Sections that never take ten seconds get no hint.
section_hint() {
  [ -r "$GATE_HISTORY" ] || return 0
  awk -F'\t' -v n="$1" '$1 == n { print $2 }' "$GATE_HISTORY" | tail -n 7 | sort -n \
    | awk '{ v[NR] = $1 } END {
        if (NR == 0 || v[NR] < 10) exit
        stuck = 2 * v[NR]; if (stuck < 60) stuck = 60
        printf "usually ~%ds; stuck after %dm%02ds", v[int((NR + 1) / 2)], stuck / 60, stuck % 60
      }'
}
check() { [ "$1" -eq 0 ] || note_fail "$2"; }

# tcp_request_rules.rs, tcp_request_tracking.rs and stick_table.rs were unprotected on
# 2026-10-02 by the user (no agent owns them any more) so their racy port helpers could be
# replaced; the eight findings below still run them.
SPEC_TESTS=(
  crates/ibex-sample/tests/sample_semantics.rs
)

hint=$(section_hint "(whole gate)")
[ -z "$hint" ] || echo "checkin: the whole gate: $hint"
section "tripwire: the spec tests must not change"
# nudge-agy.md says to fix the code, not the assertions. A change here means either
# that instruction was ignored or a supervisor weakened a test to go green.
#
# Hashes, not `git diff`: three of these files are untracked, and `git diff -- <path>`
# reports nothing for an untracked path no matter what is in it. The first version of
# this script used git diff and printed "clean" while being structurally incapable of
# detecting a change. Refresh the manifest deliberately, with --accept, only after
# reading what changed.
MANIFEST=tools/checkin.sha256
if [ ! -f "$MANIFEST" ] || [ "${1:-}" = "--accept" ]; then
  sha256sum "${SPEC_TESTS[@]}" > "$MANIFEST"
  echo "manifest written: $MANIFEST"
elif sha256sum --quiet -c "$MANIFEST" 2>/dev/null; then
  echo "clean (hashes match $MANIFEST)"
else
  echo "!! SPEC TESTS CHANGED -- read this before trusting anything below:"
  sha256sum -c "$MANIFEST" 2>&1 | grep -v ': OK$'
  note_fail "tripwire: spec tests modified"
fi

echo
section "the eight findings"
cargo test -p ibex-sample --test sample_semantics 2>&1 | grep -E "^test |test result"
check "${PIPESTATUS[0]}" "sample_semantics"
cargo test -p ibex-rt --test tcp_request_rules 2>&1 | grep -E "^test |test result"
check "${PIPESTATUS[0]}" "tcp_request_rules"
cargo test -p ibex-rt --test tcp_request_tracking 2>&1 | grep -E "^test |test result"
check "${PIPESTATUS[0]}" "tcp_request_tracking"

echo
section "the oracles that measure a port against the real thing"
# A crate whose correctness is defined by a reference must be checked against it here,
# not only in its own task. crates/slz was landed reporting SUCCESS while its only test
# panicked on `serde_json::from_str` before comparing a single vector -- the struct named
# `_in_len` where data/slz_vectors.json has `in_len`. It had never been run against the
# oracle it exists for. A test nobody runs is a test nobody has.
cargo test -p slz --test test_slz -- --nocapture 2>&1 | grep -E "EXACT MATCHES|ROUND TRIPS|test result"
check "${PIPESTATUS[0]}" "slz oracle"

echo
section "every test in the workspace, against a declared baseline"
# The three sections above name four test targets by hand. The workspace has 77, so 73 of
# them -- including every file a task had added -- never ran here. That is how T48 shipped
# crates/ibex-rt/tests/load_balancing.rs with a red assertion and a SUCCESS report, past two
# reviewers and a green check-in: nothing ran the file, so nothing could go red. A test that
# exists and is never run is worse than no test, because it is counted as coverage.
#
# Failing targets are re-run alone before they count: tcp_proxy passes 17/17 by itself and
# fails in the parallel run on port contention, and fc_src_is_the_real_peer_after_set_src
# does the same. Known failures live in data/suite_baseline.json with a reason each.
python3 harness/suite.py 2>&1 | grep -vE "^$"
check "${PIPESTATUS[0]}" "workspace suite"

echo
section "did a test execute what changed"
# The recurring defect is one thing wearing several hats: the test does not execute the code
# the feature lives in. T48's test called lb::balance_uri directly and never entered the
# engine, so `balance uri` sent every request to one server while its test passed, through
# two reviewers and a green check-in. T40's module was never called. T26 never measured Ibex.
# T51's first attempt changed nothing and reported SUCCESS.
#
# All four are the same mechanical question. Costs several minutes because it builds the
# workspace instrumented and runs every test; set COVERCHECK=0 to skip it on a quick loop.
if [ "${COVERCHECK:-1}" = "1" ]; then
  python3 harness/covercheck.py 2>&1 | grep -vE "^$"
  check "${PIPESTATUS[0]}" "covercheck"
else
  echo "covercheck: skipped (COVERCHECK=0)"
fi

echo
section "the regressions no unit test can see"
# A daemon that will not start is invisible to `cargo test`. Making the `global` section
# strict about unknown keywords took the reg-test board from 7 passing to 1 -- `thread-groups`
# appears in nearly every HAProxy reg-test -- and it survived two hours because every unit
# test stayed green. This runs in about two seconds.
cargo build -q --bin ibex 2>/dev/null
python3 harness/smoke.py 2>&1 | grep -vE "^$"
check "${PIPESTATUS[0]}" "smoke"

echo
section "does HAProxy still behave as the tests record"
# http_txn.rs is measured against HAProxy; run against it here, a case that starts failing
# means HAProxy changed (T89: Content-Length beside chunked is the case the user asked to
# watch). Expected HAProxy failures: data/txn_oracle_baseline.json.
python3 harness/txn_oracle.py 2>&1 | grep -vE "^$"
check "${PIPESTATUS[0]}" "txn oracle"

echo
section "does the rest still build and lint"
cargo clippy -q --workspace --all-targets 2>&1 | grep -E "^(warning|error)" | grep -v generated | sort | uniq -c
CLIPPY_RC=${PIPESTATUS[0]}
echo "clippy exit: $CLIPPY_RC"
check "$CLIPPY_RC" "clippy"

echo
section "continuous measurement"
# IBEX_GATE_SKIP_MEASURE=1 is for agents working in a worktree. With a dozen of them on
# one machine the throughput samples are noise (T99's gate failed on -10% at load 24 with
# no hot-path change, then passed unchanged), and each re-run costs the agent a whole gate.
# The supervisor runs the full gate, measurement included, on main before a merge counts.
if [ "${IBEX_GATE_SKIP_MEASURE:-}" = 1 ]; then
  echo "skipped (IBEX_GATE_SKIP_MEASURE=1): measured on main at merge, not here"
  SKIPPED_MEASURE=1
else
  tools/measure/run.sh --fast
  check "$?" "continuous measurement"
fi

echo
section "new surface since the nudge, and whether it came with tests"
echo "-- uncommitted:"
git diff --stat | tail -1
echo "src lines changed:  $(git diff --numstat -- '*/src/*.rs'   | awk '{s+=$1} END {print s+0}')"
echo "test lines changed: $(git diff --numstat -- '*/tests/*.rs' | awk '{s+=$1} END {print s+0}')"
echo "-- commits since the nudge was written:"
git log --oneline --since="2026-09-22" | head -20

echo
section "stray files (the supervisor's own are expected)"
git status --short | grep '^??' \
  | grep -vE 'tests/(sample_semantics|tcp_request_rules|tcp_request_tracking)\.rs|nudge-agy\.md|tools/checkin\.sh' \
  || echo "none"

echo
section "verdict"
# A gate without its measurement is shorter; its time would drag the "usually" hint down.
[ -n "${SKIPPED_MEASURE:-}" ] || printf '%s\t%s\n' "(whole gate)" $((SECONDS - GATE_T0)) >> "$GATE_HISTORY" 2>/dev/null || true
if [ ${#FAILED[@]} -eq 0 ]; then
  echo "checkin: PASS${SKIPPED_MEASURE:+ (measurement skipped: not final until the gate on main has measured)}"
  exit 0
fi
echo "checkin: FAIL (${#FAILED[@]})"
for f in "${FAILED[@]}"; do echo "  - $f"; done
exit 1
