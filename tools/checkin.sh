#!/usr/bin/env bash
# Supervisor check-in: one command, everything needed to judge agy's progress.
#
# Uses its own target directory so it never contends with a build agy is running.
# Read-only with respect to the repository.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-/tmp/ibex-checkin-target}

SPEC_TESTS=(
  crates/ibex-sample/tests/sample_semantics.rs
  crates/ibex-rt/tests/tcp_request_rules.rs
  crates/ibex-rt/tests/tcp_request_tracking.rs
  crates/ibex-rt/tests/stick_table.rs
)

echo "=== tripwire: the spec tests must not change ==="
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
fi

echo
echo "=== the eight findings ==="
cargo test -p ibex-sample --test sample_semantics 2>&1 | grep -E "^test |test result"
cargo test -p ibex-rt --test tcp_request_rules 2>&1 | grep -E "^test |test result"
cargo test -p ibex-rt --test tcp_request_tracking 2>&1 | grep -E "^test |test result"

echo
echo "=== does the rest still build and lint ==="
cargo clippy -q --workspace --all-targets 2>&1 | grep -E "^(warning|error)" | grep -v generated | sort | uniq -c
echo "clippy exit: ${PIPESTATUS[0]}"

echo
echo "=== new surface since the nudge, and whether it came with tests ==="
echo "-- uncommitted:"
git diff --stat | tail -1
echo "src lines changed:  $(git diff --numstat -- '*/src/*.rs'   | awk '{s+=$1} END {print s+0}')"
echo "test lines changed: $(git diff --numstat -- '*/tests/*.rs' | awk '{s+=$1} END {print s+0}')"
echo "-- commits since the nudge was written:"
git log --oneline --since="2026-09-22" | head -20

echo
echo "=== stray files (the supervisor's own are expected) ==="
git status --short | grep '^??' \
  | grep -vE 'tests/(sample_semantics|tcp_request_rules|tcp_request_tracking)\.rs|nudge-agy\.md|tools/checkin\.sh' \
  || echo "none"
