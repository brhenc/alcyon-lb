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
echo "=== the oracles that measure a port against the real thing ==="
# A crate whose correctness is defined by a reference must be checked against it here,
# not only in its own task. crates/slz was landed reporting SUCCESS while its only test
# panicked on `serde_json::from_str` before comparing a single vector -- the struct named
# `_in_len` where data/slz_vectors.json has `in_len`. It had never been run against the
# oracle it exists for. A test nobody runs is a test nobody has.
cargo test -p slz --test test_slz -- --nocapture 2>&1 | grep -E "EXACT MATCHES|ROUND TRIPS|test result"

echo
echo "=== every test in the workspace, against a declared baseline ==="
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

echo
echo "=== the regressions no unit test can see ==="
# A daemon that will not start is invisible to `cargo test`. Making the `global` section
# strict about unknown keywords took the reg-test board from 7 passing to 1 -- `thread-groups`
# appears in nearly every HAProxy reg-test -- and it survived two hours because every unit
# test stayed green. This runs in about two seconds.
cargo build -q --bin ibex 2>/dev/null
python3 harness/smoke.py 2>&1 | grep -vE "^$"

echo
echo "=== does the rest still build and lint ==="
cargo clippy -q --workspace --all-targets 2>&1 | grep -E "^(warning|error)" | grep -v generated | sort | uniq -c
echo "clippy exit: ${PIPESTATUS[0]}"

echo
echo "=== continuous measurement ==="
tools/measure/run.sh --fast

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
