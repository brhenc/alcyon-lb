#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
# Supervisor check-in: one command, everything needed to judge agy's progress.
#
#   tools/checkin.sh                   every stage
#   tools/checkin.sh --list            the stages, with their usual time
#   tools/checkin.sh --only ID[,ID..]  those stages (and what they need, below)
#   tools/checkin.sh --rerun-failed    the stages that failed or did not run in the gates
#                                      on this same tree; then the combined verdict
#   tools/checkin.sh --accept          rewrite the tripwire manifest (read what changed first)
#
# Rerunning a stage (T267). A gate is 6-15 minutes, and most failed gates failed one stage:
# a flaky test, two uncovered lines, load noise in the measurement. Each stage's result is
# kept per tree by harness/gatestate.py: the commit, a clean worktree (data/measurements.jsonl
# apart) and the env that changes a verdict (COVERCHECK, IBEX_GATE_SKIP_MEASURE, the
# covercheck base). A result from another tree is never reused, and a dirty tree keeps
# nothing. The verdict is every stage's last attempt on this tree -- PASS only when each one
# passed -- with every failed attempt before it listed: a stage that passed on a rerun is
# reported as such, not hidden.
#
# Dependencies between stages (the table; harness/gatestate.py DEPS enforces the first):
#   covercheck  <- suite   covercheck judges the profiles the suite's instrumented run left
#                          (T257). Alone, it reuses them only when the suite wrote them for
#                          this tree in this target (gate-tree.json beside suite-run.json);
#                          otherwise the suite runs with it.
#   smoke       <- ibex    `cargo build --bin ibex` first: builds it when the target does
#                          not hold one from this tree, a no-op when it does.
#   measure                builds and times its own plain release ibex, in the plain target
#                          and the plain env (tools/measure/run.sh refuses an instrumented one).
#   the rest               build what they test (cargo does), or need nothing.
#
# Uses its own target directory so it never contends with a build agy is running.
# Read-only with respect to the repository.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

STAGES=(tripwire harness-tests findings oracles suite covercheck smoke diff-fuzz haproxy lint measure surface stray)
declare -A TITLE=(
  [tripwire]="tripwire: the spec tests must not change"
  [harness-tests]="the harness's own tests"
  [findings]="the eight findings"
  [oracles]="the oracles that measure a port against the real thing"
  [suite]="every test in the workspace, against a declared baseline"
  [covercheck]="did a test execute what changed"
  [smoke]="the regressions no unit test can see"
  [diff-fuzz]="differential fuzz against HAProxy, end to end, vs the known-differences baseline"
  [haproxy]="does HAProxy still behave as the tests record"
  [lint]="does the rest still build and lint (clippy, and the libFuzzer targets compile: T279)"
  [measure]="continuous measurement"
  [surface]="new surface since the nudge, and whether it came with tests"
  [stray]="stray files (the supervisor's own are expected)"
)
usage() { sed -n '6,11p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2; }
MODE=all
ONLY=""
ACCEPT=0
while [ $# -gt 0 ]; do
  case "$1" in
    --list) MODE=list ;;
    --only) [ $# -ge 2 ] || usage; MODE=only; ONLY=$2; shift ;;
    --only=*) MODE=only; ONLY=${1#--only=} ;;
    --rerun-failed) MODE=rerun ;;
    --accept) ACCEPT=1 ;;
    -h|--help) usage ;;
    *) echo "checkin: unknown argument: $1" >&2; usage ;;
  esac
  shift
done
if [ "$MODE" = only ]; then
  for id in ${ONLY//,/ }; do
    [ -n "${TITLE[$id]:-}" ] || { echo "checkin: no stage '$id' (see tools/checkin.sh --list)" >&2; exit 2; }
  done
fi

# Each section header carries the time since the gate started, so a slow or stuck section
# can be told from a long one while it runs (T116), and how long that section took on the
# last few runs: past the "stuck after" mark, look at the processes rather than wait. The
# history is per machine, not per checkout, so a fresh worktree has it too.
GATE_T0=$SECONDS
GATE_HISTORY=${IBEX_GATE_HISTORY:-$HOME/.cache/ibex/checkin-sections.tsv}
mkdir -p "$(dirname "$GATE_HISTORY")" 2>/dev/null || true
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
if [ "$MODE" = list ]; then
  for id in "${STAGES[@]}"; do
    h=$(section_hint "${TITLE[$id]}")
    printf '%-14s %-60s %s\n' "$id" "${TITLE[$id]}" "${h:-usually under 10s}"
  done
  exit 0
fi

# In a linked worktree (an agent's), the default would be the same directory the main
# checkout's run uses. Two checkouts building into one target directory overwrite each
# other's test binaries, and each run then tests the other's code. Refuse instead.
if [ -z "${CARGO_TARGET_DIR:-}" ] && [ "$(git rev-parse --git-dir)" != "$(git rev-parse --git-common-dir)" ]; then
  echo "checkin: this is a linked worktree; set CARGO_TARGET_DIR to a directory of its own" >&2
  echo "         (for example CARGO_TARGET_DIR=/home/bhenc/ibex-targets/<task> ./tools/checkin.sh)" >&2
  exit 2
fi
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-/tmp/ibex-checkin-target}

# One build, one run of the tests (T257). Every section below builds and runs in the
# instrumented build `cargo llvm-cov` makes (<target>/llvm-cov-target): the suite section's
# run judges the tests and leaves the profiles covercheck reads. The gate used to build and
# run every test target twice, plain and then instrumented, ~4.5 minutes of a 15-minute gate
# and a second target directory. COVERCHECK=0 keeps the quick loop: plain build, no profiles.
# The measurement builds and times a plain release ibex: it keeps the target from before.
PLAIN_TARGET_DIR=$CARGO_TARGET_DIR
if [ "${COVERCHECK:-1}" = "1" ]; then
  if [ -n "${IBEX_CHECKIN_FAKE:-}" ]; then
    export IBEX_INSTRUMENTED=$CARGO_TARGET_DIR/llvm-cov-target CARGO_TARGET_DIR=$CARGO_TARGET_DIR/llvm-cov-target
  elif ! INSTRUMENTED_ENV=$(python3 harness/covercheck.py --print-env); then
    echo "checkin: cannot set up the instrumented build (cargo llvm-cov show-env); COVERCHECK=0 skips it" >&2
    exit 2
  else
    eval "$INSTRUMENTED_ENV"
  fi
fi
INSTR_DIR=${IBEX_INSTRUMENTED:-}
# The plain env, for the measurement: run.sh refuses an instrumented one.
run_plain() { env -u RUSTFLAGS -u LLVM_PROFILE_FILE -u IBEX_INSTRUMENTED CARGO_TARGET_DIR="$PLAIN_TARGET_DIR" "$@"; }

# --- which tree, which stages --------------------------------------------------------------
RUN_DIR=$(mktemp -d /tmp/ibex-checkin-run.XXXXXX)
FAIL_FILE=$RUN_DIR/failed
: > "$FAIL_FILE"
gs() { python3 harness/gatestate.py "$@"; }
if KEY=$(gs key); then
  echo "checkin: tree $KEY: $(git log -1 --format='%h %s' | cut -c1-70); results kept in ${IBEX_GATE_STATE:-~/.cache/ibex/gate-state}"
else
  echo "checkin: not kept, nothing reusable: $KEY"
  KEY=dirty
  export IBEX_GATE_STATE=$RUN_DIR/state
fi
STAGE_LIST=$(IFS=,; echo "${STAGES[*]}")
case "$MODE" in
  all) SELECTED=("${STAGES[@]}") ;;
  only) read -ra SELECTED <<<"${ONLY//,/ }" ;;
  rerun)
    if [ "$KEY" = dirty ]; then
      echo "checkin: --rerun-failed on a tree with no key: running every stage"
      SELECTED=("${STAGES[@]}")
    else
      read -ra SELECTED <<<"$(gs plan --key "$KEY" --stages "$STAGE_LIST")"
      echo "checkin: --rerun-failed: ${SELECTED[*]:-nothing: every stage has passed on this tree}"
    fi ;;
esac
if [ "${COVERCHECK:-1}" = 1 ] && [ ${#SELECTED[@]} -gt 0 ]; then
  read -ra SELECTED <<<"$(gs deps --key "$([ "$KEY" = dirty ] && echo - || echo "$KEY")" \
      --stages "$STAGE_LIST" --select "$(IFS=,; echo "${SELECTED[*]}")" --tdir "$INSTR_DIR")"
fi
[ "$MODE" = all ] || echo "checkin: running: ${SELECTED[*]:-nothing}"

# Every step below pipes into grep, and a pipeline's exit status is the last command's.
# `pipefail` does not help when nothing checks the result: this script had no exit-code
# handling at all, so it returned 0 whatever happened. It printed
# "Verdict: FAIL (1 regression detected!)" and exited 0 in the same run that found a
# 20% throughput drop. AGENTS.md calls this script "the project's definition of still
# standing", and agents are asked to paste its output -- but anyone checking $? instead
# of reading two hundred lines got a green that meant nothing. Collect the failures and
# exit on them. (A stage runs in a subshell, so its failures go through $FAIL_FILE.)
note_fail() { echo "$1" >> "$FAIL_FILE"; echo "!! FAILED: $1"; }
check() { [ "$1" -eq 0 ] || note_fail "$2"; }
note_skip() { echo "$1" > "$RUN_DIR/skipped"; }

# tcp_request_rules.rs, tcp_request_tracking.rs and stick_table.rs were unprotected on
# 2026-10-02 by the user (no agent owns them any more) so their racy port helpers could be
# replaced; the eight findings below still run them.
SPEC_TESTS=(
  crates/ibex-sample/tests/sample_semantics.rs
)

stage_tripwire() {
  # nudge-agy.md says to fix the code, not the assertions. A change here means either
  # that instruction was ignored or a supervisor weakened a test to go green.
  #
  # Hashes, not `git diff`: three of these files are untracked, and `git diff -- <path>`
  # reports nothing for an untracked path no matter what is in it. The first version of
  # this script used git diff and printed "clean" while being structurally incapable of
  # detecting a change. Refresh the manifest deliberately, with --accept, only after
  # reading what changed.
  local MANIFEST=tools/checkin.sha256
  if [ ! -f "$MANIFEST" ] || [ "$ACCEPT" = 1 ]; then
    sha256sum "${SPEC_TESTS[@]}" > "$MANIFEST"
    echo "manifest written: $MANIFEST"
  elif sha256sum --quiet -c "$MANIFEST" 2>/dev/null; then
    echo "clean (hashes match $MANIFEST)"
  else
    echo "!! SPEC TESTS CHANGED -- read this before trusting anything below:"
    sha256sum -c "$MANIFEST" 2>&1 | grep -v ': OK$'
    note_fail "tripwire: spec tests modified"
  fi
  # AGENTS.md section 8: no new hand-written per-thread cache (allowlist shrinks S1-S4).
  python3 harness/pool_layout.py
  check "$?" "pool_layout (no hand-written thread_local cache)"
}

stage_harness-tests() {
  # The gate's verdicts come from harness/*.py; their tests ran only when someone remembered
  # (T254 found test_covercheck.py half-skipped). A few seconds.
  python3 -m unittest discover -s harness -p 'test_*.py' 2>&1 | grep -E "^(Ran |OK|FAILED|FAIL:|ERROR:)"
  check "${PIPESTATUS[0]}" "harness tests"
  (cd tools/measure && python3 -m unittest test_measure 2>&1 | grep -E "^(Ran |OK|FAILED|FAIL:|ERROR:)"; exit "${PIPESTATUS[0]}")
  check "$?" "measure.py tests"
  # The findings ledger (T292): a malformed data/findings.csv or verification_runs.csv fails the
  # gate; an open finding does not.
  python3 tools/findings.py --check
  check "$?" "findings ledger parses"
}

stage_findings() {
  cargo test -p ibex-sample --test sample_semantics 2>&1 | grep -E "^test |test result"
  check "${PIPESTATUS[0]}" "sample_semantics"
  cargo test -p ibex-rt --test it tcp_request_rules:: 2>&1 | grep -E "^test |test result"
  check "${PIPESTATUS[0]}" "tcp_request_rules"
  cargo test -p ibex-rt --test it tcp_request_tracking:: 2>&1 | grep -E "^test |test result"
  check "${PIPESTATUS[0]}" "tcp_request_tracking"
}

stage_oracles() {
  # A crate whose correctness is defined by a reference must be checked against it here,
  # not only in its own task. crates/slz was landed reporting SUCCESS while its only test
  # panicked on `serde_json::from_str` before comparing a single vector -- the struct named
  # `_in_len` where data/slz_vectors.json has `in_len`. It had never been run against the
  # oracle it exists for. A test nobody runs is a test nobody has.
  cargo test -p slz --test it -- --nocapture 2>&1 | grep -E "EXACT MATCHES|ROUND TRIPS|test result"
  check "${PIPESTATUS[0]}" "slz oracle"
}

stage_suite() {
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
}

stage_covercheck() {
  # The recurring defect is one thing wearing several hats: the test does not execute the code
  # the feature lives in. T48's test called lb::balance_uri directly and never entered the
  # engine, so `balance uri` sent every request to one server while its test passed, through
  # two reviewers and a green check-in. T40's module was never called. T26 never measured Ibex.
  # T51's first attempt changed nothing and reported SUCCESS.
  #
  # All four are the same mechanical question. The suite section ran every test in the
  # instrumented build; this merges those profiles and judges the diff (T257). Set COVERCHECK=0
  # to skip it on a quick loop.
  if [ "${COVERCHECK:-1}" = "1" ]; then
    python3 harness/covercheck.py 2>&1 | grep -vE "^$"
    check "${PIPESTATUS[0]}" "covercheck"
  else
    echo "covercheck: skipped (COVERCHECK=0)"
    note_skip "COVERCHECK=0"
  fi
}

stage_smoke() {
  # A daemon that will not start is invisible to `cargo test`. Making the `global` section
  # strict about unknown keywords took the reg-test board from 7 passing to 1 -- `thread-groups`
  # appears in nearly every HAProxy reg-test -- and it survived two hours because every unit
  # test stayed green. This runs in about two seconds.
  #
  # In the instrumented build this is the ibex the suite already built (T257), not a second
  # plain build (~20 s and a second target directory): its verdicts
  # match the plain one's (192/529 configs, 6/6 tests on 2026-10-10; 4.6 s against 3.2 s).
  # Its profiles go to a directory of their own, removed after: the
  # smoke run is not a test, and what it executes must not count as tested.
  # Run alone (--only smoke), this build is what makes the ibex it needs.
  cargo build -q --bin ibex 2>/dev/null
  local SMOKE_PROFILES
  SMOKE_PROFILES=$(mktemp -d /tmp/ibex-smoke-profiles.XXXXXX)
  LLVM_PROFILE_FILE="$SMOKE_PROFILES/smoke-%4m.profraw" python3 harness/smoke.py 2>&1 | grep -vE "^$"
  check "${PIPESTATUS[0]}" "smoke"
  rm -rf "$SMOKE_PROFILES"
}

stage_diff-fuzz() {
  # T293: the request-line / bare-LF / chunk-extension classes T291 tracks showed up only
  # when the repaired differential harness ran real ibex against real HAProxy. This keeps it
  # running: a time-boxed (30 s budget, plus the baseline's replay) run of fuzz/difffuzz.py.
  # It fails on a DIFF not in fuzz/known_diffs.json, on a known input whose DIFF shape
  # changed, and on a known input that became SAME (T291 fixing it: remove the printed hash).
  # Takes its own ports (18400-18423). Usually ~40 s; stuck after 3 min (the budget and the
  # replay are bounded, the section hint above learns the real numbers from the history).
  # Run alone (--only diff-fuzz), this builds the ibex and the generator it needs.
  # Instrumented-build profiles of the ibex it runs go to a directory of their own, removed
  # after, like smoke's.
  cargo build -q --bin ibex 2>/dev/null
  cargo build -q --manifest-path fuzz/Cargo.toml --bin ibex-fuzz 2>/dev/null
  local PROF
  PROF=$(mktemp -d /tmp/ibex-difffuzz-profiles.XXXXXX)
  LLVM_PROFILE_FILE="$PROF/difffuzz-%4m.profraw" python3 fuzz/difffuzz.py gate 2>&1 | grep -vE "^$"
  check "${PIPESTATUS[0]}" "diff-fuzz"
  rm -rf "$PROF"
}

stage_haproxy() {
  # http_txn.rs is measured against HAProxy; run against it here, a case that starts failing
  # means HAProxy changed (T89: Content-Length beside chunked is the case the user asked to
  # watch). Expected HAProxy failures: data/txn_oracle_baseline.json.
  python3 harness/txn_oracle.py 2>&1 | grep -vE "^$"
  check "${PIPESTATUS[0]}" "txn oracle"
}

stage_lint() {
  cargo clippy -q --workspace --all-targets 2>&1 | grep -E "^(warning|error)" | grep -v generated | sort | uniq -c
  local CLIPPY_RC=${PIPESTATUS[0]}
  echo "clippy exit: $CLIPPY_RC"
  check "$CLIPPY_RC" "clippy"
  # T279: fuzz/libfuzzer is its own crate outside the workspace, so clippy above never
  # compiles its targets; T273A removed a function a target called and nothing noticed for
  # hours. A plain stable `cargo check` of the bins (no sanitizer, no nightly) catches it.
  # Warnings are not judged here, only errors. fuzz/ (the differential harness against
  # HAProxy) is its own crate too and rotted the same way (HtxSlice change), so it is
  # checked as well; its target dir is the shared one, so it costs a few seconds.
  cargo check -q --manifest-path fuzz/libfuzzer/Cargo.toml --bins > /tmp/ibex-fuzz-check.$$ 2>&1
  local FUZZ_RC=$?
  cargo check -q --manifest-path fuzz/Cargo.toml --bins >> /tmp/ibex-fuzz-check.$$ 2>&1
  [ $? -ne 0 ] && FUZZ_RC=1
  grep -E "^error" /tmp/ibex-fuzz-check.$$ | head -20
  rm -f /tmp/ibex-fuzz-check.$$
  echo "fuzz/libfuzzer + fuzz/ check exit: $FUZZ_RC"
  check "$FUZZ_RC" "fuzz targets compile"
}

stage_measure() {
  # IBEX_GATE_SKIP_MEASURE=1 is for agents working in a worktree. With a dozen of them on
  # one machine the throughput samples are noise (T99's gate failed on -10% at load 24 with
  # no hot-path change, then passed unchanged), and each re-run costs the agent a whole gate.
  # The supervisor runs the full gate, measurement included, on main before a merge counts.
  # A measurement that failed on load noise alone: --only measure (in the plain env too).
  if [ "${IBEX_GATE_SKIP_MEASURE:-}" = 1 ]; then
    echo "skipped (IBEX_GATE_SKIP_MEASURE=1): measured on main at merge, not here"
    note_skip "IBEX_GATE_SKIP_MEASURE=1"
  else
    run_plain tools/measure/run.sh --fast
    check "$?" "continuous measurement"
  fi
}

stage_surface() {
  echo "-- uncommitted:"
  git diff --stat | tail -1
  echo "src lines changed:  $(git diff --numstat -- '*/src/*.rs'   | awk '{s+=$1} END {print s+0}')"
  echo "test lines changed: $(git diff --numstat -- '*/tests/*.rs' | awk '{s+=$1} END {print s+0}')"
  echo "-- commits since the nudge was written:"
  git log --oneline --since="2026-09-22" | head -20
}

stage_stray() {
  git status --short | grep '^??' \
    | grep -vE 'tests/(sample_semantics|tcp_request_rules|tcp_request_tracking)\.rs|nudge-agy\.md|tools/checkin\.sh' \
    || echo "none"
}

# harness/test_gatestate.py runs this script with every stage replaced by
# $IBEX_CHECKIN_FAKE/<id> (missing: the stage passes); not for normal use.
fake_stage() {
  local f=$IBEX_CHECKIN_FAKE/$1
  echo "$1" >> "$IBEX_CHECKIN_FAKE/ran"
  [ -f "$f" ] || return 0
  if [ "$1" = measure ]; then run_plain bash "$f"; else bash "$f"; fi
  check "$?" "$1"
}

# --- run -------------------------------------------------------------------------------
hint=$(section_hint "(whole gate)")
[ "$MODE" != all ] || [ -z "$hint" ] || echo "checkin: the whole gate: $hint"
RAN=()
for id in "${SELECTED[@]}"; do
  now=$((SECONDS - GATE_T0))
  hint=$(section_hint "${TITLE[$id]}")
  echo
  echo "=== ${TITLE[$id]} [$id] === [+${now}s]${hint:+  ($hint)}"
  n0=$(wc -l < "$FAIL_FILE")
  rm -f "$RUN_DIR/skipped"
  t0=$SECONDS
  if [ -n "${IBEX_CHECKIN_FAKE:-}" ]; then
    (fake_stage "$id") 2>&1 | tee "$RUN_DIR/$id.log"
  else
    ("stage_$id") 2>&1 | tee "$RUN_DIR/$id.log"
  fi
  secs=$((SECONDS - t0))
  RAN+=("$id")
  mapfile -t fails < <(tail -n +$((n0 + 1)) "$FAIL_FILE")
  if [ ${#fails[@]} -gt 0 ]; then status=fail
  elif [ -s "$RUN_DIR/skipped" ]; then status=skip
  else status=pass; fi
  # A skipped stage's 0 s would drag its "usually" hint down.
  [ "$status" = skip ] || printf '%s\t%s\n' "${TITLE[$id]}" "$secs" >> "$GATE_HISTORY" 2>/dev/null || true
  # A tree that changed while the stage ran is not the tree the result belongs to.
  if [ "$KEY" != dirty ] && [ "$(gs key)" != "$KEY" ]; then
    echo "checkin: the tree changed during the gate: from here on nothing is kept"
    KEY=dirty
    export IBEX_GATE_STATE=$RUN_DIR/state
  fi
  gs record --key "$KEY" --stage "$id" --status "$status" --secs "$secs" \
    --log "$RUN_DIR/$id.log" "${fails[@]/#/--fail=}"
  if [ "$id" = suite ] && [ "$KEY" != dirty ] && [ -n "$INSTR_DIR" ]; then
    gs mark-profiles --key "$KEY" --tdir "$INSTR_DIR"
  fi
  [ "$id" != measure ] || [ "$status" != skip ] || SKIPPED_MEASURE=1
done

echo
echo "=== verdict === [+$((SECONDS - GATE_T0))s]"
# A gate without its measurement is shorter; its time would drag the "usually" hint down.
if [ "$MODE" = all ] && [ -z "${SKIPPED_MEASURE:-}" ]; then
  printf '%s\t%s\n' "(whole gate)" $((SECONDS - GATE_T0)) >> "$GATE_HISTORY" 2>/dev/null || true
fi
[ -z "${SKIPPED_MEASURE:-}" ] || echo "checkin: measurement skipped: not final until the gate on main has measured"
[ "$KEY" != dirty ] || echo "checkin: this tree's results are not kept (logs in $RUN_DIR)"
echo "stages on this tree (each one's last attempt; earlier failed attempts after it):"
gs verdict --key "$KEY" --stages "$STAGE_LIST" --ran "$(IFS=,; echo "${RAN[*]}")"
