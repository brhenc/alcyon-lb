#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
# Alcyon Continuous Measurement Suite Runner
# Appends structured measurement results to data/measurements.jsonl and alerts on regressions.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# Ensure ~/.cargo/bin is in PATH for inferno/perf tools
export PATH="${HOME}/.cargo/bin:${PATH}"

# A coverage-instrumented build is ~2.5x slower: measuring it says nothing about Alcyon, and an
# A/B of two instrumented builds still "passes". The gate exports the instrumented env for
# its tests (T257); it must hand this script the plain one.
if [[ "${RUSTFLAGS:-}" == *instrument-coverage* || -n "${LLVM_PROFILE_FILE:-}" ]]; then
    echo "measure: refusing to measure a coverage-instrumented build (RUSTFLAGS='${RUSTFLAGS:-}', LLVM_PROFILE_FILE='${LLVM_PROFILE_FILE:-}')" >&2
    exit 2
fi

# Run Python measurement suite
exec python3 "${SCRIPT_DIR}/measure.py" "$@"
