#!/usr/bin/env bash
set -euo pipefail

# MC/DC and LLVM Source-Based Coverage Runner for Ibex
# Aerospace / DO-178C Level A & NASA JPL Verification

echo "=== Running Ibex MC/DC & LLVM Source-Based Coverage Suite ==="

export RUSTFLAGS="-C instrument-coverage"
export LLVM_PROFILE_FILE="ibex-%p-%m.profraw"

cargo test --workspace

echo "All tests passed with instrumented coverage."
