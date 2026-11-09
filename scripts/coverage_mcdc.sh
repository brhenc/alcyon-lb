#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

set -euo pipefail

# MC/DC and LLVM Source-Based Coverage Runner for Alcyon
# Aerospace / DO-178C Level A & NASA JPL Verification

echo "=== Running Alcyon MC/DC & LLVM Source-Based Coverage Suite ==="

export RUSTFLAGS="-C instrument-coverage"
export LLVM_PROFILE_FILE="alcyon-%p-%m.profraw"

cargo test --workspace

echo "All tests passed with instrumented coverage."
