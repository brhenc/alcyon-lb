#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
# Ibex Continuous Measurement Suite Runner
# Appends structured measurement results to data/measurements.jsonl and alerts on regressions.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# Ensure ~/.cargo/bin is in PATH for inferno/perf tools
export PATH="${HOME}/.cargo/bin:${PATH}"

# Run Python measurement suite
exec python3 "${SCRIPT_DIR}/measure.py" "$@"
