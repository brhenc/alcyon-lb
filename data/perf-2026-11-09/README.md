<!--
SPDX-License-Identifier: GPL-2.0-or-later
Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
-->
# Raw output behind performance.md (2026-11-09)

- `matrix/`: `tools/measure/variants-matrix.sh` for each build (`<label>.<run>.out`), and `run.log`
  with the load average and governor at the start and end of every run. Labels as in
  performance.md: `alcyon-rp`, `alcyon-pgo`, `hap-<variant>` (3.5-dev8), `hapq-<variant>` (3.5-dev10).
- `default-builds/`: `tools/measure/insreq.sh` for `alcyon-rp` (`a-*`) and the reference HAProxy
  `-O2` binary (`h-*`), and `measure.py --full` (`full.log`).

The `hw-*.out` files end in a Python traceback: `hwcounters.sh` failed on its last line when the
kernel counters were not permitted (fixed the same day). The per-request counts above it are complete.
