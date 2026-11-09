<!--
SPDX-License-Identifier: GPL-2.0-or-later
Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
-->
# Raw output behind performance.md (2026-11-09)

- `matrix/`: `tools/measure/variants-matrix.sh` for each build (`<label>.<run>.out`), and `run.log`
  with the load average and governor at the start and end of every run. Labels as in
  performance.md: `alcyon-rp`, `alcyon-pgo`, `hap-<variant>` (3.5-dev8), `hapq-<variant>` (3.5-dev10).
- `matrix2/`: the second matrix, with `kernel.perf_event_paranoid` 1 (user and kernel
  instructions), the AWS-LC builds (`hap-*-awslc`, `hapq-*-awslc`) and the TLS `ab1s` / `hs1` rows
  (`<label>.tls-<client>.out`). Runs after 15:32 overlap another project's job (performance.md,
  Setup): their instruction counts stand, their cycles are not used.
- `default-builds/`: `tools/measure/insreq.sh` for `alcyon-rp` (`a-*`) and the reference HAProxy
  `-O2` binary (`h-*`), and `measure.py --full` (`full.log`).

The `hw-*.out` files end in a Python traceback: `hwcounters.sh` failed on its last line when the
kernel counters were not permitted (fixed the same day). The per-request counts above it are complete.
- `dpbench/`: `tools/measure/dpbench.sh` (dpbench's h1load and httpterm). `run1/` (16:39) and `run2/`
  (16:47) with `balance random`, `run3/` (18:11) with `balance roundrobin`, each with `run.log` (the summary lines) and per proxy and thread count the load
  generator's `max.out` and `fixed.out`, the probe's `probe.out` (percentiles), and the
  configuration `p-<nbthread>.cfg`. Run 1 reports the process CPU only; runs 2 and 3 add the CPUs' busy
  time with softirq, which is the figure performance.md uses.
