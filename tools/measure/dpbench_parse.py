# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
#
# dpbench_parse.py rps|pctl <h1load output>: req/s, or the probe's percentiles; used by dpbench.sh
import re, sys
mode, path = sys.argv[1], sys.argv[2]
if mode == 'rps':  # (tot_req delta) / (time delta) from the per-second rows, without the first 4 and the last
    rows = [(int(f[0]), int(f[3])) for f in (l.split() for l in open(path)) if len(f) >= 4 and f[0].isdigit() and f[1].isdigit()]
    if len(rows) < 7: print(0); sys.exit()
    a, b = rows[4], rows[-2]
    print(int((b[1] - a[1]) / (b[0] - a[0])))
else:  # the ttfb column of h1load -P's percentile rows
    out = {f[0]: f[4] for f in (l.split() for l in open(path)) if len(f) == 7 and f[0] in ('50', '90', '99', '99.9', '99.99')}
    print(' '.join(f'p{k}={v}ms' for k, v in out.items()))
