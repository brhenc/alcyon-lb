# Does the buffer floor follow `maxconn`? RSS-per-burst curve (T469, 2026-10-25)

Status: measurement and recommendation; no code changed. Open question Q1 of
`memory-2026-10-24.md` §8.

## Method

Harness `/tmp/t469/burst.py` (not committed; scratch). One proxy process per series, `nbthread 4`,
`maxconn` 1000 or 20000, `http-keep-alive`, backend = a second HAProxy (`nbthread 2`) answering
`http-request return status 200 string ok`. A burst is N concurrent keep-alive connections (up to
8 client processes): connect, 1 request, wait until all N are established and answered, then 2 more
requests (the last `Connection: close`), close. 10 bursts per series, 5 s idle after each. After
each burst (+0.6 s) and each idle: `VmRSS`, `show pools` buffer line, and (shim pass) malloc +
calloc + realloc + aligned calls from `tools/allocshim/shim.c` via `LD_PRELOAD` on both proxies,
divided by 3N requests (so it includes accept, session and close work, and the proxy's backend side).
N > maxconn was not run. Binaries: Alcyon release of 07151b01 (`cargo build --release -p alcyon-rt --bin alcyon`),
HAProxy 3.5-dev8-885761-29. Each series ran under its own `flock -x /tmp/ibex-load.lock`.

Host state: governor `performance`; load average 3-45 from other agents' work (logged per series in
`/tmp/t469/out/log`); `virsh list` shows 3 VMs (suspended from ~11:30 per the supervisor).
`wwm.exe` was running until ~11:30; only the first shim series (haproxy, maxconn 1000, N 100; started 11:30:15, wwm=1 in the log) overlapped it, and its p99 is replaced by the no-shim rerun.
RSS, pools and malloc counts are not timing-sensitive and are taken from the shim pass (the shim adds
one thread and a few atomics; the no-shim pass agrees on RSS within 1 MB for every series run).
**p99 column**: median over 10 bursts of the p99 request latency (requests 2 and 3 of each connection,
after the barrier) from the no-shim pass on the quiet host; values marked `*` (N = 5000, 20000) come
from the shim pass (quiet host, shim overhead included) because the supervisor cut the no-shim pass
before it reached them. **p99 for N >= 5000 without the shim is an open line.**
Alcyon at N = 20000 on maxconn 20000 also queues on the SYN backlog (somaxconn 4096): both proxies show
multi-second p99 there; that is the harness/kernel, not a buffer effect. 0 connection errors in every series.

## Results (one table for both proxies; RSS in MB)

| proxy | maxconn | N | RSS start MB | burst 1 | burst 5 | burst 10 | idle after 10 | buffers allocated (idle 10) | mallocs/req burst 1 | mallocs/req bursts 2-10 | p99 req ms (median of 10) |
|---|---|---|---|---|---|---|---|---|---|---|---|
| haproxy | 1000 | 100 | 21 | 22 | 23 | 23 | 23 | 106 | 8.36 | 0.45 | 2.6 |
| haproxy | 1000 | 1000 | 21 | 32 | 38 | 40 | 40 | 95 | 10.86 | 12.91 | 48.2 |
| haproxy | 20000 | 100 | 23 | 24 | 25 | 25 | 25 | 99 | 8.31 | 0.56 | 2.8 |
| haproxy | 20000 | 1000 | 23 | 32 | 37 | 39 | 39 | 94 | 9.72 | 9.76 | 28.2 |
| haproxy | 20000 | 5000 | 23 | 73 | 112 | 127 | 127 | 99 | 10.36 | 14.81 | 152* |
| haproxy | 20000 | 20000 | 23 | 310 | 481 | 533 | 533 | 97 | 18.55 | 17.79 | 3139* |
| alcyon | 1000 | 100 | 10 | 14 | 14 | 14 | 14 | 200 | 1.70 | 0.12 | 2.9 |
| alcyon | 1000 | 1000 | 10 | 20 | 20 | 20 | 20 | 256 | 1.38 | 0.41 | 22.9 |
| alcyon | 20000 | 100 | 10 | 14 | 14 | 14 | 14 | 200 | 1.70 | 0.11 | 2.9 |
| alcyon | 20000 | 1000 | 10 | 20 | 20 | 20 | 20 | 256 | 1.38 | 0.44 | 30.5 |
| alcyon | 20000 | 5000 | 10 | 27 | 26 | 25 | 25 | 256 | 1.34 | 1.34 | 150* |
| alcyon | 20000 | 20000 | 10 | 71 | 66 | 55 | 55 | 256 | 1.61 | 1.46 | 3875* |

"buffers allocated" is the `Pool buffer` `allocated` count at the end of the series (after 5 s idle).
Raw per-burst JSON lines: `/tmp/t469/out/*.jsonl` (scratch, not committed).

## Reading the curves

- **Alcyon plateaus; no leak.** RSS after burst 1 is within 1 MB of burst 10 at N = 100, 1000, 5000;
  at N = 20000 it goes 71 -> 55 MB (falls, never grows). The buffer pool is 200-256 allocated at
  every N, i.e. the floor (64 per thread x 4) and never above it: `failures 0` and no growth when
  N goes from 100 to 20000. The pool's `allocated` count does not depend on N in this workload
  (each request is served and its buffer given back before the next connection is read), so the
  floor is not being exceeded and the kept peak (Q2) is a few MB.
- **HAProxy keeps growing.** At N = 20000 RSS climbs 310 -> 533 MB over 10 bursts and had not stopped
  (still +9 MB on the last burst); N = 5000: 73 -> 127 MB; N = 1000: 32 -> 40 MB (plateau by burst ~8).
  Its buffer pool stays ~100 allocated, so the growth is not buffers (connection/stream/session
  objects and malloc arenas; not attributed here). At 20000 it is ~10x Alcyon's RSS.
- **Mallocs per request.** Alcyon 1.3-1.7 on burst 1, 0.1-0.4 (N <= 1000) and 1.3-1.5 (N >= 5000) after;
  HAProxy 8-19 on burst 1 and 0.5-18 after (0.5 only at N = 100, where its pools stay warm).
  The Alcyon remainder at large N is not buffers (buffer `allocated` is constant); I did not
  attribute it (`tools/allocprofile` is an in-process single-request tool, not a burst tool).

## Would a floor that follows `maxconn` pay?

Take floor = maxconn / nbthread / k. For maxconn 20000, nbthread 4, k = 4 the floor is 1250 buffers
per thread, 5000 in all, 80 MB of 16 KiB buffers if filled once (k = 16: 20 MB). Alcyon's whole-process
RSS after 20000 simultaneous connections is 55-71 MB, so even k = 4 would put the idle floor above the
whole measured peak, and at the default maxconn (what a small blog sets) it is idle RSS paid for nothing.
What it would save: the buffer pool never allocated beyond its 64-per-thread floor in any series
(256 at every N from 1000 to 20000, 0 failures), so the buffer mallocs a larger floor would remove
are 0 per burst in this workload. The 1.3-1.5 mallocs per request Alcyon still makes at N >= 5000 are not buffers.

**Recommendation: keep 64 per thread.** No formula. Evidence: cost of the formula is 20-80 MB of idle
RSS at maxconn 20000; its saving on this workload is 0 buffer mallocs per burst. Limits of that
claim: the workload is small requests with immediate responses against a sink, where a buffer is
held for microseconds. A workload that holds buffers (large bodies, slow clients, `maxconn`-many
concurrent uploads) was not measured here (m1_active_conn_rss.py covers 1 MB in flight for 1000
connections) and could push `allocated` above the floor; if the netfuzz soak shows `allocated`
rising with N there, revisit with `tune.memory.prealloc` (T468) as the opt-in rather than a default
floor. No code change was made.
