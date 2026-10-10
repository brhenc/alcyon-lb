# M1 resource measurements (T180)

(`docs/tradeoff.md` does not exist, so the table is here; `docs/milestones.md` "Resource
parameters" is the source of the targets.)

- Date: 2026-10-05. Commit: 4d2cc6f (no `crates/` change; Ibex built with
  `CARGO_TARGET_DIR=/home/bhenc/ibex-targets/t180 CARGO_INCREMENTAL=0 cargo build --release --bin ibex`).
- HAProxy: `/home/bhenc/reference/haproxy/haproxy` 3.5-dev8-885761-29, also used as the origin
  server (4 threads, `http-request return`).
- Machine: 64 CPUs, shared with other agents' builds. **Load was far above the 8 limit**: `uptime`
  load average at the start of each script (1/5/15 min): idle-rss 35/39/31, active-rss and
  fds about 52-60, startup 52/61/48, h2/tls 78/76/58, throughput 43/43/49, latency 17/35/45;
  h2/tls rerun 37/29/38. Each script waits up to 5 min for load < 8 and then runs anyway.
  Absolute figures are therefore inflated and noisy; ratios of RSS, fds and CPU-per-request
  are robust, throughput and latency ratios close to 1 are not.
- Each row: 3 runs, median. Both proxies on the same generated config (`tools/measure/m1lib.py`
  `proxy_cfg`), `nbthread 1`, frontend `maxconn` set explicitly (see T182).
- **Tools substituted.** `wrk`, `wrk2`, `h2load` and `ab` are not installed on this machine.
  Throughput and latency use the Python client in `m1lib.load()` (epoll, up to 12 processes;
  closed loop for throughput, open-loop constant rate for latency, latency counted from the
  scheduled send time). h2 uses `curl --http2 --parallel` (nghttp2), TLS handshakes use
  `openssl s_time -new -tls1_3`. A Python client tops out near 30k rps, so on small bodies at
  50 conns both proxies are probably client-limited.

| Parameter | Ibex | HAProxy | Ratio | M1 target | Result | Command (from repo root, `CARGO_TARGET_DIR=/home/bhenc/ibex-targets/t180`) |
|---|---:|---:|---:|---|---|---|
| RSS per idle keep-alive conn (10k) | 26 989 B | 1 062 B | 25.4x | <= 2x | MISS (T183) | `tools/measure/m1_idle_conn_rss.py` |
| RSS per active conn, 1 MB body in flight (1k) | 35 308 B | 4 510 B | 7.8x | <= 2x | MISS (T184) | `tools/measure/m1_active_conn_rss.py` |
| Throughput 1 conn, small | 8 482 rps | 8 940 rps | 0.95 | >= 0.8x | PASS | `tools/measure/m1_throughput.py` |
| Throughput 50 conns, small | 32 087 rps | 27 799 rps | 1.15 | >= 0.8x | PASS (client-limited?) | same |
| Throughput 1 conn, 64 KB | 24 rps | 3 632 rps | 0.007 | >= 0.8x | MISS (T185) | same |
| Throughput 50 conns, 64 KB | 1 213 rps | 10 593 rps | 0.11 | >= 0.8x | MISS (T185) | same |
| Added latency p50 at 14 373 rps (50% of max) | +81 us | +262 us | 0.31 | - | info | `tools/measure/m1_latency.py` |
| Added latency p99 at 14 373 rps | +107 us (p99 1.24 ms) | +29.7 ms (p99 30.8 ms; runs 1.4 / 30.8 / 1868 ms) | 0.04 | p99 <= 1.5x | PASS (HAProxy p99 is load noise) | same |
| CPU per request, h2 (TLS, ALPN h2) | 941 us | 48.5 us | 19.4x | <= 1.5x | MISS (T186) | `tools/measure/m1_h2_tls.py` (rerun: 905 vs 50.8 us, 17.8x) |
| TLS handshakes per CPU-second (ECDSA P-256, TLS 1.3) | 4 603 | 2 064 | 2.23x (CPU per handshake 217 vs 485 us) | <= 1.5x CPU | PASS | same |
| File descriptors per connection (client-proxy-server keep-alive) | 2.00 | 1.01 | 1.98x | equal | MISS (T187) | `tools/measure/m1_fds.py` |
| Startup, 10k backends, to first accepted conn | 0.582 s | 0.257 s | 2.27x | <= 2x | MISS (T188) | `tools/measure/m1_startup_10k.py` |

Latency run: max throughput at 50 conns was 30 006 (Ibex) and 28 746 (HAProxy) rps; rate
14 373 rps for both, direct-to-origin baseline p50 567 us, p99 1 137 us (subtracted to get
"added"). Ibex p99 over 3 runs: 1 226, 1 244, 1 420 us.

Notes on individual rows

- Idle RSS: HAProxy reuses one idle server connection for successive clients (fds 10 007 at
  10k clients), Ibex holds one per client (20 005), so Ibex's figure includes server-side
  connections (T187, T183).
- Active RSS: slow-client case (4 KB receive buffer, never reads); a slow-server case is not
  measured.
- 64 KB: Ibex shows a fixed ~41 ms per response (24 rps x 50 conns = 1 213 rps).
- Frontend maxconn: with only `global maxconn 11000`, Ibex stops accepting after ~2 129
  connections because it defaults the frontend limit to 2000, HAProxy accepts 5 000 (T182,
  not a measured parameter; filed because it blocks the 10k-connection tests).
- Not redone, see earlier work: startup RSS (T175), CPU per request h1 and allocations
  (`tools/measure/run.sh`); reload and backend connections are in the T214 section below.

Raw `RESULT` lines of the runs are printed by each script; re-run any row with its command.

## Reload and uneven load (T214)

- Date: 2026-10-05. Commit: 863f5a8 (no `crates/` change; Ibex built with
  `CARGO_TARGET_DIR=/home/bhenc/ibex-targets/t214 CARGO_INCREMENTAL=0 cargo build --release --bin ibex`).
  Load average (1/5/15) at the start: reload single 6.2/23.2/36.0, reload soak 6.1/13.8/28.6,
  uneven 26.1/23.0/25.2. HAProxy 3.5-dev8-885761-29 as oracle and as origin.
- Load: `~/.local/bin/wrk2 -t2 -c50 -R2000` h1 keep-alive (installed now, unlike T180), plus a side
  Python client (10 connections, retries once when an idle connection was closed, counts a reset,
  truncated answer or 2 s hang as failed). `nbthread 1`, 1 `server` per backend, HAProxy config
  has `stats socket ... expose-fd listeners`. Ibex and HAProxy interleaved, 3 runs, median.
- RSS = sum of VmRSS of every process of the layout (master + old + new worker), sampled every
  10 ms, peak between the signal and 1 s after the old worker is gone (shared binary pages are
  counted once per process, for both proxies). "New worker accepting" = first probe answer
  (a probe connection every ~5 ms) whose accepted socket is held by a pid that had not answered
  before; Ibex has no `pid` sample fetch, so `/proc` is used for both.

| Parameter | Ibex | HAProxy | Ratio | Target | Result | Command |
|---|---:|---:|---:|---|---|---|
| Reload, 1k backends, SIGUSR2 -> new worker accepting, `-W` | 73 ms | 157 ms | 0.47 | <= 2x | PASS | `tools/measure/m1_reload.py single` |
| same, Ibex `-W -S` | 68 ms | 157 ms | 0.43 | <= 2x | PASS | same |
| Reload, 10k backends, to new worker accepting, `-W` | 160 ms | 190 ms | 0.84 | <= 2x | PASS | same |
| same, Ibex `-W -S` | 129 ms | 190 ms | 0.68 | <= 2x | PASS | same |
| Peak RSS old+new during reload, 1k, `-W` (baseline 15.6 vs 53.2 MB) | 31.0 MB | 85.4 MB | 0.36 | <= 2x | PASS | same |
| same, Ibex `-W -S` (baseline 24.6 MB: master 9 + worker 15) | 39.8 MB | 85.4 MB | 0.47 | <= 2x | PASS | same |
| Peak RSS old+new, 10k, `-W` (baseline 70.4 vs 131.7 MB) | 140.5 MB | 242.0 MB | 0.58 | <= 2x | PASS | same |
| same, Ibex `-W -S` (baseline 109.2 MB) | 179.1 MB | 242.0 MB | 0.74 | <= 2x | PASS | same |
| Failed/reset requests (py client), 6 reload runs per layout | 0 / 0 | 0 | - | 0 | PASS | same |
| 100 reloads under load, 1k, `-W`: worker RSS before/after, fds net of conns | 15 516 / 15 456 kB, 8 / 8 | 32 220 / 32 164 kB, 10 / 10 (master 20 996 / 21 052 kB, 7 / 7) | - | flat | PASS | `tools/measure/m1_reload.py soak` |
| 100 reloads, 1k, Ibex `-W -S`: worker RSS, fds; master RSS, fds | 15 424 / 15 676 kB, 8 / 7; master 9 088 / 9 296 kB, 5 / 5 | (above) | - | flat | PASS | same |
| Backend conns accepted, T159 B scenario, burst cycles, nbthread 4 | 15-18 per 10 s (median 16) | 19-24 (median 21) | 0.76 | within 10% | PASS (fewer) | `tools/measure/m1_uneven_load.py` |
| same, nbthread 16 | 15-16 (median 15) | 31-34 (median 32) | 0.47 | within 10% | PASS (fewer) | same |
| Backend conns accepted, wrk2 -c100 -R1000 `Connection: close` /slow, 10 s, nbthread 4 | 60-85 (median 69) | 69-94 (median 86) | 0.80 | within 10% | PASS (fewer) | same |
| same, nbthread 16 | 54-84 (median 57) | 74-90 (median 90) | 0.63 | within 10% | PASS (fewer) | same |

Notes

- Old worker gone (median, 1k / 10k): Ibex `-W` 104 / 214 ms, `-W -S` 76 / 196 ms, HAProxy 95 / 320 ms.
- **wrk2 reports timeouts on HAProxy, not on Ibex**: HAProxy closes the idle keep-alive client
  connections when the old worker stops (the side client saw 5-10 of its 10 connections closed
  per 1k reload, 770 in the 100-reload soak, and retried each one with no failed request), and
  wrk2 neither retries nor notices: it counts 40-80 timeouts per 1k reload run and, over the soak,
  4 385 timeouts and 71 req/s (connections hung for the rest of the run). Ibex keeps the idle
  connections open (0 closed) and wrk2 sees 0 errors. With the legal retry both have 0 failures,
  so the "0 failed" criterion is met by both only for a client that retries an idle close; for
  wrk2 HAProxy itself does not meet it. At 10k backends HAProxy showed no closures in 3 runs.
- "Uneven load" metric: connections the backend accepts; the T159 B scenario of
  `crates/ibex-rt/tests/it/idle_pool_shared.rs` (burst of 16 concurrent /slow clients, 20 sequential
  ones, 10 s of cycles, `http-reuse always`, one server) needs at least 16. Ibex opens fewer than
  HAProxy at both thread counts (HAProxy at nbthread 16 opens about twice the minimum), so it is
  within the target read as "no more than HAProxy + 10%"; read two-sided it is outside by
  0.47-0.8. The 40 sequential clients use 1 backend connection on both. Rates are 1.5-9 conns/s
  because reuse works; the per-second figure is the count over 10 s.
- `-W -S` costs Ibex a master (9 MB at 1k, about 39 MB more at 10k than `-W`: it holds the
  parsed configuration, T200); still below HAProxy's total.
- Not measured: 100-reload soak at 10k backends; nbthread above 1 for reload.
- Ibex has no `pid` sample fetch (`http-response set-header x-pid %[pid]` is refused at parse time).
