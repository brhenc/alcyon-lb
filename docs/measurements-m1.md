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
  (`tools/measure/run.sh`), reload (T166), backend connections (T159 B).

Raw `RESULT` lines of the runs are printed by each script; re-run any row with its command.
