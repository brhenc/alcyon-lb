# Per-thread counter rows: `tune.ibex.counters` (T582 Part A, D-4 "both")

Status: **design for approval, no code.** Inputs: engine doc §2.1 row 13 and §6.1 (D-4), the C1
row; `memory-2026-10-24.md` (one owner); HAProxy `include/haproxy/counters-t.h`,
`include/haproxy/counters.h`, `src/stream.c` 2860-2905, `src/stats-proxy.c` 836/1215. Figures
marked *(est.)* are mine; the rest are X0's or counted in the source.

## 1. Which counters

| object | where | per request (hot) | per connection | cold (checks, CLI, rare paths) |
|---|---|---|---|---|
| frontend `TxnCounters` (`fe`) | `statcnt.rs`, `account_stream` engine.rs:3349 | `req_tot`, `hrsp[class]`, `bin`, `bout` (4 RMW) | `conn_rate_max`, `rate_max`, `req_rate_max` (maxima) | `ereq`, `eint` |
| backend `TxnCounters` (`be`) | same | `stot`, `bin`, `bout`, `req_tot`, `hrsp`, `lbtot`, `smax` (7 RMW); `qtime`/`ctime`/`rtime`/`ttime` sum (load+store), `last_sess` store, `sess_rate` tick (2 load+store) | `connect`/`reuse` (engine.rs:9177) | `cli_abrt`, `srv_abrt`, `eresp`, `eint`, retries |
| server `TxnCounters` (`srv[i]`) | same | as backend (7 RMW + the same stores) | `connect`/`reuse` | `chkdown`, `last_chg`, `down_since`, `downtime_ms` |
| `ProxyStats` (per proxy) | engine.rs:1475 | `fe_req_rate`, `be_sess_rate` ticks | `cum_conn`, `fe_sess_rate`, `act_conn`, `be_streams`, `bytes_in/out` | `denied_*`, `failed_conn`, `queue_*` |
| global (`show info`) | `stats.rs` `CUM_STREAMS`; engine.rs:1374 `ThreadRates` | `CUM_STREAMS` (1 RMW) | conn/sess rates (**already per thread**) | `SSL_*` |
| listener | none: Ibex has no listener rows (`stats_typed.rs:331`) | - | - | - |
| stick tables | `ibex-stick` | entries are read by rules (rate limits must be global) | | **out of scope**: stay shared, as HAProxy's |

That is T579's pinned 19 RMWs per request (`engine_pass.rs`: 4 + 7 + 7 + `CUM_STREAMS`) plus
~12 plain stores to the same shared lines (4 `TimeStat` sums, `last_sess`, `sess_rate` x2 rows).
A plain store to a line another core holds moves the line just as an RMW does: per-thread rows
must take the stores too, or they buy little.

## 2. Layout

**HAProxy (3.x).** `fe_counters_shared.tg[]` / `be_counters_shared.tg[]`: one ~330-byte struct
per object per **thread group** (`calloc` each, or the shm-stats-file slot), written with
`_HA_ATOMIC_INC` (several threads per group), summed by readers with `COUNTERS_SHARED_TOTAL`.
The timing sums (`q_time`...`t_time`), every maximum (`*_max`, `sps_max`, `cur_sess_max`) and the
rate counters behind the maxima stay in the non-tg `be_counters`/`fe_counters`: one copy,
shared. The `swrate` window uses the **own tgroup's** `cum_req` (stream.c:2881), the reader the
total (stats-proxy.c:836). Default `nbtgroups` is 1, so a default HAProxy writes one shared set:
Ibex's `shared` is parity.

**Ibex, `per-thread`.** Split `TxnCounters` (today 280 B, 320 with `align(64)`) into:
- `HotRow` (written once per stream by its owner thread): `hrsp[6]`, `req_tot`, `stot`, `lbtot`,
  `connect`, `reuse`, `bin`, `bout`, `cli_abrt`, `srv_abrt`, `eresp`, `ereq`, `eint` (18 x u64 =
  144 B), the four `TimeStat` sums (32 B), `last_sess` (8 B), `sess_rate: RateCtr` (16 B) =
  **200 B**;
- `ColdRow` (stays one shared copy per object): the maxima (`TimeStat::max` x4, `rate_max`,
  `req_rate_max`, `conn_rate_max`, `smax`; written only when beaten since T579) and the server
  state fields.

**Thread-major slabs.** Each worker owns **one** `Box<[HotRow]>` holding every row of every
proxy (row index fixed at configuration load: `proxy.row_base + {0: fe, 1: be, 2+i: server i}`),
allocated 64-byte aligned and padded to a whole line at the end. Rows inside a slab are packed
(no per-row padding: only the owner writes them); the only line two threads could share is the
slab edge, and padding removes it. The owner writes with `load` + `store` (`Relaxed`, no lock
prefix); readers on other threads `load`. `shared` keeps today's `fetch_add` on the one slab.
Both modes run the same `account_stream::<M: CounterMode>` monomorphised, chosen once per stream
end, so `shared` adds one predictable branch, not one per site.

**Owner (AGENTS §8).** The slabs are an `ibex_alloc` arena of fixed size: a `CounterTable` that
registers with `PoolRegistry` as `counters` (`show pools`: allocated = slots x 200 B, used =
rows), never grows, and is never compacted (`Arena::compact` returns 0). Indexed by
`ibex_alloc`'s `thread_slot()`; allocated **eagerly at worker start** with `try_reserve_exact`
(a failure refuses the start, naming the size), never on the request path.

## 3. Memory

200 B x servers x threads (decimal MB; add 400 B per proxy per thread for its fe/be rows):

| servers | 8 threads | 32 threads | 64 threads | today, `shared` (320 B x servers) |
|---:|---:|---:|---:|---:|
| 1,000 | 1.6 MB | 6.4 MB | 12.8 MB | 0.32 MB |
| 10,000 | 16 MB | 64 MB | **128 MB** | 3.2 MB |
| 60,000 | 96 MB | 384 MB | 768 MB | 19.2 MB |

D-4's 128 MB (10k x 64 x 200 B) holds exactly. Keeping the `TimeStat` sums shared (Q2's other
answer) makes the row 168 B (-16 %). `shared` stays lazy per proxy (`Proxy::tc`'s `OnceLock`),
so it costs nothing for backends that never saw a request; `per-thread` is eager by design (Q4).

## 4. Readers

One reader, `TxnCounters::snapshot(obj) -> TxnSnapshot` (plain `u64`s), replaces the `ld()`
calls in `stats.rs::fill_counters` (stats.rs:792) and the `req_tot` sums at stats.rs:571,
applet.rs:962, engine.rs:5620. `show stat`, `show info`, Prometheus (`promex.rs` fills from the
same `StatRow`s) and the stats page (T572's cursors) all go through it.

| field | `per-thread` reader | equal to `shared`? |
|---|---|---|
| totals (`hrsp_*`, `req_tot`, `stot`, `lbtot`, `bin`, `bout`, aborts, errors, `connect`, `reuse`) | sum of rows | **exact** |
| `lastsess` | max of rows | exact |
| `rate` (`sess_rate`) | sum of the rows' `RateCtr::rate` | exact |
| `rate_max`, `req_rate_max`, `conn_rate_max` | shared `ColdRow`, fed from the **owner's** rate | upper bound when peaks are not simultaneous: as `MaxConnRate` today (engine.rs:1376) |
| `qtime`...`ttime` | mean of the active rows' `swrate` averages; window from the own row's `req_tot` (HAProxy's per-tg rule) | exact at `nbthread 1`; differs when threads see different latencies (Q2) |
| `*_max`, `smax` | shared, unchanged | exact |

Read cost: rows x threads x 25 loads; 60k servers x 64 threads is ~96 M loads (~50-100 ms
*(est.)*) per full `show stat`: the T572 cursors already yield between rows.

**`clear counters`.** The CLI never writes another thread's slab (a store racing the owner's
load+store loses one or the other). It bumps the table's epoch (as `CLEAR_EPOCH` does for
`ThreadRates`); each owner compares once per loop pass and zeroes its own slab (60k servers:
12 MB `memset`, ~1-3 ms once *(est.)*); readers count a slab whose epoch is stale as zero, so the
clear is visible at once. Maxima (`clear counters` without `all`) stay a direct store on the
shared `ColdRow`, as today.

## 5. The setting

`tune.ibex.counters shared|per-thread` in `global`, default **`shared`**. `per-tgroup` is
refused: Ibex refuses `thread-groups` > 1 (`parser/global.rs:764`), so it would be `shared` under
another name, which is the §5 trap. Message: `'tune.ibex.counters': 'per-tgroup' is not
implemented (one thread group); expected 'shared' or 'per-thread'`; any other word is refused
the same way. It reaches the data path where the engine builds `CounterTable::new(mode, rows,
nbthread)` and each worker picks `account_stream::<Shared|PerThread>`. Read at start only: a
reload (new process) applies a change, and counters restart at zero as they do today (Ibex has no
`shm-stats-file`). The startup notice prints the table's bytes when `per-thread` is set.

## 6. Expected saving

**The setting saves cycles, not instructions.** A relaxed load-add-store compiles to one
unlocked `add [mem]` on x86-64 (LLVM folds it *(est.: to be checked in Part B's asm)*), so
`insreq.sh` should read **flat (+-0.1k)** with it on. What goes: 19 locked RMWs (~20 cycles each
uncontended on Zen *(est.)*: **~0.4k cycles a request at `nbthread 1`**) and, at `nbthread >= 8`
on one busy backend, the line transfers of ~5 shared lines a request (hundreds of cycles each
across CCDs *(est.)*). X0 measured one thread and instructions; row 13's "atomic 1.3k" in §2 was
profile share (IBS samples land on locked ops), which is why D-4 put "~0.5k" on it. Part B needs
a `cycles:u` / throughput A/B at `nbthread 4` and `16` (reported, not pinned, as S2's).

**Without the setting (C1 leftovers, instructions, `shared`):** T579's first pass gave keepalive
-262, rules -127, h2s1 -497 against C1's -0.3 to -0.6k / -0.8 to -1.2k. The leftovers *(est.)*:
`count_status` classified once per stream, not on three rows (-0.02 to -0.04k); skip zero
`bin`/`bout` adds (-0.01k h1, more on h2 streams with no body); `CUM_STREAMS` and the other
`show info` globals per thread unconditionally (O(threads) memory: -0.01k, and a shared line
gone); `SampleContext`'s accept date once per stream (h2s1 -0.05 to -0.1k); and one found here:
**the backend `smax` sums `server_actconn` over every server of the backend per request**
(engine.rs:3468: O(servers) loads; 1k servers = ~1k loads), where HAProxy updates
`be_counters.conn_max` from `beconn` in O(1) (proxy.c:4120): -0.01k at 2 servers, -1k+ at 1k.
Sum: **keepalive/rules -0.1 to -0.2k, h2s1 -0.2 to -0.4k** at the bench's server counts.

## 7. Questions for the user

1. **Values now**: `shared` and `per-thread`, with `per-tgroup` refused until Ibex runs more
   than one thread group? *Recommendation: yes.* Default taken: yes.
2. **Timing averages in `per-thread`**: per-thread `swrate` (reader averages the threads'; equal
   at `nbthread 1`, close but not HAProxy's figure otherwise) or keep the sums shared (one shared
   line still written per request; row 168 B)? *Recommendation: per-thread; the averages are
   already a 512-sample estimate.* Default taken: per-thread.
3. **Rate maxima in `per-thread`**: the sum of the threads' peaks (an upper bound, as
   `MaxConnRate` already is) rather than a shared rate counter ticked per request?
   *Recommendation: yes, documented in the setting's doc.* Default taken: yes.
4. **Allocation**: eager at worker start, fallible, size in the startup notice and `show pools`,
   no cap (rather than lazy per proxy per thread, which allocates on the request path)?
   *Recommendation: eager, no cap; the operator opted in.* Default taken: eager, no cap.
5. **Globals**: make `CUM_STREAMS` and the other `show info` totals per thread in every mode (the
   memory is O(threads)), shrinking the §8 exception without the setting? *Recommendation: yes.*
   Default taken: yes.
6. **Proof for `per-thread`**: accept a `cycles:u` + throughput A/B at `nbthread 4`/`16` as its
   figure, with `insreq` only required flat (+0.5 %) in both modes? *Recommendation: yes;
   `insreq` cannot see a lock prefix.* Default taken: yes.
7. **The `smax` O(servers) sum** (engine.rs:3468): fix it in the C1 leftovers (HAProxy's O(1)
   `beconn` derivation, oracle-checked) rather than wait for Part B? *Recommendation: yes, it is
   a scaling defect, not a trade.* Default taken: yes.
