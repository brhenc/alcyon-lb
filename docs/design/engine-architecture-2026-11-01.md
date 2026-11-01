# The engine at parity with HAProxy: loop, streams, rules, representation (2026-11-01)

Status: design, no production code. Written for the user's goal of 2026-11-01 ("aim for better
performance than haproxy at least for h1 and maybe h2 ... the design isn't matching haproxy and
we are still leaving performance on the table"). No measurement was run for this document (the
host was in use); every number names its record. Oracle: `~/reference/haproxy` (3.5-dev8,
88576119c), line numbers as of 2026-11-01.

This document is the whole programme. `htx-engine-2026-11-01.md` (D5, the representation) is
one of its four tracks and keeps its slices except where §4 says otherwise; the T550 survey's
S2/S3 become the O and L tracks here; the h3 track (`quic-transport-2026-11-01.md`) keeps its
slices and gets the ordering answer in §3.6.

## 0. Short answers

- **Target.** User-space instructions per request <= 1.0x HAProxy (aim 0.9x) on `keepalive ab1`,
  `rules ab1`, `h2s1`; non-PGO `release-perf` against non-PGO HAProxy dev8; kernel instructions
  no worse than today. Today (11:50, slot A, min of 3, user / kernel): keepalive 45,843 / 68,152
  against 36,236 / 69,421 (**1.27x**); rules 75,712 / 65,959 against 43,833 / 69,926
  (**1.73x**); h2s1 ~70k against ~54k (**1.30x**). Kernel is at parity already (Ibex makes fewer
  syscalls: §2 row 9); the whole gap is user space.
- **Why the gap is design, not language.** Ibex already holds structural advantages HAProxy does
  not: no stream allocation and free per keep-alive request (HAProxy's `stream_new`/`stream_free`
  are ~4.4k of its 53.4k on h2, §2 row 4); the server connection parked on the session between
  requests (HAProxy returns it to the idle list and takes it back, ~1k); an unmodified head sent
  as the bytes that arrived (HAProxy re-serialises every head, `h1_make_*` ~2.4k per request);
  rustls/ring against OpenSSL (~3k on h2, 11k on h3); no `CLOCK_THREAD_CPUTIME_ID` syscalls
  (HAProxy makes 6 a request); 4 data syscalls a request against 6; no pool/malloc traffic
  (HAProxy 1.4-4.2k). That is ~12-15k of advantage on h1, and Ibex is still 9.6k behind on
  keep-alive: **the engine's own overhead is ~20k above HAProxy's on the simplest request**. It
  is in four places, each a track: the loop and the stream run (L), the stream object and its
  backend side (O), the rules' dispatch and samples (R), the message representation (X, D5).
- **Where it goes (§2).** On h2 (T544 IBS, the only full profile): scheduler/loop/`engine::*`
  11-17.6k against HAProxy's ~2.3k; child session set-up and tear-down ~7.8k against 4.4k;
  backend selection and idle reuse 7.2k against 2.5k; the response scan family 4.2k (E2 took
  part) against 1.1k; mux<->stream bridge 10.5k against ~3.5k (E1/E2/Q3 took part). On rules
  (memory doc §1.3, pre-S7): spare strings 4.1k, per-edit rebuilds 6.5k, context clones 1.5k,
  fetch lookup by name ~1.5k+, UTF-8 1.6k. No post-E2 profile of any h1 scenario exists: **X0 is
  the first slice and its scope is extended** (§1.2, `tasks/X0-profile-post-e2.md`).
- **Architecture after the overhaul (§3).** One loop pass reads the clock once, polls, runs
  tasklets and tasks with HAProxy's class budgets, and does housekeeping only from timer tasks.
  A connection is a `TcpSession` (h1) or an owner (h2/h3) with a mux; a request is a pooled
  `Stream` (txn, log, vars, backend side) with its own scheduler task; the stream run is gated by
  wake reason and a pending bitmask, as `process_stream` is gated by flags. The message is HTX
  descriptors over the transport buffer (D-A); rules are compiled to fetch function pointers with
  parsed arguments and evaluate borrowed samples; actions edit blocks; the h1 encoder writes a
  modified head once at the send; h2/h3 muxes write and read blocks. Owner and streams of one
  connection run in the same pass (instant wakeup, HAProxy's `task_instant_wakeup`, task.h:553),
  which is where Ibex goes below HAProxy's pass count.
- **Landing (§5, ranges overlap, read at +-30 %).** keepalive 35-41k (0.96-1.14x, central
  ~1.05x); rules 45-57k (1.03-1.30x, central ~1.15x); h2s1 41-54k (0.75-1.0x, central ~0.9x).
  h2 reaches the target with margin (TLS and the pass count); keepalive reaches it only at the
  optimistic end unless X0 finds the I/O state machine's share (IO1); rules reaches 1.0x only if
  both the base is at parity and the per-rule cost drops to HAProxy's ~1k a rule.
- **quinn ordering (§3.6).** Q1 and the mechanical half of Q2 now; Q4 in parallel at any time;
  Q2's "drive once per pass" after L2 (it defines the pass); the h3 stream object (O1c) after
  O1b. Nothing in the quinn work waits for the representation track.
- **Cost.** 18 slices: 9 Opus (5 L, 4 M), 9 Sonnet (S/M); ~6 weeks at the current pace with two
  gate slots, critical path X0 -> X1/X5 -> X2/X3 -> X4 -> O1b -> O1c (~4 weeks), the L, R, O2, C
  slices in parallel beside it.

## 1. Evidence

### 1.1 Records used

| record | what it gives | trust |
|---|---|---|
| `~/ibex-worktrees/review/t544-2026-11-01/ibs/ibex-h2.folded` (IBS, frame pointers, inlines expanded) | Ibex h2s1 per-function inclusive and self, 79.6k build (pre-E1/E2/Q2/Q3/Q8) | +-10-20 % a row |
| `.../hap-h2-dwarf.folded` (`instructions:u` + DWARF) | HAProxy h2s1 per-function **inclusive**; 24.5 % of samples are on syscall entry (skid) so each inclusive share carries the syscalls under it | +-20 %, and read "minus the syscall skid" where a row contains recv/send |
| `.../ibs/hap-h2.folded` | HAProxy h2 IBS: 79 % of leaves unresolved (`[unknown]`): **no per-function HAProxy IBS exists**; T544's HAProxy phase rows came from the DWARF callers (`scripts/hybrid.py`) | per-phase only |
| `.../census/*.strace`, `calls/*.stat` | syscalls and probe counts per request (2000 / 5000 requests) | exact for that run |
| `quic-profile-2026-11-01.md` §2-3 (T544), `rust-performance-survey-2026-10-31.md` §3.2 | the phase table and the per-function h2 table | as above |
| `memory-2026-10-24.md` §1.3 | rules ab1 `perf record` by self cost, **pre-S7/T455/E2** | the buckets' shares; the totals have since moved |
| today's `insreq.sh` (11:50) | the three headline ratios and the kernel column | min of 3, indicative |

**No post-E2 profile of keepalive or rules exists, and no HAProxy per-function profile of any h1
scenario exists.** The parity table marks every h1 row "estimate" and says what X0 measures.

### 1.2 X0, extended

X0 (`tasks/X0-profile-post-e2.md`, Sonnet, S, slot B then A, quiet host) now produces, on main,
for `keepalive ab1`, `rules ab1`, `h2s1` (and `h3fit` for the h3 track), Ibex **and** HAProxy:

1. Per-function inclusive and self tables: Ibex by IBS with inline expansion (T544's `fold2.py`);
   HAProxy by `perf record -e instructions:u -c 100003 --call-graph dwarf` (as
   `hap-h2-dwarf.folded`), because its IBS leaves do not resolve. Scaled to the `insreq.sh`
   totals of the same run.
2. **Passes and runs per request**: uprobes on `Engine::step_at`, `step_stream`, `step_stream_run`,
   `h2_owner_pass`, `epoll_wait`; on HAProxy `run_poll_loop`'s `_do_poll`, `process_stream`,
   `h1_io_cb`, `h2_io_cb`, `sc_conn_io_cb`, `run_tasks_from_lists`. T544 reported 7.15
   `Engine::step` and 3.07 `epoll_wait` per h2 request; the two must be reconciled (which probe
   counted what).
3. The **per-run fixed cost**: `step_stream` + `step_stream_run` self with inlines, excluding
   `advance`/`http_step`; the per-pass fixed cost: `step_at` self + `Poller::poll` self + the
   housekeeping calls (`purge`, `trim_idle`, `purge_stick_tables`, `pool::pass`, `publish` x3).
4. The I/O state machine's self cost: `process_cli`, `process_cli_io`, `process_srv*`,
   `TcpSession::advance`, `MsgState::advance_counted`, `interests`, `update_interests`,
   `Buf::nominal/readable/drop`, `release`.
5. Tear-down and accounting: `end_txn`, `end_stream`, `account_stream`, `set_stream_log`,
   `statcnt::*`, every atomic RMW on the request path (count them: `perf stat -e` on a uprobe
   is not possible for inlined atomics; use the IBS leaf `atomic_*` rows), against HAProxy's
   `stream_free`, `stream_process_counters`, `stream_update_time_stats`.
6. Rules (rules ab1): `Registry::eval_g`/`any_acl`'s `fetches.get` count per request (uprobe on
   the non-inlined `hashbrown` probe or a debug counter build), `spare::*` operations,
   `VarStore` take/give, `SampleContext` construction sites, `from_utf8` calls, `rebuild`/
   `write_req_head` calls (`work::Op` counters), against HAProxy's `sample_process`,
   `pattern_exec_match`, `http_replace_header`/`http_add_header` rows.
7. Syscalls per request by name, both proxies, kernel instructions per syscall class
   (`insreq.sh` T568's kernel column split with `perf stat -e instructions:k` under
   `strace -c`-style counts), including HAProxy's `clock_gettime(CLOCK_THREAD_CPUTIME_ID)`.
8. Clock reads per request after Q2 (`Instant::now`, `SystemTime::now`, `clock_gettime`).
9. **Every per-request safety extra on by default** and its cost (zero-on-free, buffer wipe,
   `crash::contain`, `watchdog::progress` x3 a pass, `fault_point`): one row each, so the user
   can rule on them under "fair benchmark defaults".
10. Whether `set_stream_log`/`log_line` does work when no `log` target is configured.

Output: `htx-engine-2026-11-01.md` §1.3 (the representation rows) and **this document's §2
"measured" column** (append a §2.1), plus the figures in the task file. The L/O/C slices are
written against these numbers; their designs do not wait for them.

## 2. Parity table

Columns: HAProxy cost; Ibex cost; why they differ (design); the design that reaches parity or
better; slice. Sources: **[I]** Ibex h2 IBS (79.6k build; E1/E2/Q2/Q3/Q8 have since taken ~9k),
**[H]** HAProxy h2 DWARF inclusive x 53.4k, **[M]** memory doc §1.3 rules, **[C]** T544 census,
**[E]** reasoned estimate (X0 measures). Per-request figures; h2s1 unless the row says otherwise.

| # | component | HAProxy | Ibex | why they differ | design to parity or better | slice |
|---|---|---:|---:|---|---|---|
| 1 | **Loop pass**: clock, poll, event dispatch, pass housekeeping | `run_poll_loop` self 0.23k, `_do_poll` self 0.28k, `clock_update_date` ~0.05k, `fd_update_events` ~0.1k [H]; ~3 passes/req [C]: **~1.5-2k/req**. Housekeeping is tasks on timers (`srv_cleanup_idle_conns`, `process_table_expire`, `pool_gc`): 0 per pass | `step_at` self ~0.6k + `run_loop` self ~0.9k + `Poller::poll` self 0.2k [I] = **~1.7k/req** at 7.15 passes, i.e. ~250 a pass of pure loop; plus ~40 checks a pass (`step_at` 5917-6230: watchdog x3, `wake_queued` x2, `buf_wait`, `QueueWait::any`, QUIC fold/any x2, `purge`, `trim_idle`, `purge_stick_tables`, `pool_gc::poll`, `pool::pass`, `publish` x3, `next_purge`, `accept_limited`, `resume_paused_listeners`, `cli_accept_retry`, `note_sched`, `srvlog::pending`, the `EngineDispatcher` of 25 fields, 4 QUIC adopt/admit calls, `resume_cli_after_close`) [E ~200-400 a pass] | Ibex does per pass what HAProxy does per timer; and runs more passes (row 2) | **L1**: housekeeping as `Kind::Housekeeping` tasks on the wait queue (idle purge, buffer trim, stick expiry, pool pass, publishes, accept-limit/CLI retry); QUIC work behind one `has_quic` bool; the dispatcher built once per `Engine` (borrow split by a struct of `&mut`), not per pass. Pass fixed cost target <= 120 instr | L1 |
| 2 | **Passes and task runs per request** | ~3 passes (3.00 `epoll_wait`, one of them zero-timeout after a task wake) [C]; runs: `h2_io_cb` x2, `sc_conn_io_cb` x1, `process_stream` x2 [E from the DWARF shares]: ~5 runs, each a direct `t->process` call, `run_tasks_from_lists` self 0.85k + `process_runnable_tasks` self 0.38k [H] | **7.15 `Engine::step`** and 3.07 `epoll_wait` [C, to reconcile]; `run_tasks_from_lists` self ~0.3k [I]; the owner<->child **wake ping-pong** (`wake_queue.push(owner_task)` after every child run, engine.rs:11212; the owner's `h2_owner_pass` wakes children) crosses passes because `wake_queue` drains after `process_runnable_tasks` (engine.rs:6196-6224) | HAProxy's mux calls the stream's receive synchronously (`sc_sync_recv`, stream.c:1926; `sc_chk_snd`, stconn.c:978); Ibex hands off through the run queue | **L2**: instant wakeup: a wake raised during the pass joins the current pass's tasklet list (HAProxy's `task_instant_wakeup`, task.h:553, which its stream path does not use: this is where Ibex goes **below** HAProxy's pass count); the `last_run == loops` guard (sched.rs:703) becomes "at most twice a pass", budget-bounded. Target: h2 <= 3 passes, h1 <= 2 | L2 |
| 3 | **Stream run prologue/epilogue** (what runs on every task run besides I/O and HTTP) | `process_stream` self 1.8k [H] for 2 runs: ~0.9k a run, gated: `stream_check_timeouts` only on `TASK_WOKEN_TIMER` (stream.c:1751), analysers only while `req->analysers` bits are set, `stream_process_counters` once | `step_stream` + `step_stream_run` self 1.26k [I] + `stream_vars_enter/leave` (`Arc<[(String,usize)]>` clone+drop 0.7k [I]), `stream_timeouts_enter` (thread-local), `check_srv_connect`, `fdtab.ready` x2, `check_timeouts` every run, `retry_after`, glitches, `stick_stores`, `run_deferred_session_rules`, tcp inspect x2, `scrape`, `log_line.take`, `checkcache`, `srv_park_exp`, `update_interests`, `req/rep.release()`, `wants_rerun`, owner wake, `timer_updates.push`, heavy check (engine.rs:10889-11270): [E] ~500-800 a run x 7 = **3.5-5.5k** on h2, ~1.5-2.5k on h1 | HAProxy's run is state-gated; Ibex's re-derives every rare condition on every run | **L3**: `step_stream_run` gated by the wake reason (`WOKEN_TIMER` -> `check_timeouts`; `WOKEN_IO` -> the side whose fd fired) and a `pending: u16` bitmask on the session set where each rare condition arises (deferred rules, inspect, scrape, stick stores, glitches, park, retry, connect log, rate max, handshake failure); `&Proxy` passed down instead of thread-locals (Q6); `update_interests` only when `(Want, Want)` changed; buffers released at txn end. Target <= 150 a run | L3 |
| 4 | **Stream/txn object set-up and tear-down** | `stream_new` 1.4k + `stream_free` 3.0k [H] **per request** (h1 keep-alive too: `h1c_frt_stream_new`, mux_h1.c:4255, per request); `session` persists | h2: `h2_child_of` 1.9k + `new_with_mode` 0.8k + `StreamLog` 0.7k + `end_stream` 1.7k + `end_txn` 2.7k [I] = **~7.8k** (a full `TcpSession`, proxy.rs:653-894, per stream); h1 keep-alive: `end_txn` 2.7k + `account_stream` 1.1k [I, same code] = ~3.8k, no set-up | Ibex's h1 model is cheaper than HAProxy's (no object per request) but its tear-down rebuilds state HAProxy frees in one `pool_free`; its h2 child is a connection-sized object | **O1**: a pooled `Stream` (txn, log, vars, backend side, captures; <= 1 KiB; `ibex_alloc::Pool`): h1 keeps one and **resets** it (a few stores, O1a); h2/h3 owners hold `Vec<Stream>` by stream id, one scheduler task each (timers per stream, as HAProxy), not a `TcpSession` (O1b, O1c). Set-up target <= 0.8k, tear-down <= 1.2k | O1a/b/c |
| 5 | **Backend selection and connection reuse** | `stream_set_backend` 0.38k self, `assign_server` 0.6k, `connect_server` 1.3k incl. `conn_backend_get` 0.23k, `srv_add_to_idle_list` 0.27k [H] = **~2.5k**; per-thread idle `mt_list` per server, own thread first | `connect_http_backend` **7.2k** inclusive [I] (self 1.0k; `route_to_server` 1.3k, `select_server` 0.6k, `IdlePools::with_count` 0.7k: `RwLock` read + SipHash on `(usize,usize)`, `IdleKey` hashing, `attach_server_with_xprt` incl. the `getsockname` Q8 removed); keep-alive: server parked 100 ms on the session (`SRV_PARK_MS`, engine.rs:8761), no pool round trip (**Ibex advantage ~1k**) | hashed maps and a lock on the fast path (AGENTS §8: the lock word is a write another thread reads) against dense per-thread lists | **O2**: servers by dense index (Q5), idle connections as per-thread per-server lists (`Vec<IdleConn>` by server index; cross-thread take only on miss, as `conn_backend_get`), `with_count` gone, `route_to_server` reading the compiled backend. Target <= 2.5k on h2; keep-alive unchanged (parked) | O2 |
| 6 | **h1 parse** (request at the frontend, response from the server) | `h1_parse_msg_hdrs` 2.3k + `h1_headers_to_hdr_list` 1.4k + `htx_add_*` 1.1k [H] = **~4.8k per head** (parse into a list, then copy into HTX) | `H1Parser` ~3.5k [I] + `req_htx_init` 1.0k (the HTX copy) on the request; response: `H1Parser` + E2's `RspHead` | parity-ish; Ibex copies into `htx_buf` where D-A writes descriptors in place | **X2/X3** (D5): descriptors over the received bytes, no copy; names lowercased per the D-E setting. Target <= 3.5k per head, i.e. **below HAProxy by ~1.3k per head** | X2, X3 |
| 7 | **HTX / representation through rules, facts, logs** | one HTX per direction; `http_find_header` views (0.15k) | three copies of the request head and a `Vec<(String,String)>` response head (D5 §1); rules: per-edit rebuild 6.5k, spares 4.1k, context clones 1.5k, UTF-8 1.6k [M, pre-S7]; `apply_http_response_rules` with no rules 4.2k [I] -> E2 cut ~2k | D5 §1 | **X1/X5/X2/X3/X4/X7** as D5, with X2 also building the rules' `SampleContext` once per phase (S7's "borrow") and X3 retiring the per-rule clone. Target rules' representation share <= 3k | X |
| 8 | **Rule compilation and execution** (rules ab1: 2 ACLs, 7 rules) | HAProxy's rules cost: 43.8k - 36.2k = **7.6k for the scenario** (~1k a rule); `acl_exec_cond` -> `sample_process` -> `expr->fetch->process` (function pointer, args parsed at load, acl.c:1044, sample.c:1395) -> `pattern_exec_match` (compiled); actions `http_replace_header` on blocks; samples are views (`SMP_F_CONST`) | 75.7k - 45.8k = **29.9k for the scenario** (today, [insreq]); `Expr::eval` -> `registry.eval_g(&self.fetch_name, &self.fetch_args, ...)` -> `self.fetches.get(name)` (registry.rs:1310: a SipHash lookup per fetch per request) with `&[String]` args interpreted per call; `Sample::Str(String)` from the spare pool per fetch (`spare::string_from` 1.4k [M]); `set-var` through a 4 KiB `VarStore` spare; `%[rand]` rendered into a `String` | dispatch by name at run time, samples materialised | **R1**: `Expr` compiled to `FetchFn` + parsed `Arg`s + converter pointers at `Expr::parse`; no map on the path. **R2**: `Sample<'a>` borrowing the HTX block (`Cow<'a,[u8]>`), owned only after a converter makes bytes; `str` validated once at the fetch (D-B). **R4**: vars and format scratch inside the `Stream` (O1a). Target scenario rules cost <= 9k (HAProxy 7.6k) | R1, R2, R4, X2 |
| 9 | **Send/recv path, syscalls** | h2s1: `recvmsg` 4.01 (1 EAGAIN), `sendmsg` 2.00, `epoll_wait` 3.00, `clock_gettime(CLOCK_THREAD_CPUTIME_ID)` **6.00 real syscalls** (`clock_entering/leaving_poll`, clock.c:404/474) [C]; `MSG_MORE` via `CO_SFL_MSG_MORE` when a head precedes a body; `sc_conn_recv` self 0.8k, `sc_conn_send` self 0.2k, `h1_recv`/`h1_send` ~1k [H] | h2s1: `read` 2.00, `write` 2.00, `epoll_wait` 3.07, no clock syscalls [C]: **fewer syscalls, kernel at parity** (68.2k vs 69.4k on keepalive today); user side: `process_cli` 0.36k, `process_cli_io` 0.26k, `advance` 0.18k, `MsgState::advance_counted` 0.53k + `eq` 0.18k, `interests` 0.18k, `Buf::nominal/readable/drop` 0.9k [I self] = **~2.6k** against HAProxy's ~2k; `req/rep.release()` per run gives the buffer back and re-takes it on the next read (HAProxy frees only when empty, keeps `ibuf` while a request is in flight) | Ibex's state machine re-derives `MsgState` and interests per run; buffer take/give per run | **IO1**: `advance` driven by readiness bits set by the poller, `MsgState` advanced by the parser's return (no re-walk), buffer kept while the txn is open, `Buf` accessors without the `nominal` indirection. Target <= 1.5k. No splice/zero-copy work: at these sizes HAProxy does not use them either (`htx_xfer` is a memcpy) | IO1 |
| 10 | **h2 framing and HPACK** | `h2c_dec_hdrs` 2.6k + `h2_make_htx_request` 2.1k + `h2c_frt_handle_headers` self 0.3k [H] on the request; `h2s_snd_fhdrs` 0.7k + `h2_snd_buf` self 0.3k + `h2_send` 0.4k on the response: **~6.4k** | `MuxH2` 4.9k + `hpack` 3.8k (of which `find_table_entry` 1.4k, Q3 done) + bridge `start_request` 5.3k (E1 took the 4.7k re-parse) + `forward_response` 3.6k (E2 took `send_h1_head`'s re-split) [I]: ~**8-10k after E1/E2/Q3** [E] | Ibex still crosses HTTP/1.1 text at the server send and a `copy_header` list; the owner moves bytes through `h2_bridge_moves` 4.2k | **X4** (blocks into the child's layout, one encode at the server send), **O1b** (the child is a `Stream`, the owner iterates its streams: no `get2_mut` dance per child per pass), **L2** (same-pass). Target <= 6k | X4, O1b, L2 |
| 11 | **TLS record layer** (h2s1) | `SSL_read` 7.4k + `SSL_write` 6.6k inclusive [H], of which ~7k is syscall skid: **~7-8k** user | rustls record 3.4k + ring seal/open 1.4k [T544] = **4.8k**: **Ibex advantage ~3k** | ring's assembly, rustls's smaller state | keep | - |
| 12 | **Clock and timers** | one `clock_update_date` a pass (vDSO) + 2 CPU-time syscalls a pass; timers in the `eb32` wait queue, `wake_expired_tasks` 0.11k [H] | 37.6 `Instant::now` a request at T544 (3-3.4k) [I]; Q2 since: per-pass cell; `wake_expired_tasks` 0.3k, `Tick::is_before` 0.1k, `Duration::as_millis` 0.2k [I] | done by Q2; residue in conversions and `StreamLog::start`'s `SystemTime::now` | **C2**: `%t`/`%Tl` from the pass clock (HAProxy's global `date`), ticks stored as the pass's `u32` ms, no `Duration` arithmetic on the path. X0 counts reads after Q2 | C2 |
| 13 | **Counters, stats accounting, logs** | `stream_process_counters` 0.21k + `stream_update_time_stats` 0.15k + atomics on per-tgroup shared counters [H]: **~0.5k**; no `log` target: `strm_log` 0 | `account_stream` 1.1k + `statcnt` 1.0k + `atomic` 1.3k (incl. `TimeStat::add`'s `fetch_max` cmpxchg loop 0.35k) + `txnlog` 0.8k [I]: **~3k**; `set_stream_log` with no target: X0 item 10 | both sides use shared atomics (HAProxy per thread group); Ibex adds a `now_ms` read, `RateCtr::at`, `count_status` on three rows, the `fetch_max` loop | **C1**: Q6 (`fetch_max` -> load, store if greater); `account_stream` from the pass clock; one `count_status` call; `StreamLog` fields only when a log target exists. Per-thread counter rows **not** adopted (10k servers x 64 threads x 200 B = 128 MB, T175's lesson). Target <= 1.2k | C1 |
| 14 | **Pools and malloc** | `pool_*` + malloc/free 1.4k (h2) to 4.2k (rules) [H, M] | 0 malloc; `Buf` pool 0.3k; spares 4.1k on rules [M] (row 8) | Ibex's pools are cheaper per op; the rules' spare traffic is a representation cost | nothing beyond R2/X2 | - |
| 15 | **Safety extras on by default** (zero-on-free, wipe, `crash::contain`, `watchdog` x3/pass, `fault_point`) | none | [E] 0.3-1k; X0 item 9 lists them | Ibex-only | user decision per item (fair benchmark defaults, §6 D-11) | X0 |

### 2.1 Measured (X0 appends here)

(unfilled: X0 has not run)

## 3. Target architecture

### 3.1 A request through the engine, after the overhaul

```
poller (epoll, one clock read)                  HAProxy: run_poll_loop / _do_poll
  -> readiness -> tasklet_wakeup(conn task, Urgent)
process_runnable_tasks (classes, budgets)       task.c:714 / sched.rs:637
  Urgent: connection task (h1: TcpSession; h2/h3: owner + mux)
     recv -> mux parses one message head -> HTX descriptors in the transport buffer (D-A)
     -> stream.wake(WOKEN_IO) [instant: same pass]
  Normal: Stream task
     run gated by wake reason + pending bits (L3)
     req analysers (compiled, once per phase): tcp-request content, http-request rules on HTX,
       backend choice (dense index), connect or take parked/idle server (O2)
     send: unmodified head = the received bytes; modified = h1 encoder once (X5)
  (server readable) -> stream.wake -> response head parsed in place (X3) -> http-response rules
     -> h1: passthrough or encode; h2/h3: mux writes HEADERS from blocks (X4 path)
     -> txn end: Stream::reset (h1) or Stream::finish + pool give (h2/h3); counters once (C1)
housekeeping: timer tasks only (L1)
```

Objects:

- **`TcpSession`** (h1): the connection, its buffers, its xprt, and **one `Stream` it reuses**
  across keep-alive. Owner (h2/h3): the connection, the mux, `Vec<Stream>` by stream id.
- **`Stream`** (O1): txn state (`MsgState` x2, flags, status, termination), `StreamLog`,
  txn/reqres vars, captures, backend side (server index, the server connection handle, retries,
  queue position), the scheduler task ref, timers (`expire`). Pooled (`ibex_alloc::Pool`, 1 KiB
  class), never zero-constructed on the path: a reset writes the dozen fields that change.
  HAProxy's `struct stream` (stream-t.h:243) is the model; what the session owns there
  (`vars_sess`, session stick counters, the frontend, the listener) stays on the connection.
- **Task per stream, tasklet per connection**: HAProxy's model, kept, because `timeout server`,
  `timeout http-request` and the queue timeouts are per stream and live in the wait queue
  keyed by task. The task stays 32 bytes (task.rs:184).
- **HTX in place** (D5 §2.1): descriptors in the transport buffer's reserve; the unmodified
  head is a passthrough; the h2/h3 request is built as blocks in the child's buffer layout.
- **Compiled rules**: `Rule { cond: Cond(terms of AclRef | Expr), action }` with `Expr { fetch:
  FetchFn, args: Box<[Arg]>, convs: Box<[(ConvFn, Box<[Arg]>)]>, matcher }` resolved at load;
  a `SampleContext` built once per phase from the `Stream` and the HTX views; `Sample<'a>`
  borrows. Actions edit blocks (`HtxSlice::set_header` etc.).
- **Mux interface** (`HtxMux`, h3-engine §2.4, now for h1 too): `take_req_head(&mut HtxLayout)`,
  `send_head(&HtxSliceRef)`, `send_interim`, body as the transport bytes (fast-forward always)
  with DATA blocks on demand (X6). h1's "mux" is the in-place parser + the encoder.

### 3.2 Where Ibex beats HAProxy, by design

| item | HAProxy pays | Ibex after the overhaul | rows |
|---|---|---|---|
| stream object per keep-alive request | `stream_new` + `stream_free` ~4.4k | reset of one pooled `Stream`, ~0.3k | 4 |
| server connection between requests | idle list give + take ~1k | parked on the session (`SRV_PARK_MS`) | 5 |
| head serialisation | `h1_make_*` both directions ~2.4k | passthrough when unmodified; one encode when modified | 6, 7 |
| head copy into HTX | `h1_headers_to_hdr_list` + `htx_add_all_headers` ~2.5k | descriptors over the received bytes (D-A) | 6 |
| TLS | OpenSSL ~7-8k (h2), ~15k crypto (h3) | rustls/ring 4.8k (h2), 3.9k (h3) | 11 |
| clock | 2 CPU-time syscalls a pass (kernel) | none | 12 |
| passes | 3 (a zero-timeout poll after a task wake) | 2 on h1, <= 3 on h2 (instant wakeup) | 2 |
| pools | 1.4-4.2k | 0 malloc, pool ops ~0.3k | 14 |
| dispatch | function pointers, 128 B tasks | monomorphised `Dispatch`, 32 B tasks | 2 |

Sum of the advantages: ~12-15k on h1, ~15-18k on h2 (TLS). That is the whole margin the 0.9x aim
rests on; §5 says how much of it the slices are expected to realise.

### 3.3 Where Ibex must copy HAProxy

- **State-gated stream processing**: `process_stream` runs only what its flags say (wake reason,
  `analysers` bits, `CF_*_EVENT`); Ibex's run re-derives rare conditions every time (L3).
- **Housekeeping from timers, not the pass** (L1).
- **Rules compiled to function pointers with parsed arguments; samples as views** (R1, R2).
- **Dense indices and per-thread lists for servers and idle connections** (O2).
- **A small stream object, pooled, with the connection-level state on the session** (O1).
- **The HTX layout** (D5, already decided).
- **Counters flushed once per stream** with the pass clock (C1).

### 3.4 What does not change

The class budgets and `RUNQUEUE_DEPTH` (sched.rs:14-38, HAProxy's numbers); `Outcome` as the
self-wake signal; `crash::contain` per stream run (T447; its cost is X0 item 9); the `Buf` pools
and `show pools` accounting (memory doc); the poller; the h1 I/O syscall pattern (already below
HAProxy's); the `tcp-request`/`tcp-response` rule engines (they move onto the compiled `Expr` with
R1 but their structure stays); the stats page, CLI, checks, resolvers, peers.

### 3.5 Locks and threads

Nothing in the four tracks adds a lock. O2 removes the `RwLock` read from the backend take; C1
leaves the shared `Relaxed` atomics (parity with HAProxy's per-tgroup counters) and removes the
cmpxchg loop. The instant wakeup (L2) is per thread: a wake for a task on another thread goes
through the mailbox as today. "The fast path writes nothing another thread reads" (AGENTS §8)
holds for every slice; the counter atomics are the documented exception on both sides.

### 3.6 h3, the quinn interface, and the ordering answer

The h3 mux shares `HtxMux` and the owner/stream model, so every engine saving lands on h3fit
(D1's ratios move with it). What changes for h3:

- **Stream object per request** (O1c): an h3 request is a `Stream` in the owner's `Vec`, not a
  `TcpSession` child (`spawn_h2_children` serves both today); `read_stream`/`write_stream` by
  `ConnectionHandle` (Q1) feed the stream's transport buffer directly.
- **HTX blocks**: the h3 mux writes the request blocks into the stream's layout (X4's path
  through `HtxMux`); the response goes from blocks to QPACK with the static index carried
  (`qpack::static_ref`, done).
- **Wakeup model**: the listener's `take_wake` wakes the owner; with L2 the owner's pass steps
  its ready streams in the same pass; `drive_connection` once per owner per pass (Q2 b1) is
  then the natural contract: one drive, one `poll_transmit` sweep, one `send_batch` per
  listener per pass.

| quinn slice | depends on the overhaul? | order |
|---|---|---|
| Q1 (glue by handle, slab, timers) | no (Ibex glue, `quic_listener.rs`/`endpoint.rs`) | **now** |
| Q2 mechanical half (option (a): `FrameStats`, `VarInt`, `PacketSpace::take`, `ArrayRangeSet`) | no (vendored quinn internals) | **now**, parallel |
| Q2 b1 (one drive + one `poll_transmit` per connection per pass) | **yes: L2** defines when the owner runs; doing b1 first would be redone | after L2 |
| Q4 (b2-b5: dirty flag, ACK-only skip, `SendBuffer.acks`, loss detection on advance) | no | any time, parallel |
| S4 (= Q2 + Q4 in the survey's naming) | as the two rows above | split as above |
| E3 for h3 (= O1c) | yes: O1b | after O1b |
| Q0/ACK frequency (D8, a setting) | no | done/independent |

The h3 track does not wait for the representation track; only b1 waits for L2 and O1c for O1b.

## 4. Tracks and slices

Rules for every slice: release-perf, `insreq.sh` on `keepalive ab1`, `rules ab1`, `h2s1`,
`h3fit` against the parent commit, slot A for claims (B for instruction counts only);
**kernel instructions counted and reported** (T568); **budget +0.5 % on every scenario the slice
does not name as its saving, user and kernel**; a slice that names a saving and does not measure
one is not merged (AGENTS §8); `request_allocations*.rs` at their pins; `./tools/checkin.sh`
green; the test that fails first is written and run red before the fix (AGENTS §1). No slice
adds a config keyword; none adds `unsafe`; none adds a dependency.

Sizes: S <= 1 day, M 2-3 days, L 4-6 days of agent time. Models: Opus where the slice changes
scheduler semantics, lifetimes across crates, or `engine.rs`'s dispatch chain; Sonnet where the
brief is mechanical and the test pins it.

### 4.1 Track X, representation (D5, revised)

X0 (extended, §1.2, Sonnet S), X1, X5, X2, X3, X4, X7, X6, X8 as `htx-engine-2026-11-01.md` §3,
with these changes:

- **X2** also: the request-phase `SampleContext` built once per rule run (not per rule) and
  the `tune.ibex.h1-lowercase-headers` passthrough leg (D-E, default off).
- **X3** also: the per-rule `SampleContext` clone retired (S7's "borrow"); the HPACK static
  `match` is **already done (Q3)**, so X3's h2 expectation drops to -1 to -2k.
- **X4** expectation unchanged (-2 to -3k on h2/h3); it is the prerequisite of O1b.
- **X0** produces §1.2's ten items, not only the representation rows.

### 4.2 Track L, loop and scheduler (survey S3)

| slice | goal | files | test that fails first | expected ins/req (reasoning) | size | depends | model |
|---|---|---|---|---|---|---|---|
| **L1** | housekeeping out of the pass: idle purge, buffer trim, stick-table expiry, `pool::pass`, the three `publish`es, accept-limit and CLI-retry checks become `Kind::Housekeeping` tasks on the wait queue (one per concern, HAProxy's `srv_cleanup_idle_conns`/`process_table_expire` model) run when their timer expires; QUIC admit/adopt/serve behind `!quic_listeners.is_empty()`; `EngineDispatcher` built once per `Engine` | `engine.rs` `step_at` 5923-6230, `sched.rs` (a task kind), `pool.rs` (`pass` from a task) | `crates/ibex-rt/tests/it/engine_pass.rs` (new module): `a_pass_with_nothing_due_does_no_housekeeping` — `#[cfg(debug_assertions)]` `work::Op::Housekeeping` counter 0 over 100 idle passes and 1 per timer period; red today (every pass). `show pools`/`show info` rows stay identical under the stats battery | **-0.3 to -0.8k on all three** (3-7 passes x 100-250); kernel 0 | M | - | Sonnet |
| **L2** | instant wakeup: `Dispatch` gets `wake_now(TaskRef)` which pushes to the current pass's tasklet list; `run_tasks_from_lists` drains what arrives while it runs (budget-bounded, as HAProxy's lists); the `last_run == loops` guard (sched.rs:703) allows a second run per pass and refuses a third; the owner<->child wakes (engine.rs:11212, `h2_owner_pass`'s `wake_queue`) and `wants_rerun` use it; `wake_queue` keeps only cross-pass uses (buffer waiters, mailbox) | `sched.rs` 637-740, `engine.rs` dispatcher (`wake_queue` sites), `h2_owner_pass` | `engine_pass.rs`: `an_h2_request_completes_in_three_passes` and `an_h1_keepalive_request_completes_in_two` — debug counter of `step_at` per request through a local h2load/ab run in the test harness (as `h2_per_request_work.rs` counts); red today (7 / to be measured by X0). `ibex-sched` unit tests: a task woken twice in a pass runs twice, a third wake waits; the Bulk demotion still applies to self-wakes | **h2 -3 to -5k** (4 fewer passes x ~0.9k: `step_at` + poll glue + `epoll_wait` user side); **keepalive -0.3 to -1k** if a third pass exists; **kernel: -4 `epoll_wait` per h2 request (a kernel saving)**; rules as keepalive | M | X0 (counts) | Opus |
| **L3** | the stream run gated by state: `step_stream_run` reads the wake reason (`WOKEN_TIMER` -> `check_timeouts`; `WOKEN_IO` -> clear the fired side's `cant_recv`), a `pending: u16` on `TcpSession` for the rare conditions (set where each arises: deferred session rules, tcp inspect x2, scrape, stick stores, glitches, park expiry, retry, connect-log, rate-max, srv handshake failure, checkcache), `stream_vars_enter/leave` and `stream_timeouts_enter` replaced by `&Proxy`/timeouts passed down (Q6: no `Arc` clone), `update_interests` only on a changed `(Want, Want)`, `req/rep.release()` at txn end | `engine.rs` 10889-11270, 7927-8000, 9485; `proxy.rs` (`pending`) | `engine_pass.rs`: `a_keepalive_stream_run_does_only_io_and_http` — `work::Op` counters for each rare check are 0 on a plain GET and 1 when the condition is set (deferred rule, inspect, scrape); red today. The timeout battery (T140-era `timeouts_*` modules) and `h2_per_request_work.rs` green; `Arc` strong count of the capture table constant across a request | **keepalive/rules -1.5 to -3k** (2-3 runs x 500-1000), **h2 -3 to -5k** (5-7 runs) | L | L2 (run counts), X0 | Opus |

### 4.3 Track O, stream objects and the backend side (survey S2 = E3)

| slice | goal | files | test that fails first | expected | size | depends | model |
|---|---|---|---|---|---|---|---|
| **O1a** | the `Stream` object: `txn`, `log`, txn/reqres vars, captures, backend side, task, timers out of `TcpSession` into a pooled `Stream` (`ibex_alloc::Pool`, 1 KiB class, counted in `show pools`); the h1 session holds one and **resets** it at txn end (`Stream::reset`: the fields that change, no `Default`); `end_txn` becomes reset + the connection-level decisions | `proxy.rs` 653-894 (`TcpSession` split), `txn.rs`, `txnlog.rs`, `engine.rs` `end_txn` 10476, `account_stream` | `crates/ibex-rt/tests/it/stream_object.rs` (new module): `a_keepalive_request_resets_its_stream_in_place` (debug counter: 0 `Stream` allocations and 0 `StreamLog` constructions per keep-alive request after the first; red today: `end_txn` rebuilds), `stream_is_at_most_1_kib` (`size_of` pin), the log-format battery (`%Tr`, `%Tw`, `%ST`, captures, vars) identical | **keepalive/rules -0.5 to -1.5k** (`end_txn` 2.7k -> ~1.2k); h2 0 (O1b) | L | X2 (the stream's buffers are the layout) | Opus |
| **O1b** | h2 children as `Stream`s: the owner holds `Vec<Stream>` by stream id with a task each; `h2_child_of`/`h2_child_done`/`spawn_h2_children` become `Stream::start`/`finish`; `h2_owner_pass` iterates its streams (no `sessions.get2_mut` per child per pass); `end_stream` for a child is `finish` + pool give | `engine.rs` 6237, 10607-10660, 11272; `h2_bridge.rs`; `proxy.rs` (`h2_owner`) | `stream_object.rs`: `an_h2_stream_is_not_a_session` (debug counter: 0 `TcpSession` constructions per h2 request; red today 1), `h2_per_request_work.rs` rows green, the h2 battery (T280, T409, GOAWAY/RST rows) green | **h2 -3 to -5k** (set-up 3.4k -> ~1k, tear-down 4.4k -> ~1.5k) | L | O1a, X4 (D-F) | Opus |
| **O1c** | h3 streams as `Stream`s: `step_h3_owner`'s children, `read_stream`/`write_stream` into the stream's layout (Q1's handle) | `engine.rs` `step_h3_owner`, `quic_listener.rs`, `mux_h3.rs` | `stream_object.rs`: the h3 row of the counter test; `h3_request_framing_to_backend.rs` green; h3fit measured | **h3fit -3 to -5k** | M | O1b, Q1 | Opus |
| **O2** | backend side without hashes or locks: servers by dense index (Q5: `engine.rs:170,179,369,427`), idle connections as per-thread per-server `Vec<IdleConn>` (own thread first, cross-thread take only on a miss, as `conn_backend_get`), `IdlePools::with_count` and the `RwLock` read gone from the take, `route_to_server`/`select_server` on the compiled backend (precomputed server list, no name compares) | `engine.rs` `connect_http_backend` 12840-13100, `route_to_server` 14016, `select_server` 2054, `IdlePool` 265-600 | `stream_object.rs`: `taking_an_idle_connection_takes_no_lock_and_hashes_nothing` (debug counters on the lock and on `IdleKey` hashing; red today), `http_reuse_*` rows (safe/aggressive/always, the 64-thread `vtc` port at `engine.rs:1036`) green | **h2 -2 to -4k** (`connect_http_backend` 7.2k -> ~3k); keepalive/rules ~0 (parked); kernel 0 | M | - | Sonnet |

### 4.4 Track R, rules

| slice | goal | files | test that fails first | expected | size | depends | model |
|---|---|---|---|---|---|---|---|
| **R1** | compiled dispatch: `Expr::parse` resolves `fetch_name` to `FetchFn` (+ `MultiFetchFn`/`VisitFetchFn`), parses args into `Arg` (lowercase header name bytes, int, regex, var name, table ref), resolves converters to `ConvFn`; `Registry::eval_g`/`any_acl`/`eval_all_g` take the compiled form; the by-name entry points stay for the CLI and tests only. Covers `tcp-request`/`tcp-response`, `use_backend`, `stick`, `log-format %[...]`, `track-sc` (the "Expr::cached" remainder) | `crates/ibex-sample/src/expr.rs`, `registry.rs` 1290-1330, `rule_compiled.rs`, `logfmt.rs` | `crates/ibex-sample/tests/it/compiled_expr.rs` (new module): `evaluating_a_compiled_expression_looks_up_no_name` (debug counter on `fetches.get`/`converters.get`: 0 per eval; red today 1 per fetch), the fetch/converter batteries (T80, T81) green through the compiled path | **rules -1.5 to -3k** (8 lookups x 200-350: SipHash on the name + `&[String]` arg handling); keepalive/h2 0 | M | - | Sonnet |
| **R2** | borrowed samples: `Sample<'a>` with `Str(Cow<'a, [u8]>)`/`Bin(Cow<'a, [u8]>)` views into the HTX block for header, path, method, query, cookie fetches (HAProxy's `SMP_F_CONST`); owned bytes only after a converter produces new ones; `str` validated once at the fetch (D-B, tradeoff 6.12 kept); `spare::string_from` off the fetch path | `ibex-sample` (`sample.rs`, the ~1,200 lines of fetches, `matcher.rs`), `rule_compiled.rs`, the 290 test sites tradeoff 6.12 counted | `compiled_expr.rs`: `a_header_acl_takes_no_spare_string` (spare counter 0 for `hdr(host) -m sub` and `path_reg`; red today), `request_allocations*.rs` pins | **rules -2.5 to -4k** (spares 3-4k [M]); 0 elsewhere | L | X2 (the HTX views), R1 | Opus |
| **R4** | vars and format scratch in the `Stream`: `set-var(txn.*)` into the stream's var slots (no 4 KiB `VarStore` spare take/give per txn), `%[rand]`/log-format fragments rendered into a stream scratch `[u8; 256]` with overflow to a pool buffer | `vars.rs`, `logfmt.rs`, `txn.rs` | `stream_object.rs`: `set_var_takes_no_spare` (counter; red today) | **rules -0.5 to -1k** | S | O1a | Sonnet |

### 4.5 Track IO and C, send/recv and accounting

| slice | goal | files | test that fails first | expected | size | depends | model |
|---|---|---|---|---|---|---|---|
| **IO1** | the h1 I/O state machine: `advance` driven by the poller's readiness bits (no `interests` recompute unless changed), `MsgState` advanced by what the parser returned (no re-derivation per run), the buffer kept while the txn is open (`release` at txn end), `Buf` accessors without the `nominal` indirection; written from X0 item 4 | `proxy.rs` 2489-2700, 3471-3800, `buf.rs`, `txn.rs` (`MsgState`) | `engine_pass.rs`: `a_keepalive_request_takes_its_buffers_once` (buffer take/give counter: 2 per request, red today: per run), the I/O batteries (half-close T88, pipelining, `timeout http-keep-alive`) green | **keepalive/rules -1 to -2k**, h2 -0.5 to -1k | M | X0 | Opus |
| **C1** | accounting once: Q6 (`TimeStat::add` load + store-if-greater, `Arc` borrows), `account_stream` from the pass clock (no `now_ms` read), one `count_status`, `StreamLog` fields only when a log target exists (X0 item 10), `RateCtr` ticks from the pass | `statcnt.rs`, `engine.rs` 3349-3480, `txnlog.rs` | `engine_pass.rs`: `accounting_a_request_does_at_most_n_atomic_rmws` (pin n from X0 item 5; red at today's count), `show stat`/`show info` rows identical under the stats battery | **-0.5 to -1.2k on all three** | S | X0 | Sonnet |
| **C2** | clock residue: `%t`/`%Tl` from the pass clock (HAProxy's `date`), ticks as the pass's `u32` ms, `Duration::as_millis`/`Timespec` conversions off the path | `txnlog.rs`, `tick.rs`, `engine.rs` `tick_at` | `engine_pass.rs`: `a_request_reads_the_clock_at_most_twice_per_pass` (counter; X0 item 8 sets red) | **-0.3 to -0.8k on all three** | S | X0 | Sonnet |

### 4.6 Order, critical path, parallelism

Two gate slots and two measure slots (A: claims; B: counts). Every slice merges alone and is
measured on the four scenarios against its parent.

```
week 1   X0 (B)         | R1 (Sonnet)   | O2 (Sonnet)   | L1 (Sonnet)      | Q1 (h3, Opus)
week 2   X1 || X5 (Opus)| L2 (Opus)     | C1, C2 (S)    | Q2a, Q4 (h3)
week 3   X2 || X3 (Opus)| L3 (Opus)     | IO1 (Opus)    |
week 4   X4 (Opus)      | R2 (Opus)     | O1a (Opus)    | X7 (Sonnet)
week 5   O1b (Opus)     | R4 (Sonnet)   | X6, X8 (S)    | Q2 b1 (h3)
week 6   O1c (Opus)     | re-measure (the landing table)
```

Critical path: **X0 -> X1/X5 -> X2 -> X4 -> O1a -> O1b -> O1c** (~4-5 weeks). Parallel: L1, L2,
L3 (engine.rs `step_at`/`step_stream_run` regions, disjoint from X2's rules region and O2's
backend region; the later merge rebases), R1 (ibex-sample), O2, C1, C2. At most two Opus L
slices in flight at once (the gate slots), Sonnet S/M beside them. The h3 track's Q1/Q2a/Q4 run
in the h3 slot of the week and do not touch these files.

## 5. Expected landing

Per scenario, user-space instructions per request, non-PGO release-perf. Ranges are each
slice's §4 range; **the sums overlap and are read at +-30 %**, as in D5. Kernel: every slice
must hold kernel at or below its parent; L2 lowers it on h2.

| scenario | today | after X (D5) | after L | after O | after R | after IO/C | **landing** | HAProxy | ratio |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| keepalive ab1 | 45.8k | 44.3-45.8 | 42.2-44.4 | 41.0-43.8 | 41.0-43.8 | **38.7-41.9** (opt. 35) | **35-42k** | 36.2k | **0.96-1.16x**, central ~1.05x |
| rules ab1 | 75.7k | 62.7-65.7 | 58.4-63.8 | 56.5-62.9 | 51.5-58.9 | **49.2-56.5** (opt. 45) | **45-57k** | 43.8k | **1.03-1.30x**, central ~1.15x |
| h2s1 | ~70k | 64-67 | 54-61 | 46-54 | 46-54 | **44-52** (opt. 41) | **41-54k** | ~54k | **0.75-1.0x**, central ~0.9x |
| h3fit (for D1) | 98.4k | 91-94 | 83-89 | 75-83 | 75-83 | 73-81 | **70-81k** + Q1/Q2/Q4 (-10 to -17k) | 73.7k (dev10) | ~1.0x after both programmes |

Reading: **h2s1 meets the target** (the pass count, the child object, the backend take, and the
TLS advantage). **keepalive meets it only at the optimistic end**: the slices name ~7.5k central
of the 9.6k gap; the remainder is what X0 must find (the candidates: the I/O state machine
beyond IO1's estimate, the response scan family after E2, the safety extras, death by a thousand
cuts). **rules lands at ~1.15x**: its 1.0x needs the keepalive base at parity *and* a per-rule
cost at HAProxy's ~1k (X2's block edits at ~200 instr an action, R2's views at the top of the
range); the honest first target for rules is **<= 1.1x** (§6 D-10).

What would make 1.0x unreachable on keepalive: (a) X0 shows the remaining gap spread over 50+
sites of 100-200 instructions each (bounds checks, `Option` re-matching, enum state
re-derivation): no slice collects that, only PGO (-13 %, T435) does, and PGO is outside the A/B
(D9); (b) the safety extras the user keeps on by default cost more than the margin (X0 item 9);
(c) `crash::contain` per run turns out to cost more than ~0.3k (then it is a `tune.ibex.*`
setting, default on, and the A/B is reported both ways under "fair benchmark defaults").

## 6. Risks, stop rules, decisions

**Risks.**
1. **L2 semantics**: a task running twice in a pass can starve the pass if it self-wakes
   through `wake_now`; the class budget bounds it, and a third wake waits. A regression here
   shows as latency under `m1_latency.py`, not as instructions: L2 runs the latency board too.
2. **L3's gating** misses a rare condition (a deferred rule not run, a scrape not pumped): the
   `pending` bits are set at the condition's source and the test counts each; the behaviour
   batteries (timeouts, inspect, scrape) are the net. Model Opus for this reason.
3. **O1's split** of `TcpSession` touches every log/counter/stick-key site (what the child
   copies today). The log-format battery and the `show stat` rows are the specification; the
   `size_of` pin stops the object regrowing.
4. **R2's lifetimes** across `ibex-sample`: 290 test sites; a `Cow` that is always `Owned` would
   measure as nothing: the spare counter test is what proves the view.
5. **Merge contention in `engine.rs`**: three tracks edit it in different regions; the second to
   merge rebases; no two Opus L slices touching `step_stream_run` run at once.
6. **Estimates without an h1 profile**: §2's h1 rows are reasoned; X0 may move any of them by
   2x. The slice designs hold either way; their budgets are set after X0.

**Stop rules.** Stop a slice that measures outside its named range on its target scenario and
cannot say why (no "should be cheaper"); stop L2 if the latency board moves > 5 % at p99; stop
O1a if the `Stream` cannot be kept under 1 KiB without losing a logged field; stop R2 if the
spare counter cannot reach 0 on `hdr`/`path` within the slice (then R2 ships the fetches it
converted and reports the rest); do not weaken a `tools/checkin.sha256` test to pass (report it).

**Decisions for the user**, each with the recommendation:

| | question | recommendation |
|---|---|---|
| **D-1** | Four tracks (X, L, O, R + IO/C) in parallel with two gate slots and the h3 track, ~6 weeks, 9 Opus (5 L) + 9 Sonnet slices | **Approve**; the critical path is X's, the others fill the second slot |
| **D-2** | L2's instant wakeup: adopt HAProxy's `task_instant_wakeup` semantics (a task may run twice per pass, budget-bounded) even though HAProxy's own stream path does not use it | **Yes**: it is where Ibex goes below HAProxy's pass count; the scheduler's budgets keep fairness |
| **D-3** | O1: one scheduler task per stream (HAProxy's model; per-stream timers in the wait queue) rather than one task per connection stepping streams inline | **Task per stream**; the connection's I/O stays in the owner's tasklet |
| **D-4** | C1: keep shared `Relaxed` atomics for counters (parity with HAProxy's per-tgroup counters) rather than per-thread rows | **Keep shared**: per-thread rows cost 128 MB at 10k servers x 64 threads; the gain is ~0.5k |
| **D-5** | R2's `Sample<'a>` API change across `ibex-sample` (L, Opus) for ~3k on rules | **Yes, after X2**; without it rules stays >= 1.2x |
| **D-6** | O1a after X2 (not after X4, which D-F set for E3 as a whole): the h1 reset does not depend on the h2 child's buffers | **Yes**; O1b keeps D-F's "after X4" |
| **D-7** | quinn: Q1 and Q2's mechanical half now, Q4 in parallel, Q2 b1 after L2, O1c after O1b | **Yes** (§3.6) |
| **D-8** | PGO stays outside the A/B (D9 unchanged); the landing table is non-PGO | **Unchanged**; report the PGO figure as "shipped" beside it |
| **D-9** | Safety extras on by default (X0 item 9): each becomes a `tune.ibex.*` setting whose cost is reported, with the user ruling per item under "fair benchmark defaults" | **Decide after X0**; `crash::contain` stays on unless it costs > 0.3k |
| **D-10** | Restate the target per scenario: keepalive <= 1.0x, h2s1 <= 1.0x (aim 0.9x), rules <= 1.1x first landing with 1.0x the stretch after R2/X2 measure | **Yes**: rules carries HAProxy's own ~1k-a-rule floor plus the base |
| **D-11** | X0's extended scope (§1.2, ten items, both proxies, three scenarios + h3fit): ~1 day Sonnet on a quiet host, before any L/O/C slice sets its budget | **Approve now**; it is the only measurement the programme waits for |

**Earlier decisions touched.** D1 (h3 ratios): unchanged, h3 gains from every engine slice.
D5 (HTX-primary plan first): this document is the superset; D5's slices stand. D-A..D-H:
unchanged (D-E's setting is built in X5/X2 as decided; D-F refined by D-6 above). D9 (PGO outside
the A/B): unchanged. Fair benchmark defaults: applied through D-9. `tune.ibex.*` for a security
trade: no slice trades security; L3's timer gating fires timers through the wait queue exactly as
HAProxy. Memory-safety-only dependencies: none added. `unsafe`: none added. AGENTS §8 (pools,
no cross-thread writes on the fast path): O1's `Stream` is an `ibex_alloc::Pool`; O2 removes a
lock from the path; every slice reports its ins/req before and after, user and kernel.

### 6.1 User decisions, 2026-11-01 (16:05)

- **D-1, D-2, D-3, D-5, D-6, D-7, D-8, D-11**: approved as recommended.
- **D-4: both.** Shared `Relaxed` atomics stay the default. Per-thread (or per-thread-group)
  counter rows become an operator setting (`tune.ibex.*`) for CPU-bound deployments that can pay
  the memory. This is the programme's first explicit memory-versus-CPU trade: C1 gets a short
  design first (the setting, memory cost per server x thread, how `show stat`/`show info` sum the
  rows). The shared default is a recorded exception to AGENTS §8 ("the fast path writes nothing
  another thread reads") until that setting exists.
- **D-9**: decided after X0, per safety extra.
- **D-10: accepted.** keepalive <= 1.0x, h2s1 <= 1.0x (aim 0.9x), rules <= 1.1x for the first
  landing; 1.0x on rules is the stretch after R2/X2 measure.
- **Soaks**: postponed until most slices are in (not after each of L2/L3/O1a/O1b).
- **Fable after X0**: one pass rewrites §2.1 and each slice's budget from X0's figures, and adds
  a slice for any keep-alive remainder X0 locates.
