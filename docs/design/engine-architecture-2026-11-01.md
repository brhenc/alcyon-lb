# The engine at parity with HAProxy: loop, streams, rules, representation (2026-11-01)

Status: design, no production code. Written for the user's goal of 2026-11-01 ("aim for better
performance than haproxy at least for h1 and maybe h2 ... the design isn't matching haproxy and
we are still leaving performance on the table"). No measurement was run for this document (the
host was in use); every number names its record. Oracle: `~/reference/haproxy` (3.5-dev8,
88576119c), line numbers as of 2026-11-01.

**Re-budgeted after X0 (2026-11-01 evening, §6.2).** §0 and §2 keep the pre-X0 reasoning and the
figures they were written with; §2.1 holds the measurements; **§4, §4.6, §5 and §6 are the
re-budget** and supersede the ranges quoted in §0 (landing, cost, critical path).

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

### 2.1 Measured (X0, 2026-11-01)

Main e83cd302, release-perf (plain build for the totals, `-C force-frame-pointers=yes` build for
the profiles), quiet CPUs (4-6 and 12-14 idle, governor `performance`, no `wwm.exe`; other
sessions were compiling on other cores, load 7-21). HAProxy dev8 (dev10 for h3). Raw data,
folded stacks, scripts: `~/ibex-worktrees/review/x0-2026-11-01/` (`insreq/`, `calls/`, `calls2/`,
`tp/`, `strace/`, `prof/`, `clk/`, `h3/`, `scripts/`). The scenarios are `keepalive ab1` and `rules
ab1` (the bodies in `tools/measure/scenarios/`) and `h2s1` on a copy of `h3.body` without the
`quic4@` bind (`scripts/h2.body`).

**How to read the profile columns.** Ibex: IBS (`ibs_op/cnt_ctl=1,swfilt=1/u`), frame pointers,
inlines expanded (`fold2.py`); samples on the `syscall` instruction (24-28 % of the samples) are
dropped and the rest scaled to the `insreq.sh` user total of the same run (T544's convention).
HAProxy: `instructions:u -c 100003 --call-graph dwarf`, with the same two drops (`__syscall_cancel_arch_end`
and the `clock_gettime` wrapper hold 8.0k + 4.8k a request of skid on keepalive) and the same scaling.
Read each row as +-15 %; two tools, two skids. A "k" below is 1,000 instructions a request.

**Totals** (`insreq.sh`, 5 rounds x 20,000 requests, min-total round; h3fit 5 rounds x 5,000, user
only):

| scenario | Ibex user | Ibex kernel | HAProxy user | HAProxy kernel | ratio user | Ibex passes/req | HAProxy passes/req |
|---|---:|---:|---:|---:|---:|---:|---:|
| keepalive ab1 | 45,900 | 65,892 | 36,230 | 69,698 | 1.27x | 2.00 | 2.00 |
| rules ab1 | 75,719 | 66,143 | 43,830 | 69,570 | 1.73x | 2.00 | 2.00 |
| h2s1 | 71,593 | 69,229 | 53,171 | 76,262 | 1.35x | **6.0-8.0** | 3.00 |
| h3fit (1.97 dg/req) | 98,882 | n/a | 64,037 (dev10) | n/a | 1.54x | 7.1 (best) / 8.1 (worst) | 3.0 / 5.1 |

HAProxy dev10's h3fit is 64.0k here against 73.7k in D6 and the table of §5: dev10 was rebuilt on
10-31 (memory: "dev10 since 18:17"); the ratio for the h3 row of §5 must be re-read from this
table. Kernel: Ibex is **3.8k (keepalive), 3.4k (rules), 7.0k (h2s1) below HAProxy**, i.e. the
kernel side is already past parity; every slice's "kernel <= parent" rule is the right one.
HAProxy's keepalive user total is 36.2k here (33.3k in the htx doc's record from
`memory-2026-10-24.md`: older build/oracle), so the keepalive gap is **9.7k**, not 12.6k.

**Passes: the T544 contradiction (7.15 `Engine::step` vs 3.07 `epoll_wait`) is the observer.**
Every `step_at` makes exactly one `epoll_wait`. Measured with the tracepoint alone
(`perf stat -e syscalls:sys_enter_epoll_wait`, the least intrusive observer): **7.99 a request**
on h2s1. With four uprobes and the tracepoint 7.998 (`step_at` 7.998); with 23 uprobes 6.0; under
`strace -f` **3.03** (strace slows every syscall, the client's frames and the proxy's own wakes
land in the same `epoll_wait`, so the pass count falls to HAProxy's). T544's 3.07 was the strace
census, its 7.15 the uprobe run. The undisturbed figure is about **8**, and it varies with the
timing of the client (6.0-8.0 over my runs); HAProxy is 3.00 under every observer. keepalive is 2.00
under every observer, both proxies. Task runs a request (`Dispatch::run`, uprobes, 6-pass runs):
Ibex 2.0 / 2.0 / 9.0 (`step_stream_run` the same; `h2_owner_mut` 10.0, `advance` 12.0, `wake_queued`
12.0, `update_interests` 9.0 on h2s1), HAProxy `process_stream` 2 / 2 / 2, `h1_io_cb` 2 / 2 / 1,
`h2_io_cb` 0 / 0 / 3, `sc_conn_io_cb` 3 / 3 / 3, `run_tasks_from_lists` 5.0 / - / 7.0 calls of
`t->process` (HAProxy h2: 7 task runs, 3 passes; Ibex: 9 runs in 6-8 passes). Ibex's h2s1 pass
costs 1.05k outside the tasks (below), so **each pass L2 removes is worth ~1k**.

**Syscalls a request** (tracepoints, 5,000 requests; `strace -c` over 2,000 in `strace/` agrees
except for `epoll_wait` on h2s1):

| syscall | keepalive Ibex / HAProxy | rules Ibex / HAProxy | h2s1 Ibex / HAProxy |
|---|---:|---:|---:|
| `epoll_wait` | 2.00 / 2.00 | 2.00 / 2.00 | **7.99 / 3.00** |
| `read` / `recvmsg` | 2.00 / 2.00 | 2.00 / 2.00 | 2.00 / **4.00** (1 EAGAIN each) |
| `write` / `sendmsg` | 2.00 / 2.00 | 2.00 / 2.00 | 2.00 / 2.00 |
| `clock_gettime` (real syscall, `CLOCK_THREAD_CPUTIME_ID`) | 0 / **4.00** | 0 / **4.00** | 0 / **6.00** |
| all syscalls | 6.01 / 10.01 | 6.01 / 10.01 | 12.01 / 15.01 |

Ibex has fewer syscalls on all three and fewer kernel instructions; the 5 extra `epoll_wait` of
h2s1 cost less in the kernel than HAProxy's 2 `recvmsg` EAGAIN, 6 CPU-time syscalls and the rest.

**Clock reads** (uprobe on libc `clock_gettime` with a call chain, `clk/`): Ibex keepalive **5.0**
(4 `Instant::now`: two a pass, `run_loop` and `step_at`; 1 `SystemTime::now`, `StreamLog::start`
from `reset_for_next_request`), rules **6.0** (+1 `SystemTime::now` inside a fetch, closure #214,
`eval_g`), h2s1 **14-16.6** (2 a pass x 6-8 passes, +2 `StreamLog::start`). Q2 holds: two a pass.
Cost, inclusive: `Instant::now` 0.55k / 0.53k / 2.58k, `SystemTime::now` 0.30k / 0.27k / 0.34k,
the vDSO leaf alone 0.51k / 0.37k / 1.83k (**1.8 % / 1.1 % / 4.1 %** of the user total). HAProxy:
8 / 8 / 12 `clock_gettime` calls a request, half of them real syscalls.

**Rows of the §2 table, measured** (user instructions a request, keepalive / rules / h2s1; Ibex
inclusive unless "self"; HAProxy inclusive, skid-dropped; the full tables are `prof/*.tab`,
`ibex-rows.txt`, `hap-rows.txt`):

| # | component | HAProxy | Ibex | against §2's estimate |
|---|---|---|---|---|
| 1 | loop pass, outside the tasks | `run_poll_loop` less `process_runnable_tasks`: 1.34k / 1.30k / 1.17k = **0.67k / 0.65k / 0.39k a pass** | `run_loop` less `run_tasks_from_lists`: 2.93k / 2.09k / ~8.4k (h2s1: `step_at` less its tasks and `spawn_h2_children`, plus `run_loop`'s own) = **1.47k / 1.05k / 1.05k a pass**; `step_at` self 0.39k / 0.31k / 1.17k; `wake_expired_tasks` 0.23 / 0.13 / 0.92, `Instant::now` 0.55 / 0.53 / 2.58 (two a pass), `trim_idle` 0.14 / 0.14 / 0.43, `publish` x3 0.04 / 0.01 / 0.32, `pool::pass` 0.01 / 0.01 / 0.09, `purge` 0.07 / 0.01 / 0.10, `watchdog` 0.04 / 0.10 / 0.11 | §2 said ~250 a pass of pure loop: measured **1.05-1.5k** including the clock, the timer queue, `epoll_wait`'s user side and event decode. Housekeeping calls alone are 0.35k / 0.2k / 1.0k a request (the 100-250 a pass of L1). |
| 2 | passes, task runs | 2 / 2 / 3 passes; 5 / - / 7 runs | 2 / 2 / **6-8** passes; 2 / 2 / 9 runs | h2s1 is 8 passes (not 3.07, not 7.15); keepalive has no excess pass. |
| 3 | stream run, fixed | `process_stream` self 1.98k / 2.1k / 2.7k for 2 runs = **~1.0-1.3k a run**; `process_runnable_tasks` + `run_tasks_from_lists` self 1.5k / 1.6k / 2.0k | `Dispatch::run` .. `step_stream` shell 0.48k a run + `step_stream_run` self 0.27k a run + its other children (`update_interests` 0.35k, `next_expiry`, `is_done`, `wants_rerun`, ...) = **~1.5k a run** keepalive; h2s1 (`step_stream_run` self 1.57k, `update_interests` 1.50k, `Buf::release` 0.80k, `next_expiry` 0.22k, shell 2.3k over 9 runs) = **~0.95k a run** | §2 said 500-800 a run: keepalive is above it; L3's target of 150 is right. |
| 4 | stream set-up and tear-down | `stream_new` 3.2k / 2.6k / 1.6k + `stream_free` 4.2k / 4.4k / 4.0k = **7.4k / 7.0k / 5.6k** | keepalive: `end_txn` 1.70k (`reset_for_next_request` 0.97k, `IdlePool::note_used` 0.33k); rules 2.04k; h2s1: `h2_child_of` 2.03k (`new_with_mode` 0.80k) + `end_txn` 2.47k + `end_stream` 2.60k (`h2_child_released` 1.42k) = **7.1k** | the Ibex h1 model is **5.7k cheaper than HAProxy** per request; on h2s1 Ibex is 1.5k *dearer* (7.1k against 5.6k). `end_txn` is 1.7k on h1, not 2.7k. |
| 5 | backend selection and reuse | `connect_server` 1.9k / 1.9k / 1.8k incl `assign_server` 1.1k, `conn_backend_get` 0.2k, `srv_add_to_idle_list` 0.5k, `stream_set_backend` 0.3k, `back_try_conn_req` 2.1k incl | `connect_http_backend` 12.9k / 33.4k / 6.4k incl; **without the request rules and the `Connection` rewrite** (below): 7.4k keepalive; `route_to_server` 1.86k / 3.89k / 2.55k (`select_server` 0.94k / 2.83k / 1.38k, `IdlePools` 0.33k / 0.59k / 0.78k) | h2s1's 6.4k (7.2k at T544) is the O2 base; the lock/hash rows (`IdlePools`) are 0.8k on h2s1 and 0.3k on keepalive: a small share. |
| 6 | h1 parse | `h1_parse_msg_hdrs` 2.4k + `h1_headers_to_hdr_list` 0.6k + `htx_*`/`__htx_*` 1.9k = **~4.9k per head** | request: `validate_request_head` **10.06k / 9.34k** (`H1Parser::parse` 7.51k / 6.78k, of which `parse_headers` 5.86k, `parse_start_line` 1.14k; `from_utf8` 0.67k) + `req_htx_init` 0.59k / 1.45k; response: `check_response_head` 1.1k, `HeadFacts::of_response` 1.2k, `RspHead` 0.2k | **parse is 2x HAProxy** (7.5k vs 3.0k for the header parse alone): hot leaves are `memchr` 3.5k self, `eq_ignore_ascii_case` 1.1k, `to_ascii_lowercase`/`is_ascii_uppercase` 1.25k, `ascii_word_spans` 1.1k, `from_utf8` 0.55k. X2/X3's 3.5k target is right. |
| 7 | representation through rules | see `htx-engine-2026-11-01.md` §1.3 | | |
| 8 | rules (rules ab1) | 7.6k for the scenario: `http_req_get_intercept_rule` 7.3k incl (`acl_exec_cond` 2.1k incl, `pattern_exec_match` 1.55k, `sample_process` 0.72k, `http_add_header` 0.9k), `http_res_get_intercept_rule` 1.3k | **29.8k**: request rules (`connect_http_backend::{closure#16}`) **16.9k**, response rules `apply_http_response_rules_in` +9.7k over keepalive's; per request: **3 fetch-function bodies** (closure #19 x2, #214 x1), `apply_converters_g` 3, `render_rule_format` 2, `req_rule_header` 2, `write_req_head` **2**, `vars::with_stream` 1, `from_utf8` **39** (22 on keepalive: +17 for the rules), `spare::*` pool misses 0 (the take/give itself is 2.26k incl), `VarStore`/`vars::` 1.31k, `SampleContext` constructions 2.11k incl, `Expr::eval` 3.75k, `any_acl` 2.26k, `eval_g` 1.33k, `Matcher` (regex) 1.1k, converters 1.88k | the hash lookup is not the cost: `eval_g` is 1.33k for 3 fetches (~0.44k a fetch), `fetches.get` itself is not separable (inlined; 3 calls a request). The rules cost sits in the per-rule representation (rebuild 3.0k, spares 2.3k, contexts 2.1k, `from_utf8` 1.7k, header edits 1.75k). |
| 9 | send/recv, I/O state machine, self | `sc_conn_recv` self 0.8k, `sc_conn_send` self 0.22k, `h1_send` self 0.23k, `h1_snd_buf` self 1.5k, `h1_rcv_buf` 0.18k, `h1_process_demux` self 1.16k = ~4.1k | `process_cli_io` self 0.88k, `process_srv*` 0.03k, `advance` self 0.05k, `MsgState::advance_counted` 0.49k, `interests` 0.05k, `update_interests` 0.07k, `Buf::nominal` 0.18k, `Buf::readable` 0.28k, `release_idle_buffers` 0.01k (0.34k incl) = **~2.1k** (h2s1: 3.0k with `advance_counted` 0.85k, `update_interests` 0.21k, `Buf::release` 0.8k incl) | the I/O state machine's *self* is not the gap (HAProxy's equivalents are larger); IO1's gain is the walk it avoids. |
| 10 | h2 framing + HPACK | `h2_*` 24.4k incl; `h2c_dec_hdrs` 3.2k, `h2_make_htx_request` 2.6k, `h2s_snd_fhdrs` 0.6k | `MuxH2` 6.2k incl, `hpack` 3.1k incl, `start_request` 8.7k incl (incl. `put_request_head` 3.9k, `process_decoded_block` 5.3k), `forward_response` 1.3k | the bridge, not the mux, is the cost: `start_request` 8.7k. |
| 11 | TLS (h2s1) | `SSL_read` 5.6k + `SSL_write` 7.5k = 13.1k incl (skid-shares) | `rustls` 3.6k + `ring` 3.5k + `ibex_tls` glue 3.9k incl (partly overlapping) | Ibex advantage stands. |
| 12 | clock and timers | see "Clock reads" above | | C2 stands. |
| 13 | counters, accounting, logs | `stream_process_counters` 0.25k + `stream_update_time_stats` 0.15-0.26k = **0.45-0.64k** | keepalive: `statcnt` 0.20k, `atomic_umax` 0.08k, `StreamLog`/`txnlog` 0.47k / 0.54k (incl. a `SystemTime::now` 0.30k), `end_txn` self 0.17k = **~0.9k**; rules ~1.0k; h2s1: `statcnt` 0.46k, `account_stream` 0.48k, `set_stream_log` 0.86k (`StreamLog` 0.78k), `end_stream` self 0.15k = **~2.0k** | §2 said ~3k: **0.9k keepalive, 2.0k h2s1**. |
| 14 | pools and malloc | `__pool_alloc` 1.1k / 1.6k / 1.3k + `__pool_free` 0.5k / 0.75k / 0.63k + `pool_put_to_cache` 0.5k = **~2.1k / 2.9k / 2.2k** | pool take/give 0.13k / 1.84k (rules) / 0.67k; 0 malloc | Ibex advantage 2k on keepalive. |
| 15 | safety extras on by default | none | below | below |

**Safety extras (item 9), one row each, user instructions a request, keepalive / rules / h2s1:**

| extra | state in release-perf | cost |
|---|---|---:|
| `crash::contain` (thread-local set/clear + `catch_unwind` landing pad), once per task run | on | **0.03k / 0.13k / 0.08k** (self; `catch_unwind` is zero-cost when nothing panics). Below the 0.3k at which §5 (c) would move it to a setting. |
| `watchdog::progress` / `sleeping` / `set_streams`, 3 a pass | on | 0.04k / 0.10k / 0.11k |
| buffer wipe (`tune.ibex.zero-buffers`) | **default off**: `ibex_alloc::wipe` is an atomic load | 0.03k / 0.05k / 0.05k |
| TLS record wipe (`tune.ibex.ssl-zero-buffers`) | on | h2s1: a memset under `Encrypting::encrypt_records` 0.12k (probably the wipe; the call chain does not say) |
| `fault_point` | **compiled out** (`#[cfg(debug_assertions)]`, crash.rs:101) | 0 |
| `StreamLog`/`set_stream_log` with no `log` target (item 10) | on | **0.47k / 0.45k / 0.78k**, 1.0-1.1 % of the total; see below |
| `Pool`/guard bookkeeping | on | not a safety extra; `Guard` 0.14k / 0.25k / 0.21k |
| **sum of the first five** | | **0.1k - 0.35k, 0.2-0.4 % of the user total** |

**Item 10: `set_stream_log`/`StreamLog` does work with no log target.** `StreamLog::start/restart`
runs once per request (twice on h2s1) and reads `SystemTime::now()` (0.30k of its 0.47k on
keepalive); `set_stream_log` is 0.01k on keepalive (the `StreamLog` is only restarted) but 0.27k
on rules and 0.86k on h2s1 (it builds the log's fields and the capture state). HAProxy's
`strm_log` costs 0 when no `log` target exists. This is the C1 slice's "fields only when a log
target exists".

**Where the keepalive remainder goes (the ~2k of the 9.6k that §5 says no slice names).** The
measured gap is 9.7k. Its largest single item is not in any slice list: **the `Connection`-header
path, 8.1k on Ibex against ~0.5k on HAProxy**. `ab -k` sends HTTP/1.0 with `Connection:
Keep-Alive`, and Ibex does this per request: `strip_request_connection` 2.29k (`with_htx_mut` 0.6k,
`and_then` 0.55k, `is_some_and` 0.66k), `rewrite_request_connection` **5.50k** (of which
`write_req_head` 3.08k, plus a **`memset` 1.14k** attributed to
`rewrite_request_connection` itself: the 8 KiB stack zeroing of the head rebuild, inlined
(htx doc §1.1); `add_req_header` 0.33k, `Buf::eoh` re-scans 0.21k), `inject_connection_token_zero_alloc` 0.38k +
a `memset` 0.31k on the response. HAProxy sets two connection-mode flags at parse
(`h1_set_srv_conn_mode` + `h1_set_cli_conn_mode` 0.28k) and emits the token in `h1_make_headers`. Only
`write_req_head`'s 3.1k is arguably inside X2's "descriptors in place"; the other **~5k** (the
strip, the memset, the re-scans) is named nowhere. That is the remainder, and it is larger than 2k.
It applies to HTTP/1.0 keep-alive clients (ab, some monitors); an HTTP/1.1 client takes the
`scan.count == 0` fast path. **Proposed slice K1** (S, Sonnet): HTTP/1.0 `Connection: keep-alive`
handled by flags at parse (HAProxy's `H1_MF_CONN_KAL`/`H1_MF_CLEAN_CONN_HDR`), no head rewrite,
no memset; expected **-4 to -6k on keepalive ab1 and rules ab1**, 0 on h2s1/h3. The rest of the
9.7k, by bucket (+-15 %, buckets overlap by <1k): request parse + facts + HTX `validate_request_head`
etc. **+5k** (X2/X3: named); response head after the server `apply_http_response_rules_in` 5.0k with
no rules (`HeadFacts::of_response` 1.2k, `check_response_head` 1.1k, `inject` 0.4k, memset 0.3k)
against HAProxy's ~2.4k: **+2.6k** (E2 left it; X3 names part); loop + run fixed **+2.2k** (L1/L3:
named); the rest nets against Ibex's **-5.7k** (no per-request stream object). So after K1 and X
the named + K1 total covers the gap with ~1k to spare; without K1, §5's keepalive landing
(38.7-41.9k) is optimistic by ~5k.

**Does each slice's §4 range stand?**

| slice | §4 range | verdict, with the measured basis |
|---|---|---|
| L1 | -0.3 to -0.8k all three | keepalive/rules **stands** (housekeeping 0.2-0.35k a request, `step_at` self 0.3-0.4k); **h2s1 is -1 to -2k** at the 8 passes it runs today (housekeeping 1.0k + `step_at` self 1.2k over 8 passes); the three counts shrink with L2. |
| L2 | h2 -3 to -5k; keepalive -0.3 to -1k | h2s1 **stands at the top: -4 to -5.5k** (5 passes x 1.05k) and a kernel saving of 5 `epoll_wait`; keepalive **0** (there is no third pass: 2.00 passes, as HAProxy). Drop the keepalive saving. |
| L3 | keepalive/rules -1.5 to -3k; h2 -3 to -5k | **stands**: measured fixed cost 1.5k a run on keepalive (2 runs) so -2.5k at the 150 target; h2s1 0.95k x 9 runs, -4 to -5k before L2 removes runs. |
| O1a | keepalive/rules -0.5 to -1.5k | **lower**: `end_txn` is 1.70k (2.04k rules), not 2.7k; to ~1.2k is -0.5k: **-0.3 to -0.8k**. |
| O1b | h2 -3 to -5k | **stands**: set-up + tear-down are 7.1k (`h2_child_of` 2.03k, `end_txn` 2.47k, `end_stream` 2.60k) against HAProxy's 5.6k; to ~2.5-3k is -4 to -4.5k. |
| O2 | h2 -2 to -4k | **-2 to -3.5k**: `connect_http_backend` 6.4k (`route_to_server` 2.55k, `IdlePools` 0.78k, `select_server` 1.38k); HAProxy 1.8k. |
| IO1 | keepalive/rules -1 to -2k; h2 -0.5 to -1k | **keepalive/rules -0.5 to -1k** (the whole I/O state machine's self is 2.1k and HAProxy's equivalent is ~4k); h2 **stands**. |
| C1 | -0.5 to -1.2k all three | keepalive/rules **-0.3 to -0.6k** (accounting is 0.9k, HAProxy 0.5k); h2s1 **-0.8 to -1.2k** (2.0k a request). |
| C2 | -0.3 to -0.8k all three | **stands** on keepalive (the `SystemTime::now` 0.30k and one of the two per-pass `Instant::now`: -0.3 to -0.6k); h2s1 -0.5 to -1.5k depending on L2's pass count. |
| X2-X4, R1-R4 | (htx §1.3, §4.4) | X2: request re-serialisation 3.0k stands; parse is 2x HAProxy so the 3.5k per head target is right; R1: the hash is not the cost (0.44k a fetch, 3 fetches); R2/X3 carry the rules. |

What X0 could not measure is listed in `tasks/X0-profile-post-e2.md` ("Results").

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

**Budgets after X0 (2026-11-01).** Every "expected" cell below is rewritten from §2.1's measured
rows and names its base; the pre-X0 reasoning in the same cell is gone. Base figures (user
instructions a request): Ibex keepalive 45.9k, rules 75.7k, h2s1 71.6k, h3fit 98.9k; HAProxy
36.2k, 43.8k, 53.2k, 64.0k (dev10). Delivery so far against a design range: R1 (T574) measured
-1.06k on a -1.5 to -3k range (X0: the name lookup was not the cost); S7/E2 left 4.0k where
~2.5k was estimated (htx §1.3 row 1). §5 therefore reads the sums at a **delivery factor of
0.7** (range 0.5-1.0). A slice that measures under the low end of its range on its target
scenario stops and reports (§6 stop rules); the budget on every other scenario stays +0.5 %.

In flight at the time of the re-budget: **R1** (T574, closing at -1.06k rules), **K1 + the
parse path in bytes** (T575, Sonnet: K1 -4k or better on keepalive and rules; UTF-8 off the
parse path -0.8k or better on keepalive).

### 4.1 Track X, representation (D5, revised after X0)

X0 is done (§2.1, htx §1.3). X1, X5, X2, X3, X4, X7, X6, X8 as `htx-engine-2026-11-01.md` §3,
with these changes (the "expected" cells there are superseded by the ranges here):

- **X1** (now **L**, was M): `index_h1_head` is also the fast scan. §2.1 row 6: the request
  parse is **10.1k against HAProxy's 4.9k per head**, and its leaves are byte-at-a-time
  (`memchr` 3.5k self, `eq_ignore_ascii_case` 1.1k, `to_ascii_lowercase`/`is_ascii_uppercase`
  1.25k, `ascii_word_spans` 1.1k htx.rs:359, `finalize_last_header` 0.56k, h1.rs:490
  `parse_headers` 5.9k). The in-place parser finds delimiters one line at a time with
  `memchr2`/`memchr3` (already a dependency), checks tchar and lowercases names with one
  256-entry table, writes descriptors as it goes, and works on bytes throughout (T575 Part 2's
  rule). Target **<= 3.5k per head** on the scenarios' heads; the number is measured by X2 (the
  path), X1 itself is off the path (0). The differential test of htx §3 is unchanged.
- **X5**: unchanged, neutral. Its `ConnMode` flags are K1's (T575) flags: K1 lands first, X5
  consumes them (`h1_make_eoh`'s mode rule emits the token; K1's interim token write goes).
- **X2**: also the request-phase `SampleContext` built once per rule run (not per rule) and the
  `tune.ibex.h1-lowercase-headers` passthrough leg (D-E, default off). Expected: **keepalive
  -3 to -5k** (the parse 10.1k -> 5-7k with X1's parser, `req_htx_init` 0.6k and the `htx_buf`
  take/give gone, +0.2k descriptor writes; T575's UTF-8 -0.8k and K1's Connection path are
  **excluded** because they land first; K1's remaining token write folds into
  `encode_if_modified`: -0.5 to -1k more). **rules -9 to -13k** (the keepalive share, plus:
  `write_req_head` **x2** + its memsets + `flush_req_rebuild`/`replace_prefix` 4.0k -> one
  encode at the send <= 1k; `req_rule_header` 2.0k / `add_req_header` 1.6k / `set_header`
  family 1.75k (overlapping) -> block edits ~0.5k; `SampleContext` 2.1k -> once per phase <=
  0.4k; §2.1 row 8). **h2s1 0** (`copy_header` is 0.2k, not 1k). The "keepalive flat" of htx §3
  was written before X0 showed the parse at 2x; it is replaced by the range above, and D-C's
  strict budget applies to what X2 does not name (kernel, h2s1).
- **X3**: also the per-rule `SampleContext` clone retired (S7's "borrow"); the HPACK static
  `match` is done (Q3). Expected: **keepalive -1.5 to -2.5k** (the response head with no rules
  is 5.0k: `HeadFacts::of_response` 2.0k, `check_response_head` 1.1k,
  `rewrite_header_names_before` 0.7k, `inject` 0.4k + memset 0.3k; target ~2.5k, HAProxy ~2.4k);
  **rules -3.5 to -5k** (7.3k: `rewrite_header_names_before` 2.9k engine.rs:16773,
  `run_res_rules` 1.7k engine.rs:16514, `HeadFacts` 1.9k, `check_response_head` 0.8k; target
  <= 3k, HAProxy's response rules 1.3k + head 2.4k); **h2s1/h3fit -2 to -3k** (4.8k:
  `indexed_fields`, the HPACK scan, the `(String, String)` head).
- **X4**: **h2s1/h3fit -3 to -5k** (was -2 to -3k: two copies of the head cost 6.8k measured,
  `put_request_head` 3.9k + `write_h1_wire` 2.1k + `req_htx_init` 0.8k, htx §1.3). Still the
  prerequisite of O1b.
- **X7**: unchanged (rules -1k, h2s1 -0.5k, keepalive -0.3k).
- **X6, X8**: neutral on the four scenarios; last, after the week-6 re-measure, Sonnet fillers.

### 4.2 Track L, loop and scheduler (survey S3)

| slice | goal | files | test that fails first | expected ins/req (reasoning) | size | depends | model |
|---|---|---|---|---|---|---|---|
| **L1** | housekeeping out of the pass: idle purge, buffer trim, stick-table expiry, `pool::pass`, the three `publish`es, accept-limit and CLI-retry checks become `Kind::Housekeeping` tasks on the wait queue (one per concern, HAProxy's `srv_cleanup_idle_conns`/`process_table_expire` model) run when their timer expires; QUIC admit/adopt/serve behind `!quic_listeners.is_empty()`; `EngineDispatcher` built once per `Engine` | `engine.rs` `step_at` 5923-6230, `sched.rs` (a task kind), `pool.rs` (`pass` from a task) | `crates/ibex-rt/tests/it/engine_pass.rs` (new module): `a_pass_with_nothing_due_does_no_housekeeping` — `#[cfg(debug_assertions)]` `work::Op::Housekeeping` counter 0 over 100 idle passes and 1 per timer period; red today (every pass). `show pools`/`show info` rows stay identical under the stats battery | **keepalive/rules -0.3 to -0.8k** (§2.1 row 1: housekeeping calls 0.2-0.35k a request + `step_at` self 0.3-0.4k); **h2s1/h3fit -1 to -2k at today's 8 passes** (housekeeping 1.0k + `step_at` self 1.2k), **-0.5 to -1k once L2 holds 3 passes**; kernel 0 | M | - | Sonnet |
| **L2** | instant wakeup: `Dispatch` gets `wake_now(TaskRef)` which pushes to the current pass's tasklet list; `run_tasks_from_lists` drains what arrives while it runs (budget-bounded, as HAProxy's lists); the `last_run == loops` guard (sched.rs:703) allows a second run per pass and refuses a third; the owner<->child wakes (engine.rs:11212, `h2_owner_pass`'s `wake_queue`) and `wants_rerun` use it; `wake_queue` keeps only cross-pass uses (buffer waiters, mailbox) | `sched.rs` 637-740, `engine.rs` dispatcher (`wake_queue` sites), `h2_owner_pass` | `engine_pass.rs`: `an_h2_request_completes_in_three_passes` and `an_h1_keepalive_request_completes_in_two` — debug counter of `step_at` per request through a local h2load/ab run in the test harness (as `h2_per_request_work.rs` counts); red today on h2 (8 passes undisturbed, X0; the h1 row is already 2.00 and only pins). `ibex-sched` unit tests: a task woken twice in a pass runs twice, a third wake waits; the Bulk demotion still applies to self-wakes | **h2s1 -4 to -5.5k** (§2.1: 7.99 passes against HAProxy's 3.00, 1.05k a pass outside the tasks; 5 passes removed) and **kernel -5 `epoll_wait` a request**; **h3fit -4 to -6k** (7-8 passes to <= 3-4); **keepalive/rules 0**: 2.00 passes under every observer on both proxies, no third pass exists; the slice names no h1 saving | M | - | Opus |
| **L3** | the stream run gated by state: `step_stream_run` reads the wake reason (`WOKEN_TIMER` -> `check_timeouts`; `WOKEN_IO` -> clear the fired side's `cant_recv`), a `pending: u16` on `TcpSession` for the rare conditions (set where each arises: deferred session rules, tcp inspect x2, scrape, stick stores, glitches, park expiry, retry, connect-log, rate-max, srv handshake failure, checkcache), `stream_vars_enter/leave` and `stream_timeouts_enter` replaced by `&Proxy`/timeouts passed down (Q6: no `Arc` clone), `update_interests` only on a changed `(Want, Want)`, `req/rep.release()` at txn end | `engine.rs` 10889-11270, 7927-8000, 9485; `proxy.rs` (`pending`) | `engine_pass.rs`: `a_keepalive_stream_run_does_only_io_and_http` — `work::Op` counters for each rare check are 0 on a plain GET and 1 when the condition is set (deferred rule, inspect, scrape); red today. The timeout battery (T140-era `timeouts_*` modules) and `h2_per_request_work.rs` green; `Arc` strong count of the capture table constant across a request | **keepalive/rules -1.5 to -2.5k** (§2.1 row 3: fixed cost 1.5k a run x 2 runs; the 150 target leaves 0.3k), **h2s1/h3fit -3 to -4k after L2** (0.95k a run; 9 runs today, 5-7 after L2; -4 to -5k if L3 lands first, then L2's figure shrinks by the same) | L | L2 (run counts) | Opus |

### 4.3 Track O, stream objects and the backend side (survey S2 = E3)

| slice | goal | files | test that fails first | expected | size | depends | model |
|---|---|---|---|---|---|---|---|
| **O1a** | the `Stream` object: `txn`, `log`, txn/reqres vars, captures, backend side, task, timers out of `TcpSession` into a pooled `Stream` (`ibex_alloc::Pool`, 1 KiB class, counted in `show pools`); the h1 session holds one and **resets** it at txn end (`Stream::reset`: the fields that change, no `Default`); `end_txn` becomes reset + the connection-level decisions | `proxy.rs` 653-894 (`TcpSession` split), `txn.rs`, `txnlog.rs`, `engine.rs` `end_txn` 10476, `account_stream` | `crates/ibex-rt/tests/it/stream_object.rs` (new module): `a_keepalive_request_resets_its_stream_in_place` (debug counter: 0 `Stream` allocations and 0 `StreamLog` constructions per keep-alive request after the first; red today: `end_txn` rebuilds), `stream_is_at_most_1_kib` (`size_of` pin), the log-format battery (`%Tr`, `%Tw`, `%ST`, captures, vars) identical | **keepalive/rules -0.3 to -0.8k** (§2.1 row 4: `end_txn` is 1.70k / 2.04k measured, not 2.7k: `reset_for_next_request` 0.97k proxy.rs:2190, `IdlePool::note_used` 0.33k; to ~1.2k); h2 0. The slice's worth is structural: O1b (-4 to -4.5k) and R4 (-1 to -2k) stand on the object, not its own saving | L | X2 (the stream's buffers are the layout) | Opus |
| **O1b** | h2 children as `Stream`s: the owner holds `Vec<Stream>` by stream id with a task each; `h2_child_of`/`h2_child_done`/`spawn_h2_children` become `Stream::start`/`finish`; `h2_owner_pass` iterates its streams (no `sessions.get2_mut` per child per pass); `end_stream` for a child is `finish` + pool give | `engine.rs` 6237, 10607-10660, 11272; `h2_bridge.rs`; `proxy.rs` (`h2_owner`) | `stream_object.rs`: `an_h2_stream_is_not_a_session` (debug counter: 0 `TcpSession` constructions per h2 request; red today 1), `h2_per_request_work.rs` rows green, the h2 battery (T280, T409, GOAWAY/RST rows) green | **h2s1 -4 to -4.5k** (§2.1 row 4: set-up + tear-down 7.1k measured, `h2_child_of` 2.03k, `end_txn` 2.47k, `end_stream` 2.60k with `h2_child_released` 1.42k; HAProxy 5.6k; target 2.5-3k) | L | O1a, X4 (D-F) | Opus |
| **O1c** | h3 streams as `Stream`s: `step_h3_owner`'s children, `read_stream`/`write_stream` into the stream's layout (Q1's handle) | `engine.rs` `step_h3_owner`, `quic_listener.rs`, `mux_h3.rs` | `stream_object.rs`: the h3 row of the counter test; `h3_request_framing_to_backend.rs` green; h3fit measured | **h3fit -3 to -5k** (the h2s1 object figures carried over; X0 took no post-E2 h3 per-function table, T544's stands) | M | O1b, Q1 | Opus |
| **O2** | backend side without hashes or locks: servers by dense index (Q5: `engine.rs:170,179,369,427`), idle connections as per-thread per-server `Vec<IdleConn>` (own thread first, cross-thread take only on a miss, as `conn_backend_get`), `IdlePools::with_count` and the `RwLock` read gone from the take, `route_to_server`/`select_server` on the compiled backend (precomputed server list, no name compares) | `engine.rs` `connect_http_backend` 12840-13100, `route_to_server` 14016, `select_server` 2054, `IdlePool` 265-600 | `stream_object.rs`: `taking_an_idle_connection_takes_no_lock_and_hashes_nothing` (debug counters on the lock and on `IdleKey` hashing; red today), `http_reuse_*` rows (safe/aggressive/always, the 64-thread `vtc` port at `engine.rs:1036`) green | **h2s1/h3fit -2 to -3.5k** (§2.1 row 5: `connect_http_backend` 6.4k on h2s1 without rules: `route_to_server` 2.55k, `select_server` 1.38k, `IdlePools` 0.78k; HAProxy 1.8k; target <= 3k); keepalive/rules ~0 (parked; the lock/hash rows are 0.3k there); kernel 0 | M | - | Sonnet |

### 4.4 Track R, rules

| slice | goal | files | test that fails first | expected | size | depends | model |
|---|---|---|---|---|---|---|---|
| **R1** | compiled dispatch: `Expr::parse` resolves `fetch_name` to `FetchFn` (+ `MultiFetchFn`/`VisitFetchFn`), parses args into `Arg` (lowercase header name bytes, int, regex, var name, table ref), resolves converters to `ConvFn`; `Registry::eval_g`/`any_acl`/`eval_all_g` take the compiled form; the by-name entry points stay for the CLI and tests only. Covers `tcp-request`/`tcp-response`, `use_backend`, `stick`, `log-format %[...]`, `track-sc` (the "Expr::cached" remainder) | `crates/ibex-sample/src/expr.rs`, `registry.rs` 1290-1330, `rule_compiled.rs`, `logfmt.rs` | `crates/ibex-sample/tests/it/compiled_expr.rs` (new module): `evaluating_a_compiled_expression_looks_up_no_name` (debug counter on `fetches.get`/`converters.get`: 0 per eval; red today 1 per fetch), the fetch/converter batteries (T80, T81) green through the compiled path | **closed: T574 measured rules -1.06k, keepalive flat** (design range was -1.5 to -3k; §2.1 row 8: the lookup was ~0.44k a fetch x 3 fetches, not 8 x 200-350; the rest of `Expr::eval`'s 3.75k is the materialised sample and the per-rule context, R2's and X2's) | M | - | Sonnet |
| **R2** | samples as bytes, borrowed (user decision 2026-11-01: Ibex keeps data as bytes like HAProxy, no UTF-8 validation or re-encoding; replaces the "`str` samples stay UTF-8, validated once at the fetch" half of tradeoff 6.12 / D-B): `Sample<'a>` with `Str(Cow<'a, [u8]>)`/`Bin(Cow<'a, [u8]>)` views into the HTX block for header, path, method, query, cookie fetches (HAProxy's `SMP_F_CONST`, `smp->data.u.str` is bytes); owned bytes only after a converter produces new ones; **matchers and converters on bytes** (`-m str/sub/beg/end/dir/dom`, `lower`/`upper`/`word`/`field` as ASCII byte ops, HAProxy's `pat_match_*`); **regex**: `UserRegex::Linear` becomes `regex::bytes::Regex` (ibex-regex/src/lib.rs:596-601; no lookaround/backrefs), `Backtracking` stays `fancy_regex` on `str` and validates at the match only (one `from_utf8` per such match, a non-match on invalid bytes, as HAProxy's `regex_exec` on bytes it cannot decode); no `from_utf8` anywhere else on the fetch/ACL/action path; `spare::string_from` off the fetch path; `%[...]` in a `str` position (log, var, format) takes the bytes and escapes as `%r` does | `ibex-sample` (`sample.rs`, the ~1,200 lines of fetches, `matcher.rs`, converters), `rule_compiled.rs`, `ibex-regex/src/lib.rs`, the 290 test sites tradeoff 6.12 counted | `compiled_expr.rs`: `a_header_acl_takes_no_spare_string` (spare counter 0 for `hdr(host) -m sub` and `path_reg`; red today), `a_rule_run_validates_no_utf8` (debug counter on `from_utf8` from the rules path: 0 for the rules scenario's 2 ACLs + 7 rules; red today: 17), `a_non_utf8_header_matches_as_bytes` (`hdr(x) -m sub \xff` and `-m reg` on a Latin-1 value: same verdict as HAProxy, recorded from the oracle), `request_allocations*.rs` pins | **rules -3 to -4.5k** (§2.1 row 8: spares 2.26k, the rules' 17 `from_utf8` ~0.3-0.5k, the `String` materialisation inside `Expr::eval`/`any_acl` ~1k); 0 elsewhere | L | X2 (the HTX views), R1 | Opus |
| **R4** | vars and format scratch in the `Stream`, as bytes: `set-var(txn.*)` into the stream's var slots (no 4 KiB `VarStore` spare take/give per txn; var values are bytes, R2's rule), `%[rand]`/log-format fragments rendered into a stream scratch `[u8; 256]` with overflow to a pool buffer (no `String`: the last rules-side `from_utf8`/`String` sites go here) | `vars.rs`, `logfmt.rs`, `txn.rs`, `engine.rs` `render_rule_format` 3262 | `stream_object.rs`: `set_var_takes_no_spare` (counter; red today), `a_format_render_takes_no_string` (counter on `String` construction in `render_rule_format`: 0; red today 2) | **rules -1 to -2k** (§2.1 row 8: `VarStore`/`vars::` 1.31k, `render_rule_format` 1.71k incl.) | S | O1a, R2 | Sonnet |

### 4.5 Tracks K, IO and C: connection mode, send/recv, accounting

| slice | goal | files | test that fails first | expected | size | depends | model |
|---|---|---|---|---|---|---|---|
| **K1** (new after X0; **in flight as T575**, with "parse path in bytes" as its Part 2) | HTTP/1.0 keep-alive by flags: the request parse records the `Connection` tokens and the version as connection-mode flags on the txn (HAProxy's `H1_MF_CONN_KAL`/`H1_MF_CONN_CLO`/`H1_MF_CLEAN_CONN_HDR`, `h1_set_cli_conn_mode`/`h1_set_srv_conn_mode`, mux_h1.c); `strip_request_connection` (proxy.rs:2344, 2.29k), `rewrite_request_connection` (engine.rs:15273, 5.50k: `write_req_head` 3.08k, the 8 KiB stack `memset` 1.14k, `add_req_header` 0.33k, `Buf::eoh` re-scans 0.21k) and the response `inject_connection_token_zero_alloc` (engine.rs:9605, 0.38k + memset 0.31k) go; the token the server and the client see is decided from the flags when the head is written (pre-X5: one bounded in-place token edit; after X5: the encoder's `h1_make_eoh` mode rule); HTTP/1.1 clients keep the `scan.count == 0` fast path; no 8 KiB scratch zeroing anywhere (`MaybeUninit` or a pool buffer if a scratch is needed). Part 2: `H1Parser`, `HeadFacts` and the facts on `&[u8]`, no `from_utf8` on the parse path (22 calls a request today), no `unsafe` | `proxy.rs` (`strip_request_connection` 2344, `validate_request_head` 2398, `reset_for_next_request` 2190), `engine.rs` (15273, 9605, the send site), `txn.rs` (flags, `HeadFacts`), `crates/ibex-proto/src/h1.rs` | `tasks/T575-k1-connection-flags-bytes-parse.md`: a debug `work::Op` counter on head rebuilds, 0 per HTTP/1.0 keep-alive request (red today: 1); wire equality with HAProxy for 1.0 keep-alive, 1.0 close, 1.1 `Connection: close`, `Connection: keep-alive, foo` (other tokens kept), `option http-server-close`, `option httpclose`, both directions (oracle bytes recorded); Part 2: a counter on `from_utf8` from the parse path, 0 per keepalive request (red today: 22); the connection-mode batteries and E1/E2's non-UTF-8 forwarding rows green | **keepalive -4 to -6k, rules -4 to -6k** (§2.1: the `Connection` path is 8.1k / 6.5k against HAProxy's ~0.5k; <= 1-2k before X5, <= 0.5k after); **Part 2 keepalive -0.8 to -1.2k** (`from_utf8` 1.45k incl. on the parse/facts path), rules the same; h2s1/h3fit 0; kernel 0 | S + S | - (X5 takes the last ~1k) | Sonnet |
| **IO1** | the h1 I/O state machine: `advance` driven by the poller's readiness bits (no `interests` recompute unless changed), `MsgState` advanced by what the parser returned (no re-derivation per run), the buffer kept while the txn is open (`release` at txn end), `Buf` accessors without the `nominal` indirection; written from X0 item 4 | `proxy.rs` 2489-2700, 3471-3800, `buf.rs`, `txn.rs` (`MsgState`) | `engine_pass.rs`: `a_keepalive_request_takes_its_buffers_once` (buffer take/give counter: 2 per request, red today: per run), the I/O batteries (half-close T88, pipelining, `timeout http-keep-alive`) green | **keepalive/rules -0.5 to -1k** (§2.1 row 9: the I/O state machine's self is 2.1k measured against HAProxy's ~4k; the gain is the re-walk and the buffer take/give per run, not the self), **h2s1 -0.5 to -1k** (3.0k). **Conditional**: scheduled only if the week-5 re-measure leaves keepalive above 1.0x | M | X2 (the parse owns `MsgState`'s advance) | Opus |
| **C1** | accounting once: Q6 (`TimeStat::add` load + store-if-greater, `Arc` borrows), `account_stream` from the pass clock (no `now_ms` read), one `count_status`, `StreamLog`/`set_stream_log` (engine.rs:3581) fields and `SystemTime::now` only when a log target exists (X0 item 10: 0.47k / 0.45k / 0.78k with none), `RateCtr` ticks from the pass. **First a short design for D-4 "both"**: per-thread (or per-tgroup) counter rows as a `tune.ibex.*` setting, memory per server x thread, how `show stat`/`show info` sum the rows; the user approves it before the code | `statcnt.rs`, `engine.rs` 3349-3480, 3581, `txnlog.rs` | `engine_pass.rs`: `accounting_a_request_does_at_most_n_atomic_rmws` (X0 could not count them: pin n from a `#[cfg(debug_assertions)]` counter at the `statcnt` sites in the slice; red at today's count), `a_request_with_no_log_target_builds_no_log_line` (counter 0; red today: `StreamLog::start` once per request, twice on h2), `show stat`/`show info` rows identical under the stats battery | **keepalive/rules -0.3 to -0.6k** (§2.1 row 13: accounting 0.9-1.0k, HAProxy 0.5-0.6k; the no-target `StreamLog` 0.47k is most of it), **h2s1/h3fit -0.8 to -1.2k** (2.0k: `set_stream_log` 0.86k, `statcnt` 0.46k, `account_stream` 0.48k) | S | - | Sonnet |
| **C2** | clock residue: `%t`/`%Tl` from the pass clock (HAProxy's `date`), one `Instant::now` a pass (today two: `run_loop` and `step_at`), ticks as the pass's `u32` ms, `Duration::as_millis`/`Timespec` conversions off the path; the `rand` fetch (registry.rs:3637) seeded from a per-thread RNG, not `SystemTime::now` per call | `txnlog.rs`, `tick.rs`, `engine.rs` `tick_at`/`run_loop`, `ibex-sample/src/registry.rs` | `engine_pass.rs`: `a_request_reads_the_clock_once_per_pass_and_never_for_a_log_it_does_not_write` (counter: X0 item 8 measured 5.0 / 6.0 / 14-16.6; pin 1 a pass + 0; red today) | **keepalive/rules -0.3 to -0.6k** (§2.1 "Clock reads": `StreamLog::start`'s `SystemTime::now` 0.30k, one of the two per-pass `Instant::now` 0.27k, the `rand` fetch's read on rules), **h2s1/h3fit -0.5 to -1.5k before L2, -0.3 to -0.8k after** (two reads a pass x the pass count) | S | - | Sonnet |

### 4.6 Order, critical path, parallelism (after X0)

Four gate slots (disk, T570) and two measure slots (A, CPUs 4-6: claims; B, CPUs 12-14: counts;
C/D may be added for counts). Every slice merges alone and is measured on the four scenarios
against its parent. **At most two large `engine.rs` slices in flight, three only in weeks 3-4**
(D-15): every merge of one forces the others to rebase (risk 5), about half a day of agent time
each. The remaining slots take slices outside `engine.rs` (`ibex-proto`, `ibex-sample`,
`ibex-regex`, `h2_bridge.rs`, h3) or Sonnet S slices with small `engine.rs` touches.

- Large `engine.rs` slices: L2 (with `sched.rs`), L3, X2, X3, O1a (with `proxy.rs`), O1b, O2,
  IO1.
- Small `engine.rs` touches (S, cheap to rebase): K1 (T575), L1, C1, C2, X5's call sites.
- Outside `engine.rs`: X1, X4, R2, R4, X7, X6, X8, Q1/Q2a/Q4.

**Dependencies, hard**: X1 -> X5 -> X2, X3; X2 -> X4, O1a, R2, IO1; X4 + O1a -> O1b -> O1c;
O1a + R2 -> R4; X2 + X3 + X4 -> X7; L2 -> Q2 b1. **Soft (order, for the budgets' sake)**: K1
before X5 and X2 (holds: T575 is in flight); L2 before L3 (L3's h2 figure is quoted after L2).

**Sequential** (the critical path): **X1 -> X2 -> X4 -> O1b -> O1c**, ~19-22 agent-days of Opus
work in series plus a gate and a rebase at each merge: **weeks 1-6, the landing re-measure in
week 7**. The previous plan said 4-5 weeks for X0 -> O1c: X1's growth to L (the parse scan),
X2/X3 at their measured sizes and K1 ahead of X5 add about a week. **Parallel** beside it: K1,
L1, O2, C1, C2 at any time; L2 then L3; X3 beside X2; R2 and O1a after X2; R4 after O1a; the h3
track's Q1/Q2a/Q4 in any free slot (no shared files); X7/X6/X8 last.

| week (from 11-02) | slot 1 (`engine.rs`) | slot 2 (`engine.rs`) | slot 3 | slot 4 | large `engine.rs` in flight |
|---|---|---|---|---|---|
| 1 | R1 close (T574), then **L1** (M, Sonnet) | **K1 + Part 2** (T575, Sonnet) | **X1** (L, Opus: `htx.rs`, `buf.rs`, `h1.rs`) | **X5** (M, Opus: the encoder), then **C2** (S, Sonnet) | 0 |
| 2 | **L2** (M, Opus) | **O2** (M, Sonnet) | X1 (cont.) | X5 -> **C1** (D-4 design, then code; S, Sonnet); **Q1** (h3) when free | 2 |
| 3 | **X2** (L, Opus) | **X3** (L, Opus; the second to merge rebases) | **L3** (L, Opus) | Q2a / Q4 (h3) | 3 (the limit) |
| 4 | X2 (cont.) | X3 -> **O1a** (L, Opus) | L3 (cont.) | **X4** (M, Opus) after X2; then **R2** (L, Opus, `ibex-sample`/`ibex-regex`) | 3 |
| 5 | **O1b** (L, Opus) after X4 + O1a | O1a -> **R4** (S, Sonnet) after R2 | **re-measure 1**: keepalive and rules verdicts (D-13, D-16); **IO1** only if keepalive > 1.0x | R2 (cont.); **X7** (M, Sonnet) | 2 |
| 6 | O1b (cont.) | **O1c** (M, Opus) after O1b | Q2 b1 (h3, after L2) | X6, X8 (Sonnet fillers) | 2 |
| 7 | **re-measure 2**: the landing table, non-PGO and the PGO column (§5) | slack: rebases, a stopped slice's re-plan | | | |

**ETA, honestly.** Seven weeks if no slice stops and no rebase goes wrong; nothing is budgeted
for a stop. A stopped X2 or O1b (the two L slices on the path) costs its re-plan plus the gate
runs behind it, about a week each; a stopped L3 or X3 costs nothing on the path. The verdict
per scenario arrives before the end: keepalive after K1, X2, X3, L3, C1, C2 (week 5); rules
after R2 and R4 (week 6); h2s1 after L2, O2, X4, O1b (week 6-7). The latency board
(`m1_latency.py`) runs with L2 and L3 (risk 1); the soaks wait until most slices are in (§6.1).

## 5. Expected landing (after X0)

Per scenario, user-space instructions a request, non-PGO release-perf against non-PGO HAProxy
(D-8). **Method**: base = X0's totals (§2.1); each slice's §4 range on the scenarios it names,
in-flight slices at their budgets (R1 at its measured -1.06k, K1 -4 to -6k, T575 Part 2 -0.8 to
-1.2k); IO1 excluded (conditional, D-16); **Σ = the sum of the midpoints**; **central = base -
0.7 x Σ** (the delivery factor of §4: R1 delivered 47 % of its midpoint, S7/E2 about 60 %);
**range = base - 1.0 x Σ (every slice at its midpoint) to base - 0.5 x Σ**. The PGO column is
x 0.87 (T435's -13 %) and is the shipped figure, not the merge criterion (§6.1). Kernel: Ibex
is already 3.4-7.0k a request below HAProxy on every scenario (§2.1); every slice holds kernel
at or below its parent, L2 removes 5 `epoll_wait` a request on h2s1.

What Σ is made of (midpoints, k):
- keepalive: K1 5.0, Part 2 1.0, X2 4.75 (incl. K1's remainder), X3 2.0, L3 2.0, L1 0.55,
  O1a 0.55, C1 0.45, C2 0.45, X7 0.3 = **17.05** (low 12.8, high 21.3).
- rules: the keepalive items at their rules figures (K1 5.0, Part 2 1.0, X2 11.75, X3 4.25,
  L3 2.0, L1 0.55, O1a 0.55, C1 0.45, C2 0.45, X7 1.0) + R1 1.06 + R2 3.75 + R4 1.5 + O2 1.5
  (`route_to_server`/`select_server` are 2.0k dearer on rules than on keepalive, §2.1 row 5;
  cause not located by X0; O2's compiled backend names it as a secondary target) = **34.8**
  (27.6-42.1).
- h2s1: L2 4.75, O1b 4.25, X4 4.0, L3 3.5, O2 2.75, X3 2.5, C1 1.0, L1 0.75, C2 0.55, X7 0.5 =
  **24.55** (20.1-29.0).
- h3fit: the h2s1 items with O1c 4.0 for O1b and L2 5.0, no X7 = **24.05**; plus the quinn
  track Q1/Q2/Q4 -10 to -17k (mid 13.5) = **37.55**.

| scenario | base (X0) | Σ mid (low-high) | **central** (0.7 Σ) | range (1.0 Σ .. 0.5 Σ) | HAProxy | ratio, central (range) | D-10 target | reached non-PGO? | PGO, shipped |
|---|---:|---:|---:|---:|---:|---|---|---|---:|
| keepalive ab1 | 45.9k | 17.1 (12.8-21.3) | **34.0k** | 28.9-37.4k | 36.2k | **0.94x** (0.80-1.03x) | <= 1.0x | **yes at central**; misses by ~1.2k at delivery 0.5 (IO1's -0.5 to -1k is the reserve, D-16) | 29.6k, 0.82x |
| rules ab1 | 75.7k | 34.8 (27.6-42.1) | **51.3k** | 40.9-58.3k | 43.8k | **1.17x** (0.93-1.33x) | <= 1.1x first, 1.0x stretch | **no at central**: 1.1x (48.2k) needs delivery >= 0.79, 1.0x >= 0.92 (D-13) | 44.6k, 1.02x |
| h2s1 | 71.6k | 24.6 (20.1-29.0) | **54.4k** | 47.1-59.3k | 53.2k | **1.02x** (0.89-1.11x) | <= 1.0x, aim 0.9x | **borderline**: 1.0x needs delivery >= 0.75; 0.9x (47.9k) >= 0.97 (D-17) | 47.3k, 0.89x |
| h3fit (1.97 dg/req) | 98.9k | 37.6 (engine 24.1 + quinn 13.5) | **72.6k** | 61.4-80.1k | 64.0k (dev10) | **1.13x** (0.96-1.25x) | none (D1: ~1.0x after both programmes) | 1.0x only at full delivery | 63.2k, 0.99x |

Reading. **keepalive reaches D-10 at the central estimate** because X0 located the remainder:
K1 and the parse (X1/X2) are 9.75k of Σ's 17.05k and both are single functions with a measured
HAProxy figure to beat, not a spread of small sites; the bet is X1's parser at <= 3.5k a head.
**rules does not reach <= 1.1x at the central estimate.** After every named slice the rules'
own cost is 12-17k (full to central delivery: 40.9 - 28.9, 51.3 - 34.0) against HAProxy's 7.6k: what remains unowned is
`Expr::eval`/`any_acl`'s remainder after R1/R2 (~1.5k), the converters 1.9k, the regex 1.1k
(parity with `pattern_exec_match` 1.55k), and whatever makes `route_to_server` 2k dearer on
rules. A rules remainder pass (R5) is not funded until X2, X3 and R2 have measured (D-13); with
PGO the shipped build is at ~1.0x. **h2s1 is borderline at 1.02x** (the earlier ~0.9x central
was read before X0 put the base at 71.6k and before the delivery factor): L2's pass count is
timing-dependent (6.0-8.0 passes, §2.1), so L2 must be measured on the same day as its parent
and report the pass count beside the instructions; the 0.9x aim is the PGO figure (D-17).
**h3fit** lands at ~1.13x with both programmes at central, 1.0x only at full delivery; D1's
ratios move with the engine slices as before.

What would still make keepalive miss 1.0x: (a) X1's parser lands at 5-7k a head instead of
<= 3.5k (then X2's keepalive figure halves and the central is ~1.0x); (b) a slice measured
outside its range is merged anyway (the stop rule exists for this); (c) delivery under 0.6
across the board, which the week-5 re-measure shows in time to schedule IO1 and to re-read the
PGO column as the shipped answer.

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

**D-9, per safety extra (X0 item 9, §2.1; user instructions a request, keepalive / rules / h2s1).**

| extra | measured cost | recommendation |
|---|---:|---|
| `crash::contain` per task run (T447) | 0.03k / 0.13k / 0.08k | **keep on, no setting**: under the 0.3k threshold of §5 (c) in the pre-X0 text; `catch_unwind` costs nothing when nothing panics |
| `watchdog::progress`/`sleeping`/`set_streams`, 3 a pass | 0.04k / 0.10k / 0.11k | **keep on, no setting**; L1 folds the three stores into one per pass as a side effect |
| buffer wipe, `tune.ibex.zero-buffers` | 0.03k / 0.05k / 0.05k with the default **off** (an atomic load) | **nothing to decide**: already a setting, default off |
| TLS record wipe, `tune.ibex.ssl-zero-buffers` | h2s1 ~0.12k (0.17 %; a memset under `encrypt_records`, attribution uncertain) | **keep on by default**: a security trade that is already a setting (memory: "Security trade = setting"); the cost is under the +-0.5 % budget noise |
| `fault_point` | 0: compiled out in release (`#[cfg(debug_assertions)]`, crash.rs:101) | nothing |
| `StreamLog`/`set_stream_log` with no `log` target | 0.47k / 0.45k / 0.78k | not a safety extra: **C1 removes it** (item 10); no decision |
| pool `Guard` bookkeeping | 0.14k / 0.25k / 0.21k | not a safety extra (AGENTS §8's accounting, `show pools`); keep |

Sum of the five extras: 0.1-0.35k, 0.2-0.4 % of the user total, below the +-0.5 % slice budget.
**Recommendation: no extra becomes a new setting, nothing is turned off, and the A/B against
HAProxy runs with every default as shipped; no second "fair benchmark defaults" column is
needed.** D-9 is thereby closed unless the user rules otherwise.

**New decisions after X0 (2026-11-01 evening), one line each.**

| | question | recommendation |
|---|---|---|
| **D-12** | K1 + "parse path in bytes" (T575, Sonnet, launched by the user): merge criterion keepalive -4k and -0.8k or better (§4.5) | **Confirm** as launched; X5 takes K1's last ~1k |
| **D-13** | rules: <= 1.1x is not reached at the central estimate (1.17x non-PGO, 1.02x PGO). Keep <= 1.1x and decide at the week-5 re-measure whether to fund a rules remainder pass (R5: `Expr::eval`/converter remainder, `route_to_server` on rules; 12-17k own against 7.6k), or accept 1.1-1.2x non-PGO | **Keep <= 1.1x; decide R5 at week 5**, not before X2, X3 and R2 have measured |
| **D-14** | X1 grows from M to L to own the parse scan (<= 3.5k a head) instead of a separate parser slice | **Yes, inside X1**: a separate slice would write the same function twice |
| **D-15** | four gate slots: three large `engine.rs` slices at once in weeks 3-4 (X2, X3, L3) at the cost of two rebases, or two and a week longer | **Three in weeks 3-4 only**, two otherwise (§4.6) |
| **D-16** | IO1 becomes conditional: scheduled only if the week-5 re-measure leaves keepalive above 1.0x | **Yes**; its range fell to -0.5 to -1k |
| **D-17** | h2s1's 0.9x aim: the central lands at 1.02x non-PGO and 0.89x with PGO | **Restate**: <= 1.0x non-PGO is the merge target, 0.9x is the shipped (PGO) figure; no extra slice for it now |
| **D-18** | bytes everywhere (user, 2026-11-01): tradeoff 6.12's "`str` samples stay UTF-8" half retired; the one `from_utf8` left on the rules path is fancy-regex's at a backtracking match | **Record in `tradeoff.md` at R2's merge** (6.12 and 6.24 rows); no further decision |

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
- **PGO (16:30).** Release builds ship PGO (`tools/pgo-build.sh`). Development and every slice's
  merge criterion stay non-PGO: a saving must hold without PGO, against non-PGO HAProxy (D-8).
  PGO is measured once at the end of a performance slice, after the non-PGO work is done, as a
  second column (`insreq.sh` on the PGO binary, same scenarios): cost ~11 min wall (instrumented
  + final fat-LTO builds ~5 min each, 27 s training, T435), no per-edit cost. Where a scenario
  reaches HAProxy only with PGO, that is reported as such and is acceptable for the shipped build.

### 6.2 Re-budget after X0 (2026-11-01)

- **Refs**: HAProxy keepalive 36.2k, rules 43.8k, h2s1 53.2k, h3fit 64.0k (dev10; not 73.7k).
  Kernel: Ibex 3.4-7.0k below HAProxy on every scenario; no slice needs a kernel saving.
- **New**: K1 + parse path in bytes (T575, in flight): the largest single keepalive item (8.1k,
  the HTTP/1.0 `Connection` rewrite) was in no slice. R1 closed at -1.06k (T574).
- **Grown**: X1 M -> L (the parse scan: 10.1k -> <= 3.5k a head); X2 keepalive -3 to -5k (was
  flat), rules -9 to -13k; X3 keepalive -1.5 to -2.5k, rules -3.5 to -5k; X4 -3 to -5k; R2 as
  bytes -3 to -4.5k; R4 -1 to -2k; L2 on h2s1 -4 to -5.5k plus 5 `epoll_wait`; O2 also on rules.
- **Shrunk**: L2 on h1 (0: 2.00 passes on both proxies); O1a -0.3 to -0.8k (kept: O1b and R4
  stand on it); IO1 -0.5 to -1k and conditional; C1 on h1 -0.3 to -0.6k; X2 on h2 0.
- **User decision, bytes like HAProxy**: no UTF-8 validation or re-encoding (R2, T575 Part 2).
  The rules-side UTF-8 cost reaches zero after **R2 + R4** (R2: the 17 fetch/ACL/action calls;
  R4: the format/var `String` sites), the parse side after T575 Part 2 (22 calls); the single
  `from_utf8` left is fancy-regex's at a backtracking match (D-18).
- **D-9**: no safety extra becomes a setting; sum 0.1-0.35k, under the budget noise.
- **Landing** (§5, delivery 0.7): keepalive 34.0k **0.94x** (reached), rules 51.3k **1.17x**
  (<= 1.1x not at central, D-13), h2s1 54.4k **1.02x** (borderline, D-17), h3fit 72.6k 1.13x;
  with PGO 0.82x / 1.02x / 0.89x / 0.99x.
- **Order**: 4 gate slots, <= 2 large `engine.rs` slices (3 in weeks 3-4); critical path
  X1 -> X2 -> X4 -> O1b -> O1c, weeks 1-6, landing re-measure week 7 (was 4-5 + 6).

### 6.3 Fast run (user, 2026-11-01 evening): the schedule in hours, not weeks

User: "debloat your estimates… without safety factors… doing things in parallel doesn't mean we
have to repeat work that can be run on one code junction… ok with a bit fuzzier result for the
moment." §4.6's week table is replaced by this; §4's slice rows and budgets stand. Starting point
`ibex-rc4`.

- **Measured durations, 2026-11-01:** X0 (sized ~1 day) 45 min; R1/T574 (M) ~25 min of agent time
  including two measured builds; gate 4-10 min since T570; release-perf build ~7 min cold, serial.
  A slice is ~1.5-3 h of wall time (agent, gate, review); an Opus L slice (X2, O1b) up to ~4 h.
- **How:** every slice agent gets `~/ibex-worktrees/review/programme-brief.md`. The row is the spec
  (no re-profiling or re-measuring HAProxy). It measures once at the end, min of 3, against a
  shared base per main sha (`tools/measure/perfbase.sh`, T576). No board and no PGO per slice;
  one PGO measurement and one landing re-measure at the end of the run. A track's slices run in
  one worktree, one after another (one build tree, no rebase between them).
- **Waves** (a slice starts when its dependency merges, not on a date):

| wave | in flight (disjoint files) |
|---|---|
| 1 | K1 + parse-bytes (T575), L1 → L2 → L3 (one worktree), O2, C1 + C2, (T572 stats, T576 tools) |
| 2 | X1 (after T575: same parser files), then X5 (h1 encoder: X2 and X3 both depend on it, htx-engine §3), then X2 ∥ X3 |
| 3 | X4, R2 (after X2), O1a (after X2) |
| 4 | O1b (after O1a, X4), R4 (after O1a), IO1 only if keepalive > 1.0x here (D-16) |
| 5 | O1c, X6/X7/X8 fillers, landing re-measure + PGO column |

- **Critical path:** X1 → X5 → X2 → X4 → O1b → O1c (X5 added 11-01 20:20: the table had left it out), six slices at ~2.5-4 h = **~15-20 h** wall time
  if each starts when its parent merges; the run end to end **~18-24 h**, with fix rounds after a
  red gate as the uncertainty (each ~1 h). Remaining decisions (D-12..D-18) are taken at the
  recommendation unless the user says otherwise.

### 6.4 User decisions, 2026-11-01 (17:30): D-12..D-18, two passes

- **D-13**: a rules miss is acceptable in this first pass if rules lands within 10 % of §5's
  estimate (central 51.3k, i.e. <= ~56.4k user ins/req). No R5 in this pass: the leftovers of every
  scenario go to a **second optimisation pass** after the landing re-measure.
- **Scope of the first pass**: the multiplicative costs (per-pass, per-run, per-rule, per-header,
  per-copy work) and the "of course we should do this" items. A slice that turns into fine-tuning
  of a constant stops and leaves the rest to the second pass.
- **D-12, D-14, D-15, D-16, D-17, D-18**: approved as recommended.
- **Finishing early / stopping point (user, 17:40):** if the queue runs dry before the run ends,
  use the time on what this pass skipped, to hit the numbers. The numbers that matter most are the
  **PGO** ones (the shipped build). A scenario is done when its PGO figure is at or below HAProxy
  and what remains can't reasonably be optimised further. Whatever ends up out of scope is
  recorded in `challenges/` (one file each, `C<task>-challenge-<slug>.md`, as C541).

### 6.5 Wave-1 landing, measured (2026-11-01 23:05, main 85edb342)

After T574 (R1), T575 (K1 + parse bytes), T577 (L1-L3), T578 (O2), T579 (C1+C2), T583 (smax O(1)),
plus correctness merges. `tools/measure/perfbase.sh` (release-perf) and the same scenarios on a
`tools/pgo-build.sh` binary, counts slot, min of 5 (h3fit: median of 3 fits). User ins/req;
HAProxy = §2.1's dev8 (dev10 for h3fit), non-PGO. Board: `~/ibex-worktrees/boards/pgo-wave1-85edb342/`.

| scenario | start (rc4) | release-perf | ratio | **PGO** | **PGO ratio** | HAProxy | kernel (rp) |
|---|---|---|---|---|---|---|---|
| keepalive ab1 | 45.9k | 39.7k | 1.10x | **34.7k** | **0.96x** | 36.2k | 65.8k (HAProxy 69.7k) |
| rules ab1 | 75.7k | 68.6k | 1.57x | **59.6k** | **1.36x** | 43.8k | 65.9k |
| h2s1 | 71.6k | 60.9k | 1.14x | **54.1k** | **1.02x** | 53.2k | 66.7k (HAProxy 76.3k) |
| h3fit (1.97 dg/req) | 98.9k | 87.9k | 1.37x | **75.7k** | **1.18x** | 64.0k | n/a |

- **keepalive passes with PGO** (0.96x); h2s1 is at 1.02x with PGO, inside D-13's 10 %.
- **rules is the gap** (1.36x with PGO): the X2/X3/R2/R4 slices carry it (X5, not in this build,
  measured -2.7k rules on its own branch; T584 -0.3k; T595 targets the var lookup ~0.4k).
- **h3fit 1.18x with PGO**: O1c and T586 item 3 (h3 same-pass wake) are the h3 slices.
- PGO gains here: keepalive -12 %, rules -13 %, h2s1 -11 %, h3fit -14 % over release-perf.

### 6.6 ibex-rc5, measured (2026-11-02 03:55, 8d456329)

After wave 1 plus T584-T598, X1, X2, X3, X5 (T599 merged after the tag). Same method as §6.5:
`tools/measure/perfbase.sh` (release-perf: fat LTO, 1 codegen unit) and the same scenarios on a
`tools/pgo-build.sh` binary, counts slot, min of 5 (h3fit: median of 3 fits at 1.97 dg/req). User
ins/req. Ratio = Ibex ÷ HAProxy, **above 1 = Ibex does more work**. HAProxy = §2.1 (dev8, dev10 for
h3fit), gcc 16.2.1 `-O2 -g -fwrapv`, **no LTO, no PGO**. Board:
`~/ibex-worktrees/boards/pgo-rc5-8d456329/`.

| scenario | wave 1 PGO (§6.5) | rc5 release-perf | ratio | **rc5 PGO** | **PGO ratio** | HAProxy | PGO gain |
|---|---|---|---|---|---|---|---|
| keepalive ab1 | 34.7k | 36.0k | 1.00x | **30.9k** | **0.85x** | 36.2k | -14 % |
| rules ab1 | 59.6k | 56.8k | 1.30x | **48.0k** | **1.10x** | 43.8k | -15 % |
| h2s1 | 54.1k | 58.6k | 1.10x | **51.1k** | **0.96x** | 53.2k | -13 % |
| h3fit (1.97 dg/req) | 75.7k | 86.7k | 1.35x | **74.5k** | **1.16x** | 64.0k | -14 % |

Kernel per request (release-perf) 65.7k keepalive, 65.7k rules, 66.6k h2s1 (HAProxy 69.7k
keepalive, 76.3k h2s1, §2.1): the kernel is the larger half of every request on both.

- **The fair comparison is not either column yet.** release-perf has fat LTO and HAProxy has none;
  PGO-Ibex against non-PGO HAProxy flatters Ibex by roughly the PGO gain (10-15 % on both, as a
  rule). T603 builds HAProxy o2/lto/pgo/pgo-lto. Until then, read release-perf vs HAProxy -O2 as
  the nearest like-for-like (Ibex has LTO, HAProxy doesn't).
- **rules is still the gap** (1.30x release-perf): R2 (samples as bytes) and R4 are in waves A-B.
- **h3fit** (1.35x): O1c and X8 (wave C). T599 (after the tag) cut h3fit by -2.5k and h2s1 by -4.0k
  on release-perf: not in this table.
- Instructions only. Cycles, IPC, cache and branch misses on both proxies (`perf stat`) come with
  T603, so a gap can be split into work, memory and kernel. T582's waived +0.5% (C582) lands after.
