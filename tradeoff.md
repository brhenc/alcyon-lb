# Tradeoffs

Every entry here is a decision that bought something and cost something. The cost column
is the point: a tradeoff recorded only by its benefit is marketing, not engineering.

**Status** is one of:

- **measured** — verified on this machine, with the number
- **reasoned** — argued from the source or from first principles, not yet measured
- **unverified** — a prediction that could be wrong, recorded so it can be falsified

The last column is what would make us reverse the decision. A tradeoff without a
reversal condition is a belief, not a choice.

---

## 1. Architecture

### 1.1 Own scheduler instead of tokio

| | |
|---|---|
| **Gained** | Class budgets (`Heavy`=1 stops TLS handshake floods starving established connections), bounded work per pass, lazy timer requeue (slowloris), key-width-bounded tree depth |
| **Gave up** | The async ecosystem. No `hyper`, no `tokio-rustls`, no `async fn`. Every I/O path is a hand-written state machine. Far more code, and all of it ours to get wrong |
| **Status** | **measured** — 100k timeout extensions produce 0 tree inserts and 0 deletes; 10k queued handshakes still let all 10 ready I/O items run in pass 1 |
| **Revisit if** | The state machines become the dominant source of bugs, or someone ships class-budgeted scheduling in a general runtime. Tokio's coop budget counts *operations*; the moment it can express cost, this weakens |

Honest caveat: tokio is not naive. It has a per-poll cooperative budget and a competent
work-stealing scheduler. The gap is specific — it has no notion of work *classes*, and
one expensive computation is one unit of its budget.

### 1.2 Thread-per-core with hard connection affinity

| | |
|---|---|
| **Gained** | Zero locks on the data path, as a consequence rather than an optimisation. Connection state is legitimately `!Send`, so the compiler enforces the invariant |
| **Gave up** | No automatic rebalancing. **One pathological connection degrades its core with no safety net** — a work-stealing runtime would paper over this and we will not. Idle backend connection reuse across threads needs `takeover()`, which is real work and is deferred |
| **Status** | **reasoned** — the lock-free property follows structurally; the imbalance risk is untested under real load |
| **Revisit if** | Load testing shows meaningful core imbalance that admission-time placement cannot fix |

### 1.3 Nothing is async

| | |
|---|---|
| **Gained** | Control over per-connection memory. An `async fn` gives every connection a suspended future whose size the compiler chooses, which is the opposite of the 32-byte discipline applied to tasks |
| **Gave up** | Ergonomics, and the ecosystem again. Readiness-driven state machines are harder to read than `await` |
| **Status** | **reasoned** — matches HAProxy, which is readiness-driven, not coroutine-based |
| **Revisit if** | Per-future sizes turn out controllable enough that the memory argument fails |

### 1.4 Traits open, dispatch closed at the composition root

| | |
|---|---|
| **Gained** | No per-connection allocation. `Box<dyn Transport>` + `Box<dyn Mux>` at 60k connections is 120k heap allocations answering questions with three possible answers |
| **Gave up** | Adding a transport or mux means touching the root enum. A plugin that ships its own transport is impossible by construction |
| **Status** | **reasoned** |
| **Revisit if** | Out-of-tree extensions become a goal. They are explicitly not one (no Lua, no SPOE) |

---

## 2. Data structures

### 2.1 ebtree over an arena with tagged `u32` indices, not tagged pointers

| | |
|---|---|
| **Gained** | 4-byte references instead of 8; **28-byte nodes carrying key *and* payload against C's 40 carrying neither**; every deref bounds-checked; zero `unsafe`. A use-after-free becomes a stale index returning the wrong node — a logic bug, not memory corruption |
| **Gave up** | Max 2^31 nodes per tree. Deletion leaves holes, so a free list is needed. Stale indices are possible and are *not* caught by the type system |
| **Status** | **measured** for the sizes; **unverified** for the claim that denser descent beats C's one-allocation locality |
| **Revisit if** | A benchmark shows the extra indirection at dispatch costs more than the denser descent saves. §6.1 |

### 2.2 Enum work-kind instead of a function pointer

| | |
|---|---|
| **Gained** | 8 bytes against C's 16 (`process` + `context`). Jump-table dispatch, no indirect call. **Introspection is free** — the tag *is* the answer, where HAProxy's `void *context` erases the type and forces `show sess`/`show fd` to rebuild that knowledge separately |
| **Gave up** | The scheduler must know every task variant, so adding a subsystem touches the enum |
| **Status** | **measured** — sizes confirmed by `const` assertion and `show pools` on the reference binary |
| **Revisit if** | Never, realistically — in a statically linked binary with no plugin surface, the coupling is free |

### 2.3 Task at 32 bytes, with tree nodes split out

| | |
|---|---|
| **Gained** | Two tasks per cache line against HAProxy's two cache lines *per task*. Queue nodes are allocated only when actually queued: 32 B unqueued vs HAProxy's flat 128 B |
| **Gave up** | HAProxy embeds the `eb32_node`s so walking the run queue prefetches the task itself; we pay one extra indirection at dispatch. Dropping `tid` only works while thread-per-core holds |
| **Status** | **measured** at 32 bytes; the descent-vs-dispatch balance is **unverified** |
| **Revisit if** | §6.1 |

### 2.4 Singly-linked tasklet lists with lazy `KILLED` removal

| | |
|---|---|
| **Gained** | The link fits in the 32-byte budget. Removal is O(1) — set a bit |
| **Gave up** | No true arbitrary removal. A killed task occupies its slot until it is popped, so a large tasklet list holds dead entries longer than a doubly-linked list would |
| **Status** | **reasoned** |
| **Revisit if** | Kill-heavy workloads (mass connection teardown) leave lists full of corpses |

### 2.5 `Sample` split from `TypeSpec`

| | |
|---|---|
| **Gained** | 30 `ABORT_NOW()` cells in HAProxy's cast matrix become **uninhabitable rather than unreachable-by-convention**. HAProxy encodes "this cast cannot exist" as a deliberate runtime crash because its type system cannot say it |
| **Gave up** | Two types where C has one enum. Slightly more ceremony at every signature |
| **Status** | **reasoned**, and directly supported by upstream's own comments annotating `ANY`, `SAME` and `ADDR` as pseudo types |
| **Revisit if** | Nothing foreseeable |

---

## 3. Runtime

### 3.1 `SO_REUSEPORT` instead of HAProxy's accept rings

| | |
|---|---|
| **Gained** | Trivial to implement. No shared accept queue, no cross-thread ring, no contention |
| **Gave up** | **The kernel hashes by 4-tuple: distribution is even across connections but blind to how expensive each one is.** HAProxy's power-of-two-choices placement can see actual queue depth and live connection counts |
| **Status** | **reasoned** — the asymmetry is real; whether it matters is untested |
| **Revisit if** | Load testing shows imbalance. The fix is to adopt HAProxy's accept-ring approach, which is why placement stays behind `Listener` rather than leaking into the accept path |

### 3.2 Level-triggered epoll

| | |
|---|---|
| **Gained** | Compatible with bounded work. A reader that stops early because it hit its budget does not lose the wakeup — which edge-triggered would require draining to `EAGAIN` to avoid |
| **Gave up** | More `epoll_wait` returns for the same traffic than edge-triggered would need |
| **Status** | **reasoned** — matches HAProxy |
| **Revisit if** | Syscall overhead dominates, and only alongside a redesign of the budget discipline, since the two are coupled |

### 3.3 Sealed TLS trait with no provider escape hatch

| | |
|---|---|
| **Gained** | Multiple TLS providers become tractable rather than aspirational. HAProxy's `xprt_ops` carries `get_ssl_sock_ctx() -> struct ssl_sock_ctx *` in its generic interface, and its `ssl_*` fetches reach into provider types directly — which is why WolfSSL and AWS-LC support has been such a grind |
| **Gave up** | Any provider-specific capability not expressible through `TlsInfo` requires changing the trait. A provider with a unique feature cannot smuggle it through |
| **Status** | **reasoned** |
| **Revisit if** | A must-have feature genuinely cannot be expressed in provider-neutral terms. Widening the trait is the correct response; reintroducing the escape hatch is not |

### 3.4 `pool_gc`: caches emptied per thread, and almost no allocation failure to retry (T445)

| | |
|---|---|
| **Gained** | `ibex_rt::pool_gc` runs where `HAProxy`'s does: SIGQUIT (the process goes on), SIGTTOU, SIGUSR1, the stop path after a stick-table purge, and a refused allocation. No thread is stopped: each worker empties its own `thread_local!` caches at its next loop pass (at most 100 ms later), where `HAProxy`'s `thread_isolate` stops them all. Ibex empties its caches completely: after a burst of 500 connections on 4 threads, SIGQUIT takes `show pools` `buffer` from 256 allocated (all cached) to 0, RSS 26.4 to 24.4 MB. `HAProxy`'s `pool_gc` frees only the shared free lists, not its per-thread caches: its counts stay at 112 allocated (~93 cached) and RSS goes 93.7 to 91.1 MB, the `malloc_trim` alone |
| **Gave up** | **Retry after collection exists only where the failure is seen.** Rust's global allocator aborts the process when an allocation fails; nothing in rustls, ring, the H2 or HTX code, or `Vec::push` returns the failure. The one recoverable site is a variable's memory (`ibex_sample::vars::reserve_more`, `try_reserve`): it collects and retries once, as `ssl_sock.c:6074` retries `SSL_new`. `HAProxy` retries `SSL_new`/`BIO_new` and its pools count `failures`; Ibex has neither, and its `failures` column stays 0. **`-m` is not an rlimit**: `HAProxy` sets `RLIMIT_DATA`/`RLIMIT_AS` so its allocations really fail and `pool_gc` can save one; Ibex's `-m` only sizes `maxconn` (`engine::apply_memmax`), so a burst past it is refused at accept, never at allocation, and an operator's `ulimit -v` makes Ibex abort where `HAProxy` would collect and go on |
| **Status** | **measured** — `show pools` and RSS before and after each signal on both (`tests/it/pool_gc_signals.rs` header) |
| **Revisit if** | Fallible allocation on the request path (T448: buffers that can fail and a wait queue): every new fallible site calls `pool_gc()` once before it gives up |

---

## 4. Scope

### 4.1 `mode tcp` at HAProxy 1.0 parity as Milestone 0

| | |
|---|---|
| **Gained** | A finishable milestone that exercises every layer — protocol, transport, mux, sedesc, stconn, stream, session, scheduler, poller — with **zero HTTP parsing**. And 1.0.2 is 3047 lines, small enough to build and run as a live differential oracle |
| **Gave up** | Nothing shippable to a real site until HTTP lands. A TCP-only proxy is a demo, not a product |
| **Status** | **measured** — 1.0.2 compiles (one fix: glibc 2.38 now defines `strlcpy`) and proxies traffic end to end |
| **Revisit if** | Never; this is sequencing, not exclusion |

### 4.2 No Lua, filters, SPOE, QUIC/H3, FCGI, cache

| | |
|---|---|
| **Gained** | A tractable, focused codebase. `src/hlua.c` alone is ~14k lines. For QUIC/H3, the architectural objection is structural: **Ibex has no datagram I/O at all** (UDP surface is three lines in `syslog.rs`). QUIC demuxes by CID from datagrams on a shared socket rather than 1 fd per connection; throughput requires `recvmmsg`/`sendmmsg`/GSO/GRO; TLS moves inside the packet layer; and loss recovery/congestion control are an entire stateful subsystem on a scheduler built for stream epoll. Connections are not file descriptors |
| **Gave up** | Every reg-test needing them is permanently `OUT_OF_SCOPE`, capping the scoreboard below 312 |
| **Status** | **measured** — triage in `data/regtests.json` |
| **Revisit if** | For Lua/filters: the core is finished and complete. For QUIC/H3: h2 is reachable and measured, a datagram I/O path exists for other reasons, and a concrete user requires it |

### 4.3 Not "99% HAProxy compatibility"

| | |
|---|---|
| **Gained** | A claim that can be true. "Passes N of HAProxy's own reg-tests" is verifiable by anyone |
| **Gave up** | A more impressive-sounding pitch |
| **Status** | n/a — this is a decision about honesty |
| **Revisit if** | Never |

---

## 5. Process

### 5.1 Copyleft licensing inherited from HAProxy

| | |
|---|---|
| **Gained** | Correctness. These are derivative works of GPL/LGPL code, and the split matches upstream's deliberate boundary |
| **Gave up** | **`ebtree` is LGPL-2.1-*only*** — upstream grants "version 2.1 exclusively", so it cannot be relicensed to LGPL-3.0. Everything else is GPL-2.0-or-later, so no proprietary use, and permissive-licensed projects cannot vendor this |
| **Status** | **measured** — read from the upstream headers |
| **Revisit if** | Impossible without a clean-room reimplementation |

### 5.2 Three-tier delegation: flash worker, pro reviewer, Opus supervisor

| | |
|---|---|
| **Gained** | Volume. 570 fetches, 211 converters, 172 CLI commands, 312 reg-tests extracted in one batch |
| **Gave up** | Everything must be verified. `agy`'s `SUCCESS` means the turn completed, never that the work was done, so the orchestrator now checks the artifact and reports where it looked |
| **Status** | **measured** — 10/10 spot-checked converter citations resolved; T04's stats header matched the live binary only after a correction round |
| **Revisit if** | Verification cost exceeds the work saved |

### 5.3 Validating against the running binary, not only the source

| | |
|---|---|
| **Gained** | Caught a real defect nothing else would have. T04's extraction of the `ST_I_PX_*` table was correct at 119 fields — but the binary emits **146**, with per-module `h2_*`/`ssl_*`/`h1_*` columns registered outside that table. A positional parser like hatop sees 146, so a 119-column model is wrong at the tail |
| **Gave up** | Requires building and running the reference, which is only cheap because we already do |
| **Status** | **measured** — corrected header is now byte-identical to live output |
| **Revisit if** | Never. Where a running HAProxy can answer the question, it is the better oracle |

---

## 6. Open, unverified, and owed

### 6.1 Arena descent vs embedded-node locality — **unverified**

The claim in [`design/006`](design/006-data-layout.md) §3: 28-byte nodes at 2.28 per
cache line beat C's scattered 40-byte embedded nodes, because descent cost dominates
dispatch cost by roughly the tree depth. **This is a layout argument, not a
measurement.** Settling it needs a benchmark on the run queue's real access pattern
(monotonic keys, `first`/`delete`/`insert` dominated) against a variant that embeds
nodes in the task arena.

### 6.2 Run-queue drain re-descends instead of using `next()` — **unverified**

`process_runnable_tasks` re-runs the circular `lookup_ge` for every task pulled, where
HAProxy walks with `eb32_next()`. O(depth) per task instead of O(1) amortised, chosen
because correctness under concurrent deletion was not worth reasoning about yet. At 280
tasks per pass and depth ≤ 32 this is ~9k steps; whether that matters is unmeasured.

### 6.3 `takeover()` not implemented — **decided 2026-10-04: per-thread pools first, a shared pool second**

Idle backend connections can only be reused by their owning thread, costing some reuse
ratio under uneven load. HAProxy needs three cooperating layers and ~60 lines for this,
and it can fail at each.

HAProxy keeps idle connections per server and per thread, and with `tune.idle-pool.shared`
(on by default) a thread that finds none `TRYLOCK`s its siblings' lists and takes a
connection over (`backend.c` `conn_backend_get`, `mux->takeover()`). Ibex keeps one pool
per worker, keyed by address and SNI, and never shares. Three ways were weighed (T151 item 7):

| | |
|---|---|
| **A** | Per-worker pools keyed by server, `pool-low-conn` / `pool-purge-delay` honoured. No locks; a connection idle on worker 1 stays invisible to worker 2. |
| **B** | One pool per server behind a mutex, `try_lock` with a fall-back to a new connect as HAProxy does, the fd moved to the taking worker's poller. HAProxy's model; a lock on every reuse and release. |
| **C** | Per-worker pools plus lock-free hand-over queues. No lock on the fast path; the most machinery and the most room for subtle bugs. |

**Decision (the user, 2026-10-04): A, then B.** A first because it fixes two keywords that are
parsed and ignored (AGENTS.md §5) and cannot cost the fast path. B second, to match HAProxy's
connection counts; it must keep `tools/allocprofile` at 4 allocations per request and put its
shared state behind a `Box` in `ProxyIdInfo` (`Proxy` is bounded in `struct_sizes.rs`).
**Gave up:** C's lock-free fast path. **Revisit if** B's lock shows in a profile.

### 6.4 Watchdog — **implemented 2026-10-17 (T361 slice 1); CPU-time like HAProxy, so a blocked (deadlocked) thread is still not caught**

`src/wdt.c` panics a thread that stops making progress. With hard affinity and no
stealing, a wedged thread silently strands every connection assigned to it.

| | |
|---|---|
| **Matches HAProxy** | A worker that spins is reported every tick (`WARNING! thread N has stopped processing traffic for M milliseconds ...`, from ~200 ms) and the process aborts about 1.2 s of that thread's CPU time into the stall (`PANIC! Thread N is about to kill the process (pid P).`, exit status 134; measured on both: HAProxy 11 warnings then the panic, Ibex 10). The thresholds are HAProxy's (warn from one tick, `stuck` past 1 s, abort at the next tick), measured on thread CPU time, so a starved or off-CPU thread is never killed. `warn-blocked-traffic-after` (1-1000 ms, HAProxy's texts) sets the tick. `show info` `BlockedTrafficWarnings` counts the warnings. CLI `expert-mode [on\|off]` and `debug dev loop <ms> [warn]` as HAProxy's (levels and answers measured). |
| **Differs** | No thread dump: HAProxy prints the stuck thread's backtrace, current task and lock history; Ibex prints neither (the core file has the stacks). The "M milliseconds" is counted from the monitor's first look, not from leaving the poller, so it is a lower bound by up to one tick. "S streams" counts the worker's sessions, not its CLI applets (HAProxy said 1 for a CLI loop, Ibex 0). `debug dev loop ... isolated` is refused (no thread isolation). |
| **Cost** | One relaxed store per loop pass, per task run and per CLI command, plus two around `epoll_wait`: no syscall, no lock, no allocation on the request path. A monitor thread wakes every tick and reads `/proc/thread-self/schedstat` (opened by each worker before the chroot) only for a worker whose counter did not move. |
| **Not caught (as in HAProxy)** | A thread blocked off-CPU: a deadlocked mutex, a blocking syscall (`debug dev delay 3000` is not reported by HAProxy either). Catching it needs a wall-clock check, which can kill a process the host starved: a decision for the user (tasks/T361-watchdog.md, decision 2). |

### 6.5 `struct server` and 60k-backend memory — **measured and verified**

| | |
|---|---|
| **Gained** | Compact server struct representation. Memory for 60,000 servers measured at:<br>- **Without checks**: **14.00 MB** (14,684,947 cumulative allocated bytes, ~245 bytes/server), >14× smaller than HAProxy's 207 MB (3,456 bytes/server).<br>- **With health checks**: **29.75 MB** (31,196,612 cumulative allocated bytes, 120,035 allocations, ~520 bytes/server), 7× smaller than HAProxy's 207 MB.<br>*(Note: Both numbers refer to `bytes_allocated` from `CountingAllocator` during construction, not RSS.)* |
| **Gave up** | Some monolithic embedded state in HAProxy (`struct check` etc.) is decoupled into optional structures and indexed side arrays (`ServerCheckState`). |
| **Status** | **measured** — verified and pinned to ≤ 20 MB bound (without checks) and ≤ 35 MB bound (with checks) in `crates/ibex-rt/tests/request_allocations.rs` (`sixty_thousand_backends_memory_bounded` and `sixty_thousand_backends_with_checks_memory_bounded`). |
| **Revisit if** | Backends require heavy embedded state that cannot be modeled compactly or shared across worker contexts. |

**Tripwire (T255, 2026-10-10):** `sixty_thousand_backends_with_checks_no_further_growth` in the same file pins the current cost (54,034,102 bytes, 180,072 allocations; +5% / +1%) so the baselined failure cannot grow silently; the 35 MB test stays the target. T304 moved its figures down to 35,525,575 bytes and 120,449 allocations (the test alone, `--exact`, as the gate runs it).

**2026-09-23: the with-checks figure moved to 47.09 MB and the bound was deliberately not
raised.** Implementing `option httpchk`, `http-check` and `tcp-check` (T36) took the
60,000-backend-with-checks measurement from 29.75 MB to 49,375,208 bytes:

```
before   29.75 MB   120,033 allocations
after    47.09 MB   120,042 allocations
```

The allocation **count** is unchanged — nine more across sixty thousand servers — so nothing
new is being allocated per server. Each `ServerCheckState` simply got bigger, because it now
carries the check configuration: method, URI, version, the expect rules, the tcp-check step
list. That is +289 bytes per server, and it is the cost of the feature rather than a leak.

`sixty_thousand_backends_with_checks_memory_bounded` fails at its 35 MB bound as a result,
and **it is being left failing on purpose.** `nudge-agy-8` set the rule when this bound was
created: *"Do not simply raise the bound. The bound is not the finding."* A bound that moves
whenever it is inconvenient measures nothing.

The reason not to optimise this now is more interesting than the number. Ibex implements a
fraction of HAProxy's feature set, and every feature still to come — the shared idle
connection pool, stick-table synchronisation, the cache, `log-format` evaluation — will add
per-server or per-session state of its own. **We do not yet know what the memory profile of a
feature-complete Ibex looks like**, so tuning a struct against today's partial set is
optimising toward a shape that will not exist. 47 MB is still 4.4× better than HAProxy's
207 MB for the same 60,000 backends, which is the comparison that matters, and it leaves
plenty of headroom to spend on correctness first.

The right time to revisit is when the feature set is close enough to HAProxy's that the
comparison is like-for-like. Until then this entry records the trajectory rather than a
target: **14.00 MB bare, 29.75 MB with TCP-connect checks, 47.09 MB with HTTP checks**, and
the next number belongs beside them.

**2026-10-04 (T160): the bytes above were one worker's; every worker held its own.** Each
worker got a clone of every `Proxy` (and of the parsed `Config`), and every proxy kept one
set of counters per thread. At 10,000 backends that was ~15 KB per backend per worker. The
workers now share one `Arc<Vec<Proxy>>` (`engine::Proxies`); nothing on the data path
takes it mutably (the compiler holds that line: `Proxies` has no `DerefMut`), and the rare
writer, a CLI or stats-page admin command, copies it for its worker with
`Proxies::make_mut`, as every worker had before. The redispatch's "avoid this server" moved
to a thread-local (`lb::with_avoided`); the counters are one set per proxy, as `HAProxy`'s
are per thread group; the fd table is reserved rather than filled (2 MB per worker at the
default 65,536 connections). Startup `VmRSS`, release build, `global maxconn 1000`, one
frontend and N backends of one server each (`/proc/<pid>/status`, 2 s after the bind
answers):

```
                       nbthread 1   nbthread 16   delta
HAProxy 3.5-dev8   10       22.0 MB       23.8 MB    +1.7
                 1k       30.7 MB       34.2 MB    +3.4
                10k      109.6 MB      130.6 MB   +20.9
Ibex before      10       10.2 MB       44.8 MB   +34.6
                 1k       53.6 MB      367.9 MB  +314.3
                10k      450.4 MB    2,550.4 MB  +2,100
Ibex after       10        8.0 MB        9.1 MB    +1.2
                 1k       33.1 MB       35.4 MB    +2.3
                10k      263.3 MB      277.6 MB   +14.3
```

Pinned by `crates/ibex-rt/tests/worker_proxy_memory.rs`: an extra engine costs 153 KB
whatever the backend count (counting allocator), and the binary at `nbthread 16` stays
within 20 MB of `nbthread 1` at 10,000 backends. One thread at 10,000 backends is still
2.4x `HAProxy` (263 MB against 110 MB): that is per-backend heap in the one shared copy
(a suspect, not measured: the 22 predefined ACLs are compiled into every proxy), and is
the next number to chase.

**2026-10-11 (T304): back under 35 MB, 33.88 MB (35,525,575 bytes, 120,449 allocations, the test run alone).**
The figure had reached 52,598,206 bytes (50.16 MB), 180,070 allocations: ~877 bytes and
three allocations per server, of which the test's own `Server` lines are 192, the proxy
without checks 138, and the checks ~545. Per checked server there were a 440-byte `ServerCheckState`, a boxed 48-byte
`ServerCheckConfig` (the third allocation), and a scheduler task and timer node whose arenas
grew by doubling to 65,536. Now:

- `ServerCheckConfig` is an `Arc`, one per run of servers whose parameters are equal
  (`engine::server_check_configs`): one allocation per backend instead of per server.
- The resolved `option httpchk` / `http-check` / `tcp-check` configuration
  (`ResolvedCheckConfig`) is registered by the parser as an `Arc` shared by every server of
  the section that resolves to the same (it was a deep copy per server, two or three times
  over in the registry, and deep-cloned again on every check run); its compiled `http-check
  send` log-formats are shared the same way (`HttpSendFormats::shared_for`). This one does not
  show in the 60,000-server test, which builds its `Config` in code, and is the larger saving
  for a parsed configuration with HTTP checks.
- What only a running check uses (the protocol sub-state, its buffers, the `tcp-check`
  connect step, the check's variables, the fd number; the socket and its transport stay
  inline) is a `CheckRun` held while the check runs and
  returned to a per-thread pool when it ends (`CheckRunSlot`); after the first round of checks
  a check run allocates nothing for it, and memory is proportional to the checks in flight.
- `Scheduler::reserve` sizes the task arena and timer tree for the checks at boot.
- The proxy and server indexes are `u32`, the last check's `info` a `Box<str>`, and the
  check's start tick lives in its `CheckRun`.

`ServerCheckState` is 200 bytes (`struct_sizes.rs` bound lowered from 464). On the check path
nothing takes a lock or a reference count that did not before: a TCP-connect check touches
no `Arc`; an HTTP or `tcp-check` run clones the `Arc` of its resolved configuration where it
used to deep-clone the configuration itself. The margin is 1.17 MB (~20 bytes per server):
the next per-server field belongs in `CheckRun` or behind a pointer. Of the figure, ~540 KB
and ~378 allocations are the process's one-time initialisation, paid by whichever engine is
built first: 358 KB of it is compiling the predefined ACL `HTTP_URL_ABS`'s regex
(`url -m reg ^[^/:]*://`), 82 KB `LOCALHOST`, 81 KB the sample registry. The regex is the
next thing to look at if this number is chased again.
Trajectory: **14.00 MB bare, 29.75 MB with TCP-connect checks, 47.09 MB with HTTP checks,
50.16 MB at T255, 33.88 MB after T304.**


### 6.6 Map converters in-memory caching — **resolved**

`match_map` in `crates/ibex-sample/src/registry.rs` previously called `std::fs::read_to_string` and
scanned the file linearly for each sample evaluation. That is now resolved: `registry.rs` has
`MAP_CACHE` (`CachedMapTable`) with a read-lock fast path and the disk read and regex/prefix parsing
happening once upon initial load.

Gained: eliminate per-request filesystem I/O (`read(2)`) and heap re-parsing on the hot data path.
Gave up: an `RwLock` read acquisition per sample evaluation, which is lock contention across threads
on the data path (though avoiding any syscall).
Status: **resolved and measured** — cached lookups verified in `crates/ibex-sample/tests/sample_semantics.rs`.

### 6.7 Request and response header size limit -- **resolved 2026-10-10 (T265): Ibex matches HAProxy**

| | |
|---|---|
| **Was** | Ibex compared the wire length with `tune.bufsize - tune.maxrewrite` (3072 bytes at 4096/1024); HAProxy 3.5 accepts 2997, because its HTX block descriptors and start line take buffer space first. |
| **Now** | T265 models HAProxy's HTX cost for request and response heads (`txn::htx_head_cost`, `htx_response_head_cost`): 2997 bytes at 4096/1024, and the same per-repeated-header cost, measured to the byte against HAProxy 3.5-dev8 (crates/ibex-rt/tests/request_head_limit.rs; tcp_proxy's boundary test corrected to the measured 2997/2998). A response head too large now gets 502 at once instead of a 504 after `timeout server`. With the default maxrewrite both give the same clean step (T272 D1). |
| **Revisit if** | HAProxy changes its HTX layout (the model is a byte count per block, not a copy of HTX). |

### 6.8 HTTP/2 flood mitigation knobs off by default for HAProxy compatibility

| | |
|---|---|
| **Gained** | Strict compatibility with HAProxy 3.5's tuning model. Knobs implemented and wired directly to `H2MuxContext`: `tune.h2.fe.max-total-streams` (stream cap per connection), `tune.h2.fe.glitches-threshold` (graceful `GOAWAY` advertising future stream `0x7fff_ffff` with `NO_ERROR` at 75%, hard close `GOAWAY` with `EnhanceYourCalm` at 100%), and `tune.h2.fe.max-rst-at-once`. Legitimate clients generating occasional stream resets (e.g. browser navigation cancels) are not prematurely terminated. Unimplemented `tune.glitches.kill.cpu-usage` is explicitly refused at parse time rather than silently ignored. |
| **Gave up** | Secure-by-default behavior. Shipping flood mitigations defaulted to zero (disabled) means an unconfigured proxy does not automatically kill rapid reset floods. |
| **Status** | **measured and verified** — verified in `crates/ibex-rt/tests/h2_flood_knobs.rs` (all 3 tests pass: unconfigured flood survival, `max-total-streams` cap enforcement, and graceful 75% `GOAWAY` preceding hard close) and `crates/ibex-rt/tests/h2_multiplexing.rs`. |
| **Revisit if** | Once compatibility is established. HAProxy's defaults here are compatibility decisions, not security ones. Shipping a flood mitigation off by default means an unconfigured Ibex has none, and "HAProxy does it too" is a reason, not a justification. Revisit once compatibility is established: a proxy whose stated purpose is surviving hostile traffic has a weak argument for inheriting a permissive default it did not choose. |

### 6.9 QUIC stays declined — the architectural constraint is fd-per-session, not HTX

| | |
|---|---|
| **Gained** | Architectural clarity and focus. Verified against the HAProxy codebase that HTX is not a blocker or dead end for QUIC/H3: <br>- `HTX introduced in HAProxy`: 2018-10-22 (`a3d2a16fa`)<br>- `QUIC mux introduced`: 2021-02-18 (`dfbae766b`)<br>- `htx_` calls in `src/mux_quic.c`: **0**<br>- Distinct `htx_` calls in H2 path: 40 (`mux_h2.c` + `h2.c`)<br>- Distinct `htx_` calls in H3 path: 30 (`mux_quic.c` + `h3.c`)<br>- QUIC-specific API in `htx.h`: **none**<br>HTX is 28 months older than any QUIC code in HAProxy and does not touch `mux_quic.c` (which operates on per-stream `qcs` buffers, converted to HTX by `h3.c` using a subset of H2's HTX API). |
| **Gave up** | QUIC / HTTP/3 protocol support remains declined (bind prefixes `quic+`, `dgram+`, `quic4+`, `quic6+` are refused by name at config parse time). |
| **Status** | **measured and verified** — the actual constraint is the fd-per-session architecture in `crates/ibex-rt/src/proxy.rs` (`pub struct TcpSession { pub cli: OwnedFd, ... }`), where thousands of UDP QUIC connections share a single socket demultiplexed by Connection ID. The architectural commitment is not to deepen the fd-per-session assumption gratuitously across `ibex-rt`. |
| **Revisit if** | Concrete user requirements demand UDP datagram I/O (`recvmmsg`/`sendmmsg`/GSO/GRO) and the session abstraction is decoupled from owning a single file descriptor. |

### 6.10 Caller-borrowed HTX buffer and zero-allocation data path

| | |
|---|---|
| **Gained** | `HtxSlice<'a>` operates directly over caller-provided byte slices backed by pooled `Buf` (`ibex-rt/src/buf.rs`). `HtxBuffer::with_capacity` (16,384 B) and `HtxBuffer::to_h1_wire` (8,192 B) eliminated completely from the data path. Total steady-state request allocations dropped from 16 allocs / 25,038 bytes to 5 allocs / 124 bytes (`allocprofile`). |
| **Gave up** | Borrow checker lifetimes require scoped borrows around `HtxSlice::new(raw_slice_mut)` in `TcpSession` and separate scratch buffers for downstream rule modifications. `HtxBuffer` becomes an ownership convenience for unit/differential tests rather than a data-path type. |
| **Status** | **measured** — 0 allocations for `HtxBuffer::with_capacity` and `to_h1_wire`, 5 allocs / 124 bytes measured per request in `tools/allocprofile`, pinned in `crates/ibex-rt/tests/request_allocations.rs`. |
| **Revisit if** | Dynamic reallocation of HTX buffers becomes necessary for requests exceeding standard buffer size classes. |

### 6.11 HAProxy C FFI Differential Oracle (`ibex-h1-sys` & `ParserKind::HaproxyFfi`)

| | |
|---|---|
| **Gained** | Pure C reference parser integration for differential testing without modifying the main daemon. Compiles reference HAProxy `h1.c` and `http.c` with a minimal stub crate (`crates/ibex-h1-sys`). Differential testing validates 100% agreement on framing violations and documents exact semantic differences. |
| **Gave up** | Feature-gated behind `haproxy-ffi` (default off). HAProxy's C parser performs in-place byte mutation on unfolded headers (`start[eol] = ' '`), requiring an isolated mutable scratch buffer in the FFI adapter to prevent SIGSEGV on `.rodata` slices. |
| **Status** | **measured** — 20 test vectors in `haproxy_ffi_differential.rs` passing, zero unsafe in `ibex-proto`, unsafe isolated to `ibex-h1-sys`. |
| **Revisit if** | Upstream HAProxy changes C header parsing function signatures in future 3.x releases. |



### 6.12 `str` samples and variables stay UTF-8 (`String`), not arbitrary bytes — **decided 2026-10-10: leave unimplemented**

> **Revisited 2026-10-17 (T363a, T364).** Bytes are now kept losslessly (bytetext; before T363a a binary sample stored in
> a variable lost every byte >= 0x80 to U+FFFD, which broke `secure_memcmp` against a decoded hash). What remains is
> the lost **type**: a variable is always `str`, so HAProxy's `bin -> str` NUL cut and typed `set-var` conditions differ
> (measured table in tasks/T364-typed-variables.md; reg-tests `hashes.vtc`, `cond_set_var.vtc`). T364 plans typed variables.
>
> **T364 S2 (2026-10-18): the type half is done.** A variable holds a `Sample` (`crates/ibex-sample/src/vars.rs`),
> so `var()` gives back what was stored and casts start from that type, as in HAProxy. What stays decided as above is
> the other half only: `Sample::Str` is a `String` (bytetext), not bytes.

| | |
|---|---|
| **Gained** | Every `str` sample, variable and log field is a Rust `String`: valid UTF-8 by construction, so no converter, regex or log writer has to handle invalid sequences, and `fancy-regex` (which has no byte API) can match every subject. No migration of ~1,200 lines of sample/variable code and ~290 test sites (cost measured by T272 D2, `tasks/T272-progress.md` on agy/T272D f6652b4). |
| **Gave up** | Byte-exact parity where HAProxy cuts or carries non-UTF-8 data in a `str`: `concat` past 16383 bytes keeps exactly 16383 bytes in HAProxy (a cut inside a multi-byte character), Ibex backs up to the character boundary (16382 or 16383, measured by T265). `str` converters fed non-UTF-8 input do not see the raw bytes HAProxy would. |
| **Status** | **measured** — the 1-byte `concat` difference by T265 (`tasks/T265-progress.md`); the cost by T272 D2. No workload is known to depend on non-UTF-8 `str` samples. |
| **Revisit if** | An operator's configuration demonstrably needs raw non-UTF-8 bytes in `str` samples or variables (e.g. a binary header value round-tripped through a variable), or a reg-test on the board fails because of it. Then do it as one dedicated task after T260, with the regex question (lossy match or refuse) decided first. If everything works, leaving it unimplemented is the safer choice: a byte-string data path removes a guarantee the rest of the code relies on. |

### 6.13 Object pools and a request path with no malloc — **not implemented; decided 2026-10-17: the goal is zero**

| | |
|---|---|
| **Gained** | Nothing yet: today's design is simpler code (owned `Vec`/`String`/`Box` values per request, freed on drop) and a small footprint (~10 MB RSS where HAProxy's pools hold ~90 MB in the same test). |
| **Gave up** | HAProxy has 69 named pools (buffers, trash, sessions, streams, resolvers, ...) with a per-thread cache (`tune.memory.hot-size`, 512 KB) and makes **0 malloc calls per request** in steady state (LD_PRELOAD count, keep-alive and new connections, 1 and 4 threads). Ibex pools only the I/O buffers (`buffer`, `small_buffer`, `large_buffer`; up to 64 spares per thread) and the shipped binary makes **about 6 malloc/free pairs, 273 bytes per request** (sizes 1, 3, 10, 10, 56, 192; `tools/allocprofile`'s 4 allocations / 127 B counts only the in-process engine path of one `Connection: close` request). Not implemented either: `tune.buffers.limit`, `tune.buffers.reserve`, `tune.memory.hot-size` (refused as unknown until S1, 6.28; it now bounds the `ibex_alloc::Pool`s only), `-dM` pool debugging (refused since T351: no pools to poison), HAProxy's `show pools` detail (T352). |
| **Why it matters** | The user's requirement (2026-10-17): a request must not need a malloc. Every allocation a client can cause is one an attacker can make fail. In Rust a failed allocation does not return NULL to unchecked code (that C cascade cannot happen): the global allocator calls `handle_alloc_error`, which **aborts the worker** — every connection on it is lost, a denial of service instead of one failed request. HAProxy instead takes from a pool sized in advance and, when a pool is empty, fails only that stream (`tune.buffers.reserve` keeps buffers back for streams already running). |
| **Status** | **measured** 2026-10-17 (`~/ibex-worktrees/review/pools-haproxy-vs-ibex-2026-10-17.md`). Planning of the pools (which objects, per-thread caches, a bounded and fallible take on the request path, what to do when a pool is empty, how to count and test "0 allocations per request" on the real binary) is set for the 2026-10-17 21:00 planning session (Fable), with T344. |
| **Revisit if** | Done when the request path makes 0 allocations per request on the shipped binary (counted, pinned in a test), and an empty pool fails one stream, not the process. |

**Plan (2026-10-18).** Spec of HAProxy's pools and the port design: `docs/design/pools-2026-10-18.md`
(119 pools in HAProxy's source, 76 registered with a blog config, measured sizes; slices P0-P9 in
its §5, tracked as T372). Measured on the oracle while writing it: HAProxy does **not** pre-allocate
its pools (2 buffers + 4 emergency buffers per thread at start, grows on demand, never shrinks), so
its "0 malloc per request" holds after warm-up; it still mallocs on some request paths (`set-var`:
2 per request; OpenSSL: 9 per TLS keep-alive request, 714 per new TLS connection; Ibex on rustls: 3
and ~137). The user's direction (2026-10-18) goes further: runtime memory is a stack variable or a
pool chunk, aiming at soft-realtime (no allocation after start-up), because malloc can block and a
failed one aborts the worker.

**Variables (T364 S6, 2026-10-18): 0 per keep-alive request.** `set-var` stores into a slot store
with interned names whose value buffers keep their capacity (`ibex-sample/src/vars.rs`); a stream's
store is swapped into the thread for a run, and ended sessions' stores are kept per thread (one
owner type, to move onto T372 P0 `Pool<T>`). Shipped binary, `nbthread 1`, allocations per keep-alive
request: none 9; 1 int 11 -> 9; 1 str 14 -> 9; int+str+sess 18 -> 9; 5 ints 19 -> 9. Left: reading
a `str`/`bin` variable copies it into an owned `Sample` (1 allocation; HAProxy's `smp_dup` uses a
trash chunk), and a non-constant expression's sample is allocated by the evaluator, as are
`Expr::eval_sample`'s converter-argument clones. Both go only with borrowed samples in the evaluator.

**Open design questions, to be decided by testing** (user, 2026-10-18: "this will require more
testing to determine the correct way to run"). Each lists the options and what to measure before
choosing; nothing is decided yet.

| | Question | Options | What decides it |
|---|---|---|---|
| **Q1** | Grow or fixed pools? | (a) HAProxy's grow-on-demand-and-keep; (b) fixed, pre-sized at start from `maxconn`/`-m` (auto maxconn on the 64-core host is 524274: ~17 GB of buffers, so fixed needs an explicit limit); (c) grow by default with a fixed mode as an opt-in; (d) grow, pre-warmed at start to a fraction of maxconn | RSS at idle and after a burst for a blog config, allocations during the first burst, latency of the first requests after start (soak + netfuzz 40k shapes), behaviour at the limit |
| **Q2** | Give memory back after a burst? | (a) keep shrinking (`trim_idle`, `SessionArena::trim_tail`, the back-to-baseline leak test, merged 10-17/18): RSS returns, the next burst mallocs again; (b) keep the peak as HAProxy (flat after the burst; the leak test then checks "no growth after the first burst" instead of "back to baseline"); (c) shrink only in grow mode | repeated bursts in the soak: RSS curve and malloc count per burst under (a) and (b); whether an operator can still tell a leak from a kept peak (`show pools` used vs allocated) |
| **Q3** | No buffer available? | (a) wait in a queue as HAProxy (`b_alloc` wait list, emergency buffers; the spec's recommendation, queue pre-sized so waiting cannot allocate); (b) fail the stream (plan-2100 Z4, M1 shape) | `tune.buffers.limit` small on both proxies: who is served, latency, log flags; slow-client attack (T371 shapes) with the limit reached |
| **Q4** | Hold Ibex to 0 where HAProxy itself mallocs? | (a) 0 everywhere (vars pool P7, rustls unbuffered API, error snapshots); (b) match HAProxy's exceptions and list them here | allocation census per path (`review/alloc-census-2026-10-18.md`), cost of each exception under attack |
| **Q5** | `show pools` names | (a) HAProxy's name only where the object really corresponds, Ibex names otherwise (spec proposal); (b) HAProxy's full list for script compatibility | which scripts/dashboards read `show pools` (likely few); honesty rule (AGENTS.md 5: no name for an object that does not exist) |

### 6.14 Slow-client defences not implemented yet — **not a decision to leave out; tracked in T349 for M1**

| | |
|---|---|
| **Gained** | Nothing; these were missed, not traded. Everything else a blog uses against slow clients matches HAProxy (docs/differences.md "Slow clients"). |
| **Gave up** | `maxconnrate`, `maxsessrate`, `rate-limit sessions` and `timeout client-fin` are refused at load. `tcp-request content` rules decide on a partial first segment instead of waiting for the inspect delay (false rejects of slow clients). |
| **Status** | **measured** 2026-10-17 live against HAProxy 3.5-dev8 (T349 audit). The HTTP/2 idle timers (`timeout http-keep-alive`, then `timeout http-request`, then `timeout client`, as `h2c_update_timeout`) were fixed the same day (T349a). |
| **Revisit if** | Done when each is implemented with an oracle test, or deliberately refused with a reason recorded here. |

### 6.15 Keywords refused instead of accepted and dropped (T351, T358 #4) — **not implemented; refused at load**

| | |
|---|---|
| **Gained** | AGENTS.md rule 5: an operator never gets a keyword that parses and does nothing. Each one below used to load and be ignored (or, for `fc_rtt`, always return 0). |
| **Gave up** | `fc_rtt`, `fc_rttvar`, `bc_rtt`, `bc_rttvar`: reading `TCP_INFO` needs `getsockopt` with a C struct, which neither `nix` nor `rustix` exposes and `ibex-rt` forbids `unsafe`; the reg-test `sample_fetches/tcpinfo_rtt.vtc` now fails at load. `resolvers` sections and `resolvers` in `defaults`: Ibex does no DNS resolution at run time (M1 scope; `init-addr`, `resolve-net`, `resolve-opts`, `resolve-prefer` are still accepted and ignored, T351 follow-up). `-dM` in every form (no pools, §6.13). `no <keyword>` other than `no option` and `no log` (HAProxy refuses those too, with the same message). |
| **Status** | **measured** 2026-10-17 against HAProxy 3.5-dev8 `-c` (exit code and message), except the `resolvers` refusal text, which is Ibex's own. |
| **Revisit if** | A blog configuration needs RTT in its logs (then a small audited `unsafe` wrapper for `TCP_INFO` in `ibex-mmsg` or `ibex-alloc`'s style), or servers named by DNS that change at run time (then `resolvers`). |

### 6.16 `Tw` 1 ms on a cold first request where HAProxy logs 0 (T367) — **resolved (T375): stamped from the loop's per-iteration clock**

| | |
|---|---|
| **Gained** | Each log timer is a real clock read (`Instant::now()`) when the event happens, so `%Tw`, `%Tc`, `%Tr`, `%Ta` are elapsed time to the millisecond even inside one event-loop iteration. |
| **Gave up** | HAProxy stamps `request_ts` (src/http_ana.c) and `t_queue` (src/backend.c) from `now_ns`, the thread's clock refreshed once per loop iteration (`clock_update_date` in `run_poll_loop`, src/haproxy.c:2246, 2287): a request parsed and connected in the same iteration logs `Tw` 0 by construction, whatever ran in between. Ibex reads the clock twice, so `Tw` is 1 whenever a millisecond boundary falls between the reads: P ≈ gap / 1 ms. Measured 2026-10-18 (`strace --seccomp-bpf -e trace=read,socket -T -tt`, host load ~10): request `read` return to `socket()` is 426-729 µs on a debug build's first request (273-381 µs on its second), 133-269 µs cold and 100-129 µs warm in release. Under that strace the debug first request logged `Tw` 1 in 3 of 4 runs, the second 0 of 4 (VV-13's observation); without strace 0 of 8 (debug) and 0 of 12 (release): the gate's load is what pushed a cold debug request past a millisecond. |
| **Why it matters** | The cold cost is real but once per worker: the first request allocates the 16 KB HTX buffer (`htx_reserve` → `Buf::alloc_if_needed` → `buf::alloc_standard`, `vec![0u8; 16384]`; the request buffer was already taken by the listening probe) and 8 small objects — 14 allocations / 18,273 bytes against 5 / 181 bytes for every later request (`tools/allocshim`) — and takes 8-10 minor page faults (3-4 zeroing the fresh buffer, 2 in glibc's heap top, 1-2 stack growth; `perf record -e page-faults/period=1/u`); it costs about twice the CPU of a warm request (`cycles/freq=20000/u`: 17-26 vs 6-17 samples debug, 9-14 vs 5-7 release), spread over the path, no single initialiser. It does not recur: the pool keeps 64 spare buffers per thread and `trim_idle` runs only after 64 fresh allocations, so after a 3 s idle the next request still made 5 allocations. HAProxy's first request pays the same (one aligned 20,832-byte allocation, 3 faults, 0 afterwards, same shim with `-db`); its `Tw` cannot show it. Not from the 2026-10-11..18 merges: the 2026-10-10 release binary makes the same first request (15 allocations / 18,321 bytes, then 6 / 229; one 48-byte allocation per request that Z1 has since removed). |
| **Status** | **measured** 2026-10-18 (T367). Note for whoever samples `allocshim` right after the listening probe: the 142 MB / 1,135 allocations it then attributes to the first request are start-up (the session arena's `with_capacity(65536)` of 1592-byte entries is 104 MB virtual, untouched, shrunk to 128 entries by `trim_tail` after the first session) — settle 0.3 s first. |
| **Resolved** | T375 (2026-10-18): every log timer (`StreamLog::start`, `first_byte_now`, `request`, `queue`, `connect`, `data`, the close time and `Ta` of the line) is read through `txnlog::loop_now()`, the thread's clock set once per loop pass right after the poller (the same `Instant` that gives the scheduler's tick, so no extra clock read). Two events of one pass share a timestamp, as `now_ns`: a request parsed and connected in one pass logs `Tw` 0 under any load. `Ta`/`Tr` now move by at most one pass (HAProxy's semantics). Test `cold_start_timers` (10 cold starts under CPU burners): red before (`Tw` 3, run 6), green after. About 10 clock reads per request fewer. |

### 6.17 `tune.vars.*` accounting differs from HAProxy's in four places (T364 S5) — **measured 2026-10-18; accepted**
| | |
|---|---|
| **Implemented** | The six `tune.vars.{global,proc,sess,txn,reqres,check}-max-size` limits (`strtol` into `unsigned int`, as `vars_max_size`) are enforced by `var_accounting_add`'s nesting (req/res in reqres, txn, sess; txn in sess; check in check and sess; all in proc and global). Cost per variable `VAR_STRUCT_COST` = 88 bytes (x86-64 build of 3.5-dev8: a limit of 87 refuses one `int`, 88 takes it) plus the bytes of a `str`/`bin`/unusual method. `tune.vars.from-map.max` is accepted; `set-vars-from-map` stays refused, so nothing reads it. |
| **Differs 1** | A `str` that does not fit turns the variable into a `bool` in both, but HAProxy's `bool` keeps the old integer in the union: `int(7)` then a 10-byte `str` under `txn-max-size 90` prints `7` and `add(1)` gives 8. Ibex stores `Bool(old != 0)`: `1` and `2`. Decided by the user (Q1). |
| **Differs 2** | HAProxy creates a `proc.` variable (88 bytes, permanent) for every name the configuration mentions (`set-var(proc.x)`, `var(proc.x)`), at load; a limit too small makes the load fail (`error detected ... while parsing 'http-request set-var(proc.b)' rule : (null)`), and a txn variable is refused after `proc-max-size 100` once one such name exists. Ibex charges a `proc.` variable when it is first set, and refuses nothing at load. |
| **Differs 3** | The `proc`/`global` total is the `proc.` variables plus the variables of the stream that is running, not those of every session. HAProxy's counter is process-wide. S6 (store) and S7 (sessions) are where the other sessions' counters can be kept. |
| **Differs 4** | `sess-max-size` counts one stream's variables; with several H2 streams on a connection HAProxy shares one `sess` counter (S7). |
| **Status** | `check-max-size` is enforced (`vars::set_in`, check.rs `run_var_rules`) but has no end-to-end test. |

### 6.18 No finite-field DHE (`DHE-*` ciphers, `ssl-dh-param-file`, DH in `crt` files) — **decided 2026-10-18: not supported; ECDHE only**
| | |
|---|---|
| **What HAProxy does** | With OpenSSL, a `bind ... ciphers "DHE-RSA-AES256-GCM-SHA384" ssl-max-ver TLSv1.2` offers TLS 1.2 finite-field Diffie-Hellman, with parameters from `ssl-dh-param-file`, from a DH block appended to the `crt` PEM (also via `set ssl cert`), or generated to the size of `tune.ssl.default-dh-param` (capped by the key size). `reg-tests/ssl/ssl_dh.vtc` checks it with `openssl s_client` ("Server Temp Key: DH, 2048 bits"). |
| **Why Ibex has none** | rustls 0.23 (0.23.45 in the tree) parses DHE in its TLS 1.2 handshake and has a `SupportedKxGroup::ffdhe_group` hook, but neither of its crypto providers ships a DHE cipher suite or an FFDHE key-exchange group. Ibex uses the `ring` provider (crates/ibex-tls/Cargo.toml), whose groups are X25519, P-256 and P-384. Offering DHE would mean Ibex writing its own provider: TLS 1.2 DHE suite definitions plus a constant-time modular exponentiation over 2048-4096-bit numbers. That is new crypto code of our own, which is exactly what the memory-safety rule for dependencies (pure-Rust, no home-made crypto) and the sealed TLS trait (§3.3) are there to avoid. |
| **Why that is acceptable** | rustls leaves FFDHE out by design. ECDHE gives the same forward secrecy, faster, with standard curves. DHE carries a history of weak or custom primes (Logjam, 2015), servers that reuse the key, and the Raccoon timing attack on TLS 1.2 DHE (2020). Browsers no longer offer DHE suites (Chrome since 2016, Firefox since 2020), so a client that can only do DHE is a very old or embedded one. |
| **What Ibex does** | TLS 1.2 and 1.3 with ECDHE (X25519, P-256, P-384). `tune.ssl.default-dh-param` is accepted and has no effect (parser/mod.rs inert list): there is no DHE for it to size, so a config written for HAProxy keeps loading. A DHE cipher name and `ssl-dh-param-file` must be refused at load with a message naming this section (T399), and a DH block in a `crt` PEM ignored with a warning (T399). |
| **Board** | `ssl/ssl_dh.vtc` cannot pass; T399 marks it OUT_OF_SCOPE in the runner. |
| **Status** | **decided** (user, 2026-10-18). |
| **Revisit if** | rustls or a provider we already depend on ships FFDHE, or a user brings a client that cannot do ECDHE. |

### 6.19 `ssl_f_*` certificate fetches: OID names and DN charsets (T398)

`ssl_f_der`, `ssl_f_sha1`, `ssl_f_serial`, `ssl_f_version`, `ssl_f_notafter`, `ssl_f_notbefore`,
`ssl_f_sig_alg`, `ssl_f_key_alg`, `ssl_f_s_dn` and `ssl_f_i_dn` read the certificate the resolver
picks for the ClientHello (`ibex_tls::x509`, a bounds-checked DER walk; no OpenSSL). Gap against
HAProxy: attribute-type and algorithm OIDs are named from a table of the common ones. `OpenSSL`
knows many more short names; Ibex shows a missing attribute as dotted (`1.2.3.4`) and a missing
signature or key algorithm as `UNDEF`. DN values are copied as raw bytes (no charset conversion
of BMPString/UniversalString) in the one-line form; `rfc2253` dumps non-text types as `#<hex>`.
The `ssl_c_*` fetches (the peer's certificate) are not implemented here.

### 6.20 rustls allocates 3 times per TLS request — **known M1 difference; fix is the rustls 0.24 port (T437 5a), waiting for 0.24.0**

| | |
|---|---|
| **Gained** | `rustls 0.23.45` (pure Rust, memory-safe, `#![forbid(unsafe_code)]` in `ibex-tls`) with its buffered `ServerConnection`/`ClientConnection` API, which is the simple one to use. |
| **Gave up** | Zero allocations per steady-state keep-alive TLS request. The allocation survey of 2026-10-19 (`~/ibex-worktrees/review/alloc-survey-2026-10-19/`, `asurv.sh`) counts **3 per request inside rustls**: `read_tls` filling rustls's own receive buffer, `take_received_plaintext` -> `into_vec`, and `encrypt` -> `PrefixedPayload::with_capacity` (one per outgoing record). Everything Ibex owns on that path is at 0. For scale, HAProxy with OpenSSL makes 13.2 mallocs per TLS keep-alive request with the same probe (8.6 from OpenSSL, 4.5 `posix_memalign` from its own pool refills: `hap-tls-h1s.txt`), so the gap is against Ibex's own goal of 0, not against the oracle. |
| **Why not fixed now** | 0.23's `unbuffered` API removes the two receive-side allocations (decryption in place in our buffer) but keeps the one per record on send: `MessageEncrypter::encrypt` returns an owned `OutboundOpaqueMessage`, and it is a public trait, so the fix is a breaking change that cannot be backported to 0.23. The `unbuffered` module is removed in 0.24, so porting to it would gain 2 of 3 and then have to be redone. |
| **Plan** | Upstream already has the fix: rustls#2940 (externalized input buffers, merged 2026-07-07) and rustls#3127 (caller-provided `MessageEncrypter` output, merged 2026-07-22), in `0.24.0-dev.1` (2026-07-23) and `0.24.0-dev.2` (2026-10-14). In 0.24, `Connection::read_tls(&mut dyn TlsInputBuffer, &mut Vec<u8>)` decrypts in place in a caller buffer and `write(plaintext, &mut Vec<u8>)` encrypts into a caller `Vec`: 0 allocations with a reused `Vec`. T437 part 5a ports `ibex-tls/src/transport.rs` and `ibex-rt/src/xprt.rs` (~35 call sites, frontend and backend; not QUIC) to it, backing the input with the pooled `Buf` and keeping a pooled, reused output `Vec` per connection. Prototype on `0.24.0-dev.*` in a branch; merge only once 0.24.0 is released. Notes: `upstream/rustls-caller-owned-buffers.md`. |
| **Status** | **measured** 2026-10-19; superseded by 6.22 (T440 ported to the 0.24 dev release). Nothing to file upstream (the change exists); once the port runs on a dev release, report on rustls#3068 or #3127 whether a proxy's steady state has 0 allocations per TLS record. |
| **Revisit if** | rustls 0.24.0 is released (port, then the TLS keep-alive scenario of the allocation test goes to 0), or the 3 per request show up as a cost in a TLS soak before then. |

Related and shipped (T437 5b): `tune.ibex.zero-buffers` zeroes the used part of a
buffer when it is released, so decrypted plaintext does not outlive its owner in the pools.
Default **off** since S1 (user 2026-10-24: "to keep the benchmarks against haproxy fair ... it
shows us where the performance gaps are"; HAProxy wipes nothing either; on the rules scenario,
ab1, off saves ~840 instructions per request). With it off, request and response bytes of the
plain I/O buffers stay in pooled or freed memory until overwritten. The TLS record buffers
(`ibex-tls` `conn::wipe_vec`, `transport.rs`) no longer follow it: they follow their own
`tune.ibex.ssl-zero-buffers` (default **on**, S2; 6.28). The
rustls-owned buffers are not Ibex's to zero; rustls zeroizes its key material (the plaintext it holds internally is the 3-allocation gap above).

### 6.21 Spare strings for the rules (T437) — **bounded, counted and given back since S1 (6.28); wiped only with `tune.ibex.zero-spares on`**

The header rules, formats, ACL fetches and `return` replies reuse per-thread strings
(`ibex_sample::spare`, `ibex_rt::reuse`) instead of allocating each request: a string that leaves
a header list or a sample goes back to its thread's spares, and the next one takes it with its
capacity. That is what brings the survey's rules from 65 allocations per request to 0 (and
`http-request return` from 4 to 0; `crates/ibex-rt/tests/request_allocations.rs`). Since S1 (as
fix/t444 did) a new connection's method and URI (`ReqText`) come from the spares too.

| | |
|---|---|
| **Bound** | As `HAProxy`'s per-thread hot cache: since S1 the spare strings (`spare_str`), header lists (`spare_list`) and the scratch buffers (`scratch_str`, `scratch_bytes`) are `ibex_alloc::Pool`s, and their footprints together stay under `tune.memory.hot-size` (524288 when unset, parsed as `HAProxy` parses it): past 3/4 of it a pool evicts down while it holds more than its share, past the whole of it the largest pools are evicted across (`pool_put_to_cache` / `pool_evict_from_local_caches`). Also at most 512 strings of 16 KiB and 16 lists. Before S1: 512 × 16 KiB = 8 MiB per thread (`tests/spare_strings.rs` measured 7864320 bytes kept after 600 requests at once; under 524288 now). |
| **Other caches** | `hot-size` reaches the `Pool`s only. The buffer pools (`buf.rs`) and the session/appctx arenas keep their own count limits until S2-S4 move them onto `Pool`s. |
| **Shown** | `show pools` lists `spare_str`, `spare_list`, `scratch_str`, `scratch_bytes` from the start (6.28 for how fresh the counts are); the bytes count in `show info`'s pool figures. |
| **Security** | `tune.ibex.zero-spares on` wipes a string's used bytes (each string's, for a list) when it is given back, whether it is kept or freed (`ibex_alloc::wipe_string`). **Default off** (user 2026-10-24: "it's one thing to wipe security-sensitive buffers, it's quite another for every request"; off keeps the comparison with HAProxy fair). With it off, header values (cookies, `Authorization`) and samples of an earlier request stay in a spare's capacity, or in freed memory, until reused or overwritten. Nothing reads past the length, but a memory disclosure elsewhere would find them. HAProxy does not wipe its pools either (`-dM` poisoning is a debug option). It costs ~1k instructions per request on the rules scenario (ab1), about 65 strings given back per request. |
| **Given back** | `pool_gc` (T445) empties the thread's pools (`ibex_alloc::drain_local_pools`) along with the other caches. |

### 6.22 TCP TLS runs on a pre-release rustls, `=0.24.0-dev.2` (T440)

| | |
|---|---|
| **What changed** | The TCP TLS path (`ibex_tls::tcp`, `ibex_tls::conn`, `ibex-rt/src/xprt.rs`, `srv_tls.rs`) uses rustls `=0.24.0-dev.2` with its `rustls-ring` provider, because 0.24 has caller-owned buffers: a steady-state keep-alive request over TLS makes 0 allocations (`tls_request_allocations`: TLS to plain 3 to 0 per request, TLS to TLS 13 to 0). 0.23 cannot do this. |
| **Cost** | A pre-release pin: the API may change before 0.24.0, and a fix may land on 0.23.x first and reach 0.24 later. We pin exactly (`=`) so a build never moves under us; every bump is a manual port. Two rustls versions are in the tree: QUIC (quinn), the log forwarder, `ring.rs`, and the test clients stay on 0.23 (`rustls`), the TCP path is `rustls24`. Binary size (release, same tree otherwise): stripped 10 920 512 to 12 204 696 bytes (+1.2 MB, +11.8%); with `debug = true` as `[profile.release]` ships it, 183 079 104 to 206 240 360 bytes. |
| **Why that is acceptable** | The zero-allocation request path is an M1 requirement; the dev pin is merged once gated green (user decision 2026-10-19). `ring` stays the crypto, so the memory-safety rule for dependencies holds. |
| **Status** | Open. |
| **Revisit** | Move to `0.24.0` when it is released (expected around Q1 2027; low confidence) and drop the duplicate rustls where QUIC can follow. |

### 6.23 A failed allocation aborts the whole process; HAProxy fails one stream (T446) — **measured 2026-10-24; open, waiting on Rust and on our own `try_*` work**

| | |
|---|---|
| **Difference** | In HAProxy, `malloc` returning NULL is checked: it gives memory back (`pool_gc`) and retries, fails that stream, or makes the buffer request wait (`b_alloc`). The process goes on. In Ibex, any infallible allocation (`Vec`, `Box`, `vec![]`, std, rustls, h2) that fails calls `handle_alloc_error`, which prints `memory allocation of N bytes failed` and **aborts**: every connection on every thread is lost. Stable Rust has no switch to change this. `-Z oom=panic` was removed upstream (rust-lang/rust#147725, 2025-12-10), and `set_alloc_error_hook` is unstable (#51245). Draft for upstream: `upstream/rust-recoverable-oom.md`. |
| **Measured** (2026-10-24, main 2fe0db33 release, Fedora HAProxy 3.0.30, both `nbthread 4`, proxy to a local HAProxy backend, `h2load --h1`; script and logs in `/tmp/t446/`, `run.sh`) | Start-up size: Ibex VmSize 905 MB / VmData 564 MB; HAProxy 232 MB / 54 MB. **Unlimited, 20000 conns:** both 200000/200000 2xx. **HAProxy** under `RLIMIT_AS` 250-400 MB (5 runs), `-m 300` (= `RLIMIT_DATA`) and `RLIMIT_DATA` 100 MB: alive every time, 42552-191328 2xx, 1211-11341 5xx, the rest refused; `curl` afterwards gets 200. **Ibex**, 20000 conns: `RLIMIT_AS` 990 and 1100 MB, and `RLIMIT_DATA` 640 and 700 MB: **aborted every time** (2323-10544 2xx). The core shows a 16 KiB buffer `vec![0; n]` in `buf::alloc_standard` (`buf.rs:364`), from `TcpSession::process_cli_io`. Ibex, 5000 conns, `RLIMIT_AS` 900-960 MB (5 runs): served every request or nearly, then **aborted while freeing**. `SessionArena::trim_tail` (`engine.rs:2050`) makes a fresh `Vec::with_capacity` of 104333312 bytes to give the old one back, so for a moment it needs a second copy of the arena. At 990 MB/5000 it survived. A log line reading `1638416384 bytes` is two threads' `16384` interleaved. |
| **`-m`** | HAProxy's `-m` sets `RLIMIT_DATA` (checked in `/proc/<pid>/limits`). Ibex's `-m` is only a `maxconn` budget (`engine::apply_memmax`) and sets no rlimit, so `ibex -m 64` never sees a failed allocation. Do **not** make Ibex's `-m` set the rlimit before the paths below are fallible: it would turn the budget into an abort. |
| **T445 "GC and retry"** | Applies only where a failure can be seen: a `try_reserve`/`try_*` call that returns `Err`. On an infallible path there is nothing to retry, because the process is already in `abort`. |
| **What would close it** | Upstream: a stable unwinding OOM hook or `-C oom=panic`, plus a per-stream `catch_unwind` in the loop. Ibex has no `catch_unwind` outside tests, so that would be new work: each stream's step would need to be unwind-safe and the stream torn down cleanly. Before upstream moves, Ibex's own large or per-connection allocations can be made fallible with stable `try_reserve`. That covers the shrink copy in `trim_tail` (on `Err`, keep the old buffer: done in T453, `engine::move_to_fresh`), the buffer pool (`alloc_standard`/`small`/`large`: refuse or queue the stream, T372 Q3), and arena growth on accept. Allocations inside rustls, h2 and std stay infallible. |
| **After S5** (2026-10-25, mem/s5) | Ibex's buffers come from their pools fallibly (`try_reserve_exact`; on a refusal `pool_gc` and one retry); a stream whose buffer cannot be had is answered `500` with `%ts` `I` and its phase, or closed once its response began (`TcpSession::fail_alloc`; tests `crates/ibex-rt/tests/buffer_alloc_failure.rs`, `tests/it/fail_alloc.rs`). Arena growth on accept was already fallible (S4). The request's method and target copy (`ReqText::set`) is fallible too. **The T446 run still aborts** (`/tmp/t446/run.sh`, `LT=data`, `RLIMIT_DATA` 640 MB, 20000 connections, release build of mem/s5, 3 runs each round): first round `memory allocation of 1 bytes failed` (and 3), core: `String::reserve_exact` in `ReqText::set` (`proxy.rs:575`) from `process_cli_io` (now fallible); second round (283-1813 2xx before) `memory allocation of 64 bytes failed` (and 128), core: `Vec<u32>::push` in `ebtree::Eb32Tree::unlink_and_recycle` (`ebtree/src/eb32.rs:668`), the timer tree's free list growing on a delete, from `Scheduler::unlink_wq` / `destroy` (`ibex-sched/src/sched.rs:337`). Not fixed in S5 (the slice's two-attempt limit): the next ones are the ebtree free list (reserve it with the nodes, as S4 did for the arenas) and whatever infallible allocation comes after it. |
| **S5 against HAProxy** | Measured on 3.5-dev8 (`-dMfail`, `tune.fail-alloc 5`, 400 requests): `200`, `500` with `IR--` or `IC--`, or a closed connection; Ibex gives the same three, `IR--` for the request's buffer and `IH--` for the response's (HAProxy's refusals at that point are of its server connection). `tune.fail-alloc` counts only under `-dMfail`, as on HAProxy; the other `-dM` features are refused. A buffer past `tune.buffers.limit` fails its stream where HAProxy queues it (S6); `tune.buffers.reserve` is refused until then. An HTTP/2 stream whose buffer cannot be had closes its connection (as a stream's panic does, 6.26). |
| **Status** | Open: buffers, sessions and the request target fail one stream; the timer tree, rustls, h2 and std still abort. |

### 6.24 HTTP/2 and HTTP/3 field bytes that are not UTF-8, and a trailer refused before the server is reached (T451, T454)

| | |
|---|---|
| **What changed** | HPACK strings are octets. Ibex keeps decoded fields as UTF-8 text (`DecodedFields`, `H2ReqHead`, the rules), so `hpack::push_as_text` decodes each byte that is not UTF-8 as a NUL: the block is decoded whole (the dynamic table stays the client's, sizes included) and the field checks refuse the field with `RST_STREAM` PROTOCOL_ERROR on that stream alone. It was a GOAWAY COMPRESSION_ERROR that closed every stream of the connection. For a **name** this is what HAProxy 3.5-dev8 does (measured: RST 1, the next stream answered). For a **value or `:path`** HAProxy forwards the byte as it is (measured: `x-a: \xe9`, `GET /a\xe9b`); Ibex resets the stream. Valid UTF-8 (`é` as `C3 A9`) is forwarded byte for byte, as HAProxy does. **HTTP/3 (T454)**: QPACK did the same for the same bytes (`H3Error::QpackDecompressionFailed`, a connection error by RFC 9204 section 2.2.3). `qpack::text_of` now decodes them the same way (`hpack::push_as_text`), and `h3_relay::request_head` refuses the request as a message error: RESET_STREAM and STOP_SENDING `H3_MESSAGE_ERROR` (0x10e), no answer, the connection and its other streams go on. Measured on HAProxy 3.5-dev7 +QUIC (`reference/haproxy-quic`, aioquic with hand-built QPACK): a **name** with 0xE9, literal or Huffman, is RESET_STREAM 0x10e and the next request on the connection is served; a **value** `a\xe9b` and a `:path` `/a\xe9b` are forwarded byte for byte, which Ibex refuses as on HTTP/2. Ibex's QPACK decoder is static-table only (required insert count 0 is the only one accepted, no encoder stream is read), so no dynamic table is lost by decoding on. |
| **Also (T454, HTTP/3)** | Every request that `h3_relay::request_head` refuses as malformed is now a stream reset 0x10e as on HAProxy (it was a `400` answer): the `h2::check_request_fields` checks (T449) now run on HTTP/3 too, which closes `:path` with `#` or without a slash, `:authority` or `host` with `/`, `@` or a space, a bad `:scheme` or `:method`, and a request with neither `:authority` nor `host`. A field section that does not decode (for example a required insert count other than 0, with no dynamic table) closes the connection with 0x200 QPACK_DECOMPRESSION_FAILED, as on HAProxy (measured on haproxy-quic 3.5-dev7); an empty `:path` resets the stream with 0x10e. `option accept-unsafe-violations-in-http-request` is not read on HTTP/3 yet (the path is checked as strict). |
| **Also** | A request whose trailers are refused: HAProxy forwards the head and body, then resets the stream, the last chunk never sent (measured). Ibex resets the stream the same way and never sends the last chunk, but when the trailers arrive before the server connection is made it forwards nothing at all. Forwarding a request already known to be malformed would only be for parity; the server sees an unfinished request either way. |
| **Cost** | A client that sends Latin-1 (or other non-UTF-8) bytes in an HTTP/2 or HTTP/3 header value or path gets its stream reset where HAProxy forwards it. HTTP/1 is not affected. |
| **Why that is acceptable** | RFC 9110 section 5.5 makes such bytes obs-text, which a recipient may refuse; clients that send them are rare. Carrying fields as bytes would change every type from the decoder to the rules. |
| **Status** | Open. |
| **Revisit** | When the request head is carried as bytes end to end. |

### 6.25 `-m <megs>` sizes `maxconn` but sets no rlimit (T453) — **measured 2026-10-24 on 3.5-dev8; change when T448 (fallible pools) has merged**

| | |
|---|---|
| **HAProxy** (oracle 3.5-dev8-885761-29, this host, 64 CPUs) | `-m N` sets `RLIMIT_DATA` soft and hard to N MiB (`/proc/<pid>/limits`: `Max data size 67108864 67108864` for `-m 64`; 16777216 for `-m 16`), shows `Memmax_MB: N` / `Memmax_bytes` in `show info`, and sizes the automatic `maxconn` from it (`nbthread 1`: 1800 at `-m 64`, 450 at `-m 16`; 524174 without `-m`, from `ulimit -n`). At the cap its pools fail and it lives: `-m 16`, `maxconn 6000`, 3000 connections each holding a partial 8 KB request: `PoolFailed: 24`, `buffer` pool `11 failures`, 12 connections closed, a request afterwards gets 200. With the default `nbthread` (64 here) `-m 64` does not start serving: 4 of 64 threads exist, `curl` and `show info` get nothing, `SIGUSR1` does not stop it (the thread stacks count against `RLIMIT_DATA`). |
| **Ibex today** | `-m N` is recorded for `show info` (`Memmax_MB`) and sizes `maxconn` the same way (`engine::apply_memmax`, called from `bin/ibex.rs` step 10); **no rlimit is set**. `ibex -m 64` therefore never sees a failed allocation, and an operator who expects a memory cap gets none. `-h` says so. |
| **Why** | Most Ibex allocations are infallible: a failed one aborts the process (6.23), where HAProxy's pools fail one stream. Setting `RLIMIT_DATA` now would only make Ibex abort sooner, at the operator's cap instead of the system's. |
| **S5 (2026-10-25)** | The buffers and arenas are fallible now, but the T446 run under `RLIMIT_DATA` 640 MB still aborts, in the scheduler's timer tree (`ebtree` `unlink_and_recycle`, a 64-byte `Vec::push`; 6.23 "After S5"). So `-m` still sets no rlimit. |
| **Condition for changing** | T448 (fallible pools: buffers and arenas that return `Err` and fail or queue the stream) merged, and the T446 run under `RLIMIT_DATA` 640 MB keeping Ibex alive. Then `-m` sets `RLIMIT_DATA` as HAProxy does, with a test that reads `/proc/<pid>/limits` and one that fills the cap and checks the process lives. |

### 6.26 A panic in a stream's run closes that stream, not the process (T447) — **measured 2026-10-24**

`EngineDispatcher::run_task` runs each stream task under `crash::contain` (`catch_unwind`). A
panic there is reported (the standard message and an `[ALERT]` line), the stream is closed
without an answer, logged with termination state `I` and its phase, and counted in `eint`
(frontend, backend and server), and the worker serves on. Design and the unwind-safety audit:
`tasks/T447-progress.md`; test: `crates/ibex-rt/tests/it/panic_contained.rs`.

| | |
|---|---|
| **Contained** | Any panic in one stream's run: H1 (tested), and by construction H2 (an h2 stream's panic ends its whole h2 connection, not just the stream), H3 request streams and TCP mode, which run as the same task kind (not tested). That covers rules, fetches, converters, parsing, forwarding and the stream's own logging. |
| **Still aborts** | A panic outside a stream's run (accept, poller loop, health checks, CLI applets, reload, master); a panic that leaves a shared lock poisoned (stick tables, load balancer state, idle server connections, rings, pattern references, variables, userlists): what it guards may be half-changed; a panic while closing the panicked stream; a panic during unwinding; and an allocation failure, which aborts before any unwinding (T446, T448). |
| **Cost** | +55 `instructions:u` per request (51 820 to 51 875, +0.1%; 50 000 keep-alive requests, `ab -k -c 1`, `nbthread 1`, release builds of 2fe0db33 and this branch, 3 rounds, all identical to ±15). Two thread-local stores and the `catch_unwind` frame per stream run. |
| **Differs from HAProxy** | HAProxy has no panic; an internal error answers 500 (`IR--`), Ibex sends nothing: after a panic the stream's buffers may be mid-update, so the connection is closed as on a failed `stream_new`. |
| **Requires** | `panic = "unwind"`: `crash.rs` has `#[cfg(panic = "abort")] compile_error!`, so no profile, PGO build or `RUSTFLAGS` can turn it off silently. |
| **Revisit if** | A panic is seen to recur on every request of some input (a contained panic per request is a slow DoS: fix the panic, which the alert names), or h2 needs per-stream containment (`RST_STREAM INTERNAL_ERROR` instead of closing the connection). |

### 6.27 ring does not zeroize key material — **found 2026-10-24; `ring-ibex` opt-in since T460**

| | |
|---|---|
| **What** | `ring` 0.17.14 (the crypto provider behind rustls for TLS over TCP and QUIC) frees its key material without wiping it. Its own comments say so: `src/agreement.rs` and `src/ec/suite_b/ecdh.rs`, at the ECDH shared secret, "a pretty liberal interpretation of the NIST's spec's 'Destroy' that doesn't meet the NSA requirement to 'zeroize'". Private keys, AEAD keys and the key-exchange shared secret can stay in freed memory until it is reused. |
| **What is wiped** | rustls 0.24.0-dev.2 wipes its own secrets on drop with `zeroize`: the TLS 1.3 key schedule (`crypto/tls13.rs`), HMAC/HKDF buffers (`crypto/hmac.rs`), cipher key buffers (`crypto/cipher/mod.rs`), HPKE secrets. Since T440 the TLS record buffers (plaintext and ciphertext) are Ibex's own (`ibex-tls/src/conn.rs`), wiped by `wipe_vec` under `tune.ibex.ssl-zero-buffers`, default **on** since S2 of `docs/design/memory-2026-10-24.md` (user 2026-10-24: "tls keys are a real target. crypto buffers should be zeroed"); `tune.ibex.zero-buffers`, the plain I/O buffers' setting, is default off. |
| **Differs from HAProxy** | OpenSSL clears key material with `OPENSSL_cleanse` when it frees it. |
| **Cost** | A memory disclosure (a core dump, a swapped page, a later read of freed memory by another bug) can expose keys that OpenSSL would have wiped. Rust's memory safety makes the "later read" path much less likely than in C, but core dumps and swap remain. |
| **Mitigations today** | Disable core dumps for the service (`LimitCORE=0`), no swap or encrypted swap. These are ops settings, not Ibex code. |
| **Plan** | Patch ring (or the rustls provider) to zeroize key material on drop: the ECDH/X25519 private and shared values, the AEAD key schedules, the RSA/ECDSA private keys. Ask upstream first whether such a patch would be taken; otherwise carry it as a vendored patch, or evaluate another memory-safe provider that wipes. aws-lc-rs stays excluded (C, see the memory-safety rule). |
| **Status** | A choice since T460: `tune.ibex.crypto-provider ring-ibex` runs TLS over TCP on the vendored fork (`vendor/ringibex`, feature `zeroize`; ring-ibex 237a254). It wipes the ephemeral and shared ECDH/X25519 secrets, the AES/ChaCha/GHASH/Poly1305 key schedules, the HMAC/HKDF and digest states, the Ed25519 key pair, the ECDSA seed and the RSA private primes and exponents (inventory: `vendor/ringibex/ZEROIZE.md`). Not wiped even there: stack copies left by moves, registers, asm temporaries, the ECDSA per-signature nonce, the affine coordinates of the ECDH point (TODO in ZEROIZE.md). `ring` (vanilla upstream) wipes none of it and stays the **default**: operators are right to be wary of a forked crypto library, and an upstream ring fix reaches Ibex by a `cargo update`, a fork fix only by our re-vendoring. QUIC, log-forward TLS binds and ring TLS servers are on rustls 0.23 and refuse `ring-ibex`, so they keep vanilla ring's behaviour. |

### 6.28 One pool type, `ibex_alloc::Pool` (S1 of `docs/design/memory-2026-10-24.md`) — **measured 2026-10-24**

The spare strings and lists and the scratch buffers (6.21) are the first caches on
`ibex_alloc::Pool<T>` (`declare_pool!`): a per-thread stack per pool, one per-thread byte budget
across pools (`tune.memory.hot-size`), HAProxy's 3/4 and 7/8 eviction with per-pool floors, and a
registry `show pools` and `pool_gc` walk. Where it differs from the design (§3) and from HAProxy:

| | |
|---|---|
| **`show pools` staleness** | Accepted (user 2026-10-24). A thread publishes its counts from its loop pass at most every 10 ms (`PUBLISH_EVERY` in `pool.rs`), not on each take or give: publishing every pass cost ~300 instructions per request on the rules scenario (ab1, one request per pass), and the fast path writes nothing another thread reads (AGENTS.md §8). So `show pools` can lag a busy thread by up to 10 ms (an idle one by up to its poll timeout); the thread that runs `show pools` and `pool_gc` publishes its own counts first. HAProxy's per-thread cache counts are approximate too (`pool_cache_count` summed without locks, `needed_avg` a moving average). |
| **Counts** | `allocated` is what the threads cache plus the `PoolBox`es alive, all counted thread-locally; an object taken with `take_raw` (a spare string that becomes a sample) leaves the accounting until it is given back. Only `.limited()` pools keep a shared `grown` counter, for `tune.buffers.limit`. Per-pool bytes are summed over the items when published or evicted, not kept on the fast path. `needed_avg` is 0. |
| **Eviction** | One object at a time, newest first (the stack's top), largest pool first across pools; HAProxy evicts clusters of 8, oldest first, from a per-thread LRU across pools. Floor objects (`minavail`) are kept whatever `hot-size` is and do not count against it. |
| **Limits** | 64 pools, 256 thread slots (+1 shared overflow slot) for `show pools`. Pools register on first use, or at start for the ones `show pools` must list from the start. |
| **Wipe** | Per pool, from the thread's copy of the settings refreshed once per loop pass: the spare and scratch pools follow `tune.ibex.zero-spares` (default off, 6.21), any other pool `tune.ibex.zero-buffers` (default off, 6.20's note). |
| **Buffers (S2)** | The three buffer pools (`buffer`, `small_buffer`, `large_buffer`) are `declare_pool!`s of `Mem<CLASS>` (floor 64 and at most 64 per thread, as the old cache; floor objects do not count against `hot-size`). The `BUF_*` shared atomics are gone: `allocated` is cached + in use, summed from the threads' counts, so `show pools` shows a buffer taken or given on another thread's hit path up to 10 ms late (above). The only shared write left is the heap-buffer count `trim_idle` watches, on the miss path. A buffer of another size than configured now (grown by a head rewrite) is freed on give. |
| **TLS buffers wiped by default (S2)** | `tune.ibex.ssl-zero-buffers on\|off`, default **on** (user 2026-10-24: "tls keys are a real target. crypto buffers should be zeroed"): the TLS record buffers (ciphertext `rx_raw`/`tx_raw`, decrypted plaintext) are overwritten when a connection ends, under their own setting; the plain I/O buffers and the spares are not (`zero-buffers`, `zero-spares`: default off). This is the exception to the fair-benchmark rule (Ibex-only per-request safety extras default off while Ibex is compared with HAProxy): the wipe costs a TLS connection two buffer-sized stores at its end, not per request, and key-adjacent bytes are the case the user wants covered. HAProxy has no such keyword (3.5-dev8 refuses it as unknown) and OpenSSL's own record buffers are cleansed only partly. |
| **Arenas (S4)** | The session, applet and task arenas (`show pools`: `session`, `appctx`, `task`) implement `ibex_alloc::Arena<T>` and publish their slot counts once per loop pass (`ArenaStats::publish`, a plain compare when nothing moved; the per-slot process-wide atomics of `ArenaCounters` are gone, so the request path writes nothing shared). **Q2 (b) is in force: a close never shrinks an arena.** The burst capacity (free slots after the last one in use, the capacity above the pre-size, the pages a burst made resident) goes back only in `pool_gc` (SIGQUIT, SIGTTOU, SIGUSR1, the stop path, a refused allocation): `Engine::compact_arenas` runs at the next loop pass after the request. Operators tell a leak from a kept peak by `show pools`: `used` is the slots in use, `cached` the free ones kept. Growth past the pre-size is fallible (`try_reserve`): `session`/`appctx`/`task` allocation returns `None`, the connection is refused, `failures` counts it; a compaction that cannot have its fresh buffer keeps the old one (T453, `ArenaStats::compactions_skipped`). **Visible consequence:** `show pools` keeps the peak after a burst, e.g. 2000 client aborts accepted in batches left `session` at 1564 slots (2.5 MB resident) until a SIGQUIT; before S4 the arena shrank on every close and hid it. `task` is new in `show pools`. Not S4: the task arena's `reserve()` (the h2 spawn path) and `free`'s `Vec::push` on a close stay infallible (the free list is reserved to the slot count when the arena grows, so a close does not allocate). |

### 6.29 `tune.ibex.zero-on-free off|soft|hard`: wipe what is freed, in Ibex's allocator (T459) — **measured 2026-10-25; default off**

| | |
|---|---|
| **What** | The `ibex` binary's `#[global_allocator]` is `ibex_alloc::IbexAllocator` (the system allocator, nothing counted). `hard`: every `dealloc` overwrites the block with zeros (`memset`, the pointer handed to `black_box` so the stores are not dropped as dead before the free) and then frees it; a reallocation becomes allocate, copy, wipe-and-free the old block, so the C library never moves a block behind the wipe. `soft`: the block goes on the freeing thread's quarantine (an intrusive FIFO: next pointer, size, time and alignment written over the block's first 24 bytes; blocks under 24 bytes are wiped at once) and is wiped and freed by that thread's loop pass: all of it after a poll that returned no events, else at most 16 KiB per pass. A quarantined block is not reused while it waits (as an ASan quarantine). Brian Smith's suggestion for ring ("an allocator that automatically zeroizes on deallocation", ring#15) is this. |
| **Default** | `off` (user rule 2026-10-24: Ibex-only safety extras stay off while Ibex is compared with HAProxy). `soft` is the intended future default. |
| **The trade of `soft`** | It trades confidentiality for availability: under load the wipe is deferred, so a freed key can sit in memory unwiped for up to the age bound. Two risks and the bounds against them: (1) **a denial of service through the wipe** (a bug or an attack makes the quarantine grow, or makes wipe storms): at most `4 x tune.memory.hot-size` bytes per thread (2 MiB by default); past it the oldest blocks are wiped and freed synchronously (`ZeroOnFreeForced`), a block larger than the bound never waits, and a pass spends at most 16 KiB unless the thread is idle; `pool_gc` and a refused allocation (the allocator retries once after emptying the quarantine) drain it first. (2) **key exposure through load** (an attacker keeps the CPU busy so that freed keys are never wiped): every pass, busy or idle, first frees everything older than 100 ms (`ZeroOnFreeExpired`); the engine passes at least every 100 ms (the poll cap), so a freed secret lives at most about 200 ms whatever the load. A thread that runs no loop passes has no quarantine (its frees take the `hard` path), and a thread's end empties its quarantine. `show info` shows the bytes, blocks and oldest age waiting and both counters, so an operator sees both levers. |
| **Coverage** | Every heap free in the process: rustls, ring's heap keys, Ibex's objects, std. Not the stack, registers or moves (ring-ibex's drop patches cover ring's stack copies, 6.27); not pooled objects, which are not freed and are wiped by their pools (`zero-buffers`, `zero-spares`, `ssl-zero-buffers`); not memory the C library keeps in its own metadata. |
| **Differs from HAProxy** | HAProxy has no wipe of freed memory; its `-dM` options poison or pattern-fill pool objects for debugging (`docs/differences.md`), and OpenSSL clears its own key material. |
| **Cost (measured 2026-10-25, 1 thread, `tools/measure/insreq.sh`, min of 3-5 rounds, base = main da8524ca, interleaved; llama-server partly running, figures relative)** | Keep-alive requests (`ab1`, 30000): base 49211-49222, `off` 49247-49249 instructions per request (+30, +0.06%: the request path frees nothing). New connection per request (`nc1`, 5000): base 58687-58692, `off` 58726-58727 (+0.06%), `soft` 59179 (+0.8%), `hard` 59141-59142 (+0.77%). One TLS handshake per request (`hs1`, 2000): base 1506936-1506940, `off` 1508265-1508357 (+0.09%), `soft` 1514877-1514879 (+0.53%), `hard` 1512101-1512365 (+0.34%). Connections/s and handshakes/s (`ab -c 1`, client-bound) were the same within noise in every mode: ~4040/s and ~1015/s. `soft` costs more instructions than `hard` (the list and the pass), and moves them off the free. |
| **Not done** | The bounds are fixed (4 x hot-size, 100 ms, 16 KiB per busy pass), not keywords. `show pools` does not list the quarantine. Threads past the 256th publish no figures. |
