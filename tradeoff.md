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

### 6.4 No watchdog

`src/wdt.c` panics a thread that stops making progress. With hard affinity and no
stealing, a wedged thread silently strands every connection assigned to it. **Needed
before this is run anywhere real.**

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
| **Gave up** | HAProxy has 69 named pools (buffers, trash, sessions, streams, resolvers, ...) with a per-thread cache (`tune.memory.hot-size`, 512 KB) and makes **0 malloc calls per request** in steady state (LD_PRELOAD count, keep-alive and new connections, 1 and 4 threads). Ibex pools only the I/O buffers (`buffer`, `small_buffer`, `large_buffer`; up to 64 spares per thread) and the shipped binary makes **about 6 malloc/free pairs, 273 bytes per request** (sizes 1, 3, 10, 10, 56, 192; `tools/allocprofile`'s 4 allocations / 127 B counts only the in-process engine path of one `Connection: close` request). Not implemented either: `tune.buffers.limit`, `tune.buffers.reserve`, `tune.memory.hot-size` (refused as unknown), `-dM` pool debugging (refused since T351: no pools to poison), HAProxy's `show pools` detail (T352). |
| **Why it matters** | The user's requirement (2026-10-17): a request must not need a malloc. Every allocation a client can cause is one an attacker can make fail. In Rust a failed allocation does not return NULL to unchecked code (that C cascade cannot happen): the global allocator calls `handle_alloc_error`, which **aborts the worker** — every connection on it is lost, a denial of service instead of one failed request. HAProxy instead takes from a pool sized in advance and, when a pool is empty, fails only that stream (`tune.buffers.reserve` keeps buffers back for streams already running). |
| **Status** | **measured** 2026-10-17 (`~/ibex-worktrees/review/pools-haproxy-vs-ibex-2026-10-17.md`). Planning of the pools (which objects, per-thread caches, a bounded and fallible take on the request path, what to do when a pool is empty, how to count and test "0 allocations per request" on the real binary) is set for the 2026-10-17 21:00 planning session (Fable), with T344. |
| **Revisit if** | Done when the request path makes 0 allocations per request on the shipped binary (counted, pinned in a test), and an empty pool fails one stream, not the process. |

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
