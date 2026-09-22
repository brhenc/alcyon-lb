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
| **Gained** | A tractable project. `src/hlua.c` alone is ~14k lines |
| **Gave up** | Every reg-test needing them is permanently `OUT_OF_SCOPE`, capping the scoreboard below 312 |
| **Status** | **measured** — triage in `data/regtests.json` |
| **Revisit if** | The core is finished and complete, which is a good problem to have |

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

### 6.3 `takeover()` not implemented

Idle backend connections can only be reused by their owning thread, costing some reuse
ratio under uneven load. HAProxy needs three cooperating layers and ~60 lines for this,
and it can fail at each.

### 6.4 No watchdog

`src/wdt.c` panics a thread that stops making progress. With hard affinity and no
stealing, a wedged thread silently strands every connection assigned to it. **Needed
before this is run anywhere real.**

### 6.5 `struct server` is the real 60k-backend prize, untouched

Measured: HAProxy's `struct server` is **3456 bytes**, so 60k backends cost **207 MB** —
against 7.7 MB for their tasks, a 27× ratio. About 1328 of those bytes are two embedded
`struct check`, and most servers never use an agent check. `Option<Box<Check>>`, interned
strings, side-array counters and optional TLS state would put a 512-byte server at 31 MB.
**This is the single largest measured win available in the project and nothing has been
built for it yet.**

### 6.6 Map converters re-read the file on every evaluation

`match_map` in `crates/ibex-sample/src/registry.rs` calls `std::fs::read_to_string` and
then scans the file linearly for each sample evaluation, so a config with `map_beg` in a
request rule does a blocking `read(2)` plus a full parse per request; `map_reg`/`map_regm`
also compile a regex per line examined. HAProxy loads each map once into a pattern tree
(`src/map.c`, `pat_ref` + `pattern_expr`) and does a tree lookup per request.

Gained: a map converter works with no config-time plumbing — the path in the converter
argument is all it needs, and files edited on disk take effect immediately.
Gave up: the data path touches the filesystem. This is squarely against the rule that the
data path gets no syscalls it does not need, and under load it is the kind of thing an
attacker can amplify by choosing a URL that hits a map rule.
Status: **reasoned, not measured** — no benchmark yet on how much a map rule costs per
request, and the page cache absorbs the read, so the cost is parse and scan rather than
I/O.
Revisit if: any map converter is used on a hot path. The fix is to load maps at config
parse time into a cached structure keyed by path, with the runtime API (`add map`,
`del map`, `clear map`) mutating that cache — which is also what makes those CLI commands
implementable at all, so this is owed regardless of performance.
