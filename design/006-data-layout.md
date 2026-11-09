# 006 — Data Layout, Zero-Cost Abstraction, and Observability Tiers

Reference: `/home/bhenc/reference/haproxy` @ `e6f616af` (3.5-dev7). Sizes measured by
compiling the actual struct definitions on this machine (x86-64, gcc -O2).

The governing constraint for Alcyon: **pick representations by measured layout and cost,
not by what reads well.** Where idiomatic Rust and cache behaviour disagree on the data
path, cache behaviour wins. Where they agree — which is more often than expected — take
both.

---

## 1. Measured sizes

| Structure | Size | Note |
|---|---|---|
| `struct eb_node` | 36 B | `__attribute__((packed))` |
| `struct eb32_node` | 40 B | carries **no** payload |
| `TASK_COMMON` | 48 B | |
| **`struct task`** | **128 B** | exactly two cache lines |
| **`struct tasklet`** | **64 B** | exactly one cache line |
| **`ebtree::Node` (ours)** | **28 B** | carries key **and** payload |

128 and 64 are not coincidences. HAProxy sized these deliberately.

Confirmed against the running binary (3.5-dev7, built locally, `show pools`):

```
- Pool task       (128 bytes/64)
- Pool tasklet     (64 bytes/64)
- Pool session    (184 bytes/8)
- Pool connection (264 bytes/64)
- Pool stream    (1056 bytes/8)
```

And via `gdb -ex "print sizeof(...)"` for the non-pooled objects:

| Structure | Size |
|---|---|
| `struct server` | **3456 B** |
| `struct proxy` | **2560 B** |
| `struct check` | 664 B (two are embedded per server) |

## 1.1 The 60k-backend budget

Operators run tens of thousands of backends per process, and this is the arithmetic that
decides whether that is possible:

| At 60,000 servers | HAProxy |
|---|---|
| `struct server` | 60k x 3456 = **207 MB** |
| check tasks | 60k x 128 = 7.7 MB |
| **dominant cost** | **`struct server`, by ~27x over its tasks** |

The scheduler is *not* where this budget goes. Shrinking the task from 128 B to 32 B
saves ~6 MB at 60k — worth having, not decisive. **`struct server` is the battleground**,
and roughly 1328 of its 3456 bytes are two embedded `struct check` (most servers never
use an agent check), with more going to inline name/cookie arrays, per-server counters,
and SSL fields present whether or not SSL is configured.

The Rust moves are available and ordinary: `Option<Box<Check>>` for the agent check,
interned strings as `u32` indices, counters in a side array (which also makes stats
sweeps sequential instead of pointer-chasing), TLS state behind an `Option`. A 512-byte
server would put 60k at **31 MB against HAProxy's 207 MB**. That is the single largest
measured win available in the whole project, and it is a data-structure decision, not a
code one. Deferred to its own document once the server model exists.

## 2. Why HAProxy uses a function pointer, and why we should not

`TASK_COMMON` carries:

```c
struct task *(*process)(struct task *t, void *ctx, unsigned int state);
void *context;
```

16 bytes and an indirect call. The reflex is to treat this as a design choice worth
preserving. It is not — it is the only tool C offers for heterogeneous dispatch, and
HAProxy pays for it twice:

- `void *context` is untyped, so nothing can recover what a task *is*;
- consequently `show sess` and `show fd` must reconstruct that information from
  elsewhere, rather than reading it off the task.

A Rust enum is **smaller and faster** than the C construct it replaces:

| | C | Rust enum |
|---|---|---|
| Size | 16 B (`process` + `context`) | **8 B** (4-byte tag + 4-byte index) |
| Dispatch | indirect call, no inlining, mispredict risk | jump table; hot arms inlinable |
| Introspection | none — payload is `void *` | free — the tag *is* the answer |

This is the case where idiom and performance agree. The cost is real but small: the
scheduler must know its task variants, so adding a subsystem touches the enum. In a
single statically-linked binary with no plugin surface (Lua and SPOE are out of scope),
that coupling is cheap and buys back the introspection HAProxy had to rebuild by hand.

**`Box<dyn Task>` is rejected on data grounds**: a 16-byte fat pointer, a heap allocation
per task, and a vtable indirection. The allocation alone disqualifies it.

## 3. The arena is faster than embedding, and descent is why

The instinct is that our index arena must be a compromise against C's intrusive nodes.
The measurement says otherwise, and the reason is that **descent cost dominates dispatch
cost by roughly the tree depth.**

**C.** Each `eb32_node` is embedded in its owner (`task`, `stksess`, …), and owners are
pool-allocated independently, so they are scattered across memory. Walking a depth-*d*
tree touches *d* separate allocations — up to *d* cache misses. HAProxy knows this and
mitigates it explicitly:

```c
eb_prefetch(old->node.branches.b[0], 0);
eb_prefetch(old->node.branches.b[1], 0);
```

Prefetch hints in the descent loop are what you write when the structure is
cache-hostile and you cannot change it.

**Ours.** Nodes are 28 bytes in one contiguous `Vec` — **2.28 nodes per 64-byte line**.
A depth-*d* descent touches roughly *d*/2.28 lines instead of *d*. For the run queue
specifically the win compounds: keys are a monotonic counter, so recently inserted nodes
are adjacent in the arena as well as adjacent in key order.

The cost is one extra indirection — `node.data` → task — **once per dispatch, not once
per descent step**. With depth up to 32 and dispatch happening once, that trade is
strongly favourable.

> **Unverified.** This is a layout argument, not a measurement. It should be settled by
> benchmarking both layouts on the run queue's real access pattern (monotonic keys,
> `first`/`delete`/`insert` dominated) before it is treated as fact. Recorded here as a
> prediction so it can be falsified.

## 4. Observability: how HAProxy actually tiers it

HAProxy already separates debug from production representations, in three distinct ways.
Worth enumerating before inventing a fourth.

### Tier 1 — compile-time: the field does not exist

```c
#ifdef DEBUG_TASK
#define TASK_DEBUG_STORAGE          \
    struct { const struct ha_caller *prev_caller; } debug
#else
#define TASK_DEBUG_STORAGE
#endif
```

Zero cost when off, because there is nothing to be zero-cost about.

### Tier 2 — runtime flag gating writes to always-present fields

```c
if (_HA_ATOMIC_LOAD(&th_ctx->flags) & TH_FL_TASK_PROFILING)
    t->wake_date = now_mono_time();
```

`wake_date`, `lat_time`, `cpu_time` always occupy space; only the writes are gated.
Costs memory unconditionally, CPU only when enabled.

The pool allocator does the same at a far larger scale — **eleven runtime-switchable
debug modes** (`include/haproxy/pool-t.h`):

```
POOL_DBG_FAIL_ALLOC  randomly fail allocations      POOL_DBG_CALLER   trace last caller
POOL_DBG_DONT_MERGE  do not merge same-size pools   POOL_DBG_TAG      tag after the area
POOL_DBG_COLD_FIRST  pick cold objects first        POOL_DBG_POISON   poison on alloc
POOL_DBG_INTEGRITY   integrity-check the cache      POOL_DBG_UAF      use-after-free trap
POOL_DBG_NO_GLOBAL   disable global pools           POOL_DBG_BACKUP   back up contents on free
POOL_DBG_NO_CACHE    disable thread-local caches
```

This is the "runtime memory debugging" worth keeping. Note the granularity: **global and
switchable at startup**, not per-connection.

### Tier 3 — on-demand walking, no shadow state

`show fd`, `show sess`, `show pools` and `show servers state` walk the real structures
when asked. They maintain nothing while idle. This is why they cost nothing on the data
path, and it is the most under-appreciated of the three.

### One thing HAProxy pays for unconditionally

The `caller` field is **not** behind `DEBUG_TASK`. HAProxy spends 8 bytes per task, always,
to record the call site of the last wakeup. Someone decided that debugging a stuck task
in production is worth 8 bytes on every task in existence. That judgement is worth
inheriting.

## 5. Per-connection debug/production: the shape that actually works

The goal — rich state for connections under investigation, nothing for the rest — is
right. The obvious implementation is not.

**What does not work: alternate structures per connection.** If connection A holds a
`DebugStream` and B a `ProdStream`, every path that touches a stream must handle both.
That means either a trait object (indirection on every access) or an enum (a branch on
every access, and size equal to the larger variant). Either way **every connection pays,
including the ones not being debugged** — precisely backwards.

**What works: side tables.** The hot structures keep one fixed minimal layout. Debug
state lives in a separate per-thread table keyed by connection id, populated only for
connections explicitly marked. Cost when nothing is marked: one load-and-branch on a
per-thread `tracing_active` flag that is almost always false and therefore near-perfectly
predicted.

The kernel does better still with **static keys / jump labels**: the disabled branch is
patched to a literal `nop`, so a disabled tracepoint costs nothing at all, not merely
little. Rust cannot patch its own instruction stream portably, but the same shape is
approximated with a `#[cold]` `#[inline(never)]` slow path behind the flag, which keeps
the disabled path out of the hot instruction cache.

### Adopted for Alcyon

| Tier | Mechanism | Example |
|---|---|---|
| 1 | `#[cfg(feature = "debug-sched")]` — field absent in release | wakeup call-site history |
| 2 | Per-thread flag gating writes to present fields | task profiling, latency accounting |
| 3 | On-demand walk of real state | `show sess`, `show fd`, `show pools` |
| 4 | Per-connection opt-in **side table** behind a cold branch | per-connection tracing |

Tier 4 is the per-connection idea, implemented so that unmarked connections pay one
predicted branch rather than a permanent layout tax.

## 6. The production task: 32 bytes

HAProxy's `struct task` is 128 B because it embeds both `eb32_node`s (40 B each),
allocated whether or not the task is queued. Ours references the ebtree arenas instead,
and packs the work kind:

```rust
#[repr(C)]
pub struct Task {
    state:    u32,      // 4   TASK_* flags
    kind:     WorkKind, // 4   packed: 8-bit tag + 24-bit index
    expire:   Tick,     // 4   wrapping 32-bit ms
    rq_ref:   NodeRef,  // 4   run-queue arena index; NONE = not queued
    wq_ref:   NodeRef,  // 4   wait-queue arena index; NONE = not queued
    caller:   CallSite, // 4   index into a static call-site registry
    nice:     i16,      // 2
    last_run: u16,      // 2   anti-double-run guard (src/task.c:543)
    tid:      i16,      // 2
    _pad:     u16,      // 2
}                       // = 32 bytes exactly
```

**32 bytes: two tasks per cache line, against HAProxy's two cache lines per task — 4x.**

Three decisions inside that:

- **`WorkKind` is packed into 4 bytes**, an 8-bit tag plus a 24-bit index (16.7M objects
  per kind, against a 60k target). Unpacking costs a shift and a mask, roughly one cycle,
  set against a potential cache miss of two hundred. The same tagged-index technique as
  `Branch`/`Parent` in the ebtree.
- **`last_run` is kept**, because it is not accounting. `src/task.c:543` compares it
  against the poll-loop counter to stop a task running twice in one pass — an
  anti-starvation guard. `calls` sits beside it in the same dispatch path and *is* pure
  accounting, so that one is gated.
- **`caller` is kept and always on**, as a 4-byte registry index rather than C's 8-byte
  pointer. HAProxy spends 8 bytes per task unconditionally to record the last wakeup's
  call site; at half the cost it fits inside the 32-byte budget, so diagnosing a stuck
  task in production stays possible without a debug build.

Queued cost, for comparison — HAProxy pays 128 B whether queued or not, while ours pays
only for the queues actually joined:

| State | HAProxy | Alcyon |
|---|---|---|
| Not queued | 128 B | **32 B** |
| In run queue | 128 B | 32 + 28 = **60 B** |
| In both queues | 128 B | 32 + 28 + 28 = **88 B** |

The second-order effect matters more than the bytes. At 60k health-check tasks waiting on
timers, HAProxy's wait-queue walk traverses 60k `eb32_node`s scattered across 7.7 MB of
independently pooled tasks. Ours traverses a dense 1.68 MB arena. **Same traversal, a
4.6x smaller working set** — and the timer tree is the hot structure at that scale.

## 7. Consequences for the scheduler

- Work kind is an **enum with a `u32` payload** (8 B), not a function pointer, not a
  boxed trait object. Smaller and faster than the C it replaces.
- Task state lives in a **per-thread arena**; run-queue and wait-queue membership are
  `u32` references into the ebtree arenas, not embedded nodes.
- Target: task state within **one cache line**, against HAProxy's two. The budget is
  real — 128 B is deliberate there, so beating it must be deliberate here.
- Tasks are `!Send` by construction. Not a safety ornament: it is the type system
  enforcing the affinity invariant that makes the lock-free data path sound.
- No allocation on the data path. Arenas are sized at boot; exhaustion is an error, not
  a `realloc`.
