# 003 — The Scheduler, and Why Ibex Writes Its Own

Reference: `/home/bhenc/reference/haproxy` @ `e6f616af` (3.5-dev7).

**Decision D1: Ibex implements HAProxy's scheduler in Rust rather than adopting a
general-purpose async runtime.**

The thesis under test: HAProxy's scheduler contains several mechanisms that exist
*specifically* to survive adversarial load, and a throughput-optimised general-purpose
runtime provides none of them. This document verifies that claim against the source
rather than asserting it, because "HAProxy wrote their own so it must be necessary" is not
an argument — the mechanisms are.

Four properties hold up. Each is named, located, and paired with the attack it defeats.

---

## 1. Two work units: `task` and `tasklet`

```c
#define TASK_COMMON                                             \
    unsigned int state;                                         \
    int tid;                                                    \
    struct task *(*process)(struct task *, void *, unsigned int); \
    void *context;                                              \
    ...                                                         \
    short nice;        /* -1024 .. +1024 */                     \
    int expire;        /* next expiration, in ticks */

struct task    { TASK_COMMON; struct eb32_node rq; struct eb32_node wq; };
struct tasklet { TASK_COMMON; struct list list; };
```

- **task** — schedulable *and* timer-capable. Lives in the run queue (`rq`, an eb32 node)
  and/or the wait queue (`wq`, another eb32 node). Has a nice priority.
- **tasklet** — immediate, no timer, no priority; lives on one of five intrusive lists.

Note the aliasing trick at `include/haproxy/task-t.h`: `struct task`'s `rq` field and
`struct tasklet`'s `list` field occupy the same offset, and the two are never both in use.
The comment warns in capitals never to reorder them. **In Rust this is an enum**, and the
hazard evaporates — one of the cleanest wins available in the whole translation.

## 2. Run queue: eb32 keyed on a wrapping insertion counter

`__task_wakeup()`, `src/task.c`:

```c
t->rq.key = _HA_ATOMIC_ADD_FETCH(&th_ctx->rqueue_ticks, 1);

if (likely(t->nice)) {
    offset = t->nice * (int)global.tune.runqueue_depth;
    t->rq.key += offset;
}

eb32_insert(root, &t->rq);
```

The key is a monotonically increasing ticket, offset by `nice × runqueue_depth`. This one
line gets you:

- **FIFO by default** — equal-priority tasks run in wakeup order, because the ticket
  increases monotonically.
- **Priority as a displacement** — a nice of −1 moves you 280 slots earlier; +1 moves you
  280 later. Priority and fairness in a single ordered structure.
- **Bounded depth** — the key is 32 bits, so the tree is at most 32 levels deep no matter
  how many tasks exist or what an attacker does (see §5).

A binary heap gives priority but not cheap FIFO among equals. A plain FIFO gives fairness
but no priority. An ordered tree over a monotonic counter gives both, which is why the
structure is an ebtree and not a heap.

Cross-thread wakeups go to `rqueue_shared` under `rqsh_lock` and then `wake_thread(thr)`.
Same-thread wakeups touch no lock.

## 3. Class budgets — the anti-starvation mechanism

`src/task.c:720`:

```c
const unsigned int default_weights[TL_CLASSES] = {
    [TL_RT]     = 1,  // never more than 1 RT task at once
    [TL_URGENT] = 64, // ~50% of CPU bandwidth for I/O
    [TL_NORMAL] = 60, // ~47% of CPU bandwidth for tasks
    [TL_BULK]   = 4,  // ~3% of CPU bandwidth for self-wakers
    [TL_HEAVY]  = 1,  // never more than 1 heavy task at once
};
```

Classes (`include/haproxy/tinfo-t.h:48`): `TL_RT`, `TL_URGENT` (I/O callbacks),
`TL_NORMAL`, `TL_BULK` (streaming self-wakers), `TL_HEAVY` (*"e.g. TLS handshakes"* —
upstream's own comment).

Two of these numbers are load-bearing under attack:

### `TL_HEAVY = 1` — the TLS handshake flood defence

A TLS handshake is the textbook asymmetric DoS: cheap for the client to request,
expensive for the server to compute. `TL_HEAVY = 1` means **a thread will never run two
handshakes back-to-back without servicing I/O in between.** Further, the budget is
refilled only once per call round (`heavy_queued` in `src/task.c:790`), so handshakes
cannot monopolise even a single pass.

An attacker opening thousands of TLS connections therefore cannot starve established
sessions. They degrade handshake *throughput* — which is the correct and unavoidable
outcome — without touching the latency of traffic already flowing.

### `TL_BULK = 4` — the bandwidth-hog defence

Tasks that re-wake themselves (a large download pumping buffers) are classed bulk and
capped at ~3%. One client streaming a large object cannot monopolise a thread against
thousands of small requests.

### And a global clamp

```c
max_processed = global.tune.runqueue_depth;                  /* RUNQUEUE_DEPTH = 280 */
if (likely(tg_ctx->niced_tasks))
    max_processed = (max_processed + 3) / 4;                 /* niced present: quarter it */
if (max_processed < th_ctx->rq_total && th_ctx->rq_total <= 2*max_processed)
    max_processed = th_ctx->rq_total / 2;                    /* halve for latency */
```

`RUNQUEUE_DEPTH` is 280 (`include/haproxy/defaults.h:262`). Note the third clause: when
the run queue is *moderately* over budget, it deliberately processes only half of it, to
split one long pass into two shorter ones and cut latency.

## 4. Lazy timer requeue — the slowloris defence

This is the subtlest mechanism and the one most likely to be missed in a rewrite.

`wake_expired_tasks()`, `src/task.c`:

```c
else if (task->expire != eb->key) {
    /* task is not expired but its key doesn't match so let's
     * update it and skip to next apparently expired task. */
    __task_unlink_wq(task);
    if (tick_isset(task->expire))
        __task_queue(task);
}
```

And the comment above it:

> *It is possible that this task was left at an earlier place in the tree because a recent
> call to task_queue() has not moved it. This happens when the new expiration date is
> later than the old one. Since it is very unlikely that we reach a timeout anyway, it's a
> lot cheaper to proceed like this because we almost never update the tree.*

**Pushing a timeout further out costs zero tree operations.** The task is left where it
is, and the stale key is repaired lazily, only if the expiry is ever actually examined.

Consider slowloris: 100k connections each dribbling one byte per second, every byte
resetting the client timeout. A naive implementation performs 100k timer
remove+reinsert operations per second — pure overhead manufactured by the attacker, for
timers that will essentially never fire. HAProxy performs approximately none.

The expiry scan is also bounded — `max_processed = global.tune.runqueue_depth` at the top
of `wake_expired_tasks()`, decremented per iteration. **A flood of simultaneously-expiring
timers cannot stall the thread**; the loop returns after 280 and I/O gets serviced.

### Wrapping tick arithmetic

Time is a 32-bit millisecond counter that wraps (~49.7 days). Comparison is by signed
difference (`include/haproxy/ticks.h:109`):

```c
static inline int tick_is_expired(int timer, int now) {
    if (unlikely(!tick_isset(timer))) return 0;
    if (unlikely((timer - now) <= 0))  return 1;
    return 0;
}
```

`TICK_ETERNITY = 0` is a reserved sentinel meaning "never". The tree is scanned as a
*circle*: `eb32_lookup_ge(&tt->timers, now_ms - TIMER_LOOK_BACK)` with
`TIMER_LOOK_BACK = (1U << 31)` — i.e. look from half the tick-space behind — and on
falling off the end, wrap to `eb32_first()`.

In Rust this becomes a newtype with wrapping arithmetic and an `Option`-like eternity
case, where the C version relies on the programmer never using `<` on a tick by mistake.

## 5. Bounded tree depth — immunity to algorithmic complexity attacks

An eb32 tree's depth is bounded by **key width (32), not element count, and not key
distribution.** This matters more than it first appears:

| Structure | Adversarial worst case |
|---|---|
| Unbalanced BST | O(n) — attacker inserts sorted keys |
| Hash table | O(n) per bucket — HashDoS via collision flooding |
| Balanced BST (RB/AVL) | O(log n), but rebalancing costs writes on every insert |
| **ebtree** | **O(32), always, regardless of input** |

There is no key distribution an attacker can choose that degrades an ebtree, because the
structure is determined by bit positions, not comparisons. And unlike a balanced tree,
there is no rebalancing: insert and delete touch O(1) nodes plus the descent.

For a proxy where every tree key is at least partly attacker-influenced — connection IDs,
timer expiries, stick-table keys derived from source IPs and headers — this is the right
trade, and it is why the same structure is used for the scheduler, the timers, stick
tables, and the server queues. See [004](004-ebtree.md).

---

## 6. The comparison with tokio, stated fairly

Tokio is not naive, and the argument should not overstate itself.

**What tokio does have:** a cooperative budget — each task gets a fixed allowance of
resource-acquiring operations per poll, after which readiness returns `Pending` to force
a yield. That genuinely prevents one busy task from spinning forever inside a single poll.
Its timer is a hierarchical wheel with good amortised behaviour. Its work-stealing
scheduler has a LIFO slot for message-passing latency and is well-engineered for
throughput.

**What it does not have, and cannot easily be given:**

| Mechanism | HAProxy | Tokio |
|---|---|---|
| Work classes with separate budgets | 5 classes, weights above | one flat class |
| "At most one expensive item per pass" | `TL_HEAVY = 1` | none — coop budget counts *operations*, and one RSA handshake is one operation |
| Priority within a queue | `nice` × depth, in the tree key | none |
| Timeout-extension without tree churn | lazy requeue, §4 | `Sleep::reset` re-registers in the wheel |
| Bounded timer work per pass | `max_processed` | wheel cascade is amortised, not bounded per pass |
| Connection affinity | by construction | work stealing defeats it; futures must be `Send` |

The coop-budget point deserves emphasis because it is the closest tokio gets. The budget
counts *operations*, not *cost*. A single expensive computation — precisely the DoS vector
— is one operation and consumes one unit of budget. `TL_HEAVY = 1` is a statement about
cost, and there is no way to express it in a runtime whose only currency is operation
count.

The work-stealing point is the structural one. HAProxy's lock-free data path is a
*consequence* of affinity; a runtime that may resume a task on any worker forces `Send` on
everything a connection touches, which reintroduces `Arc`/atomics exactly where HAProxy
has a plain struct field. Adopting it would not produce a memory-safe HAProxy. It would
produce a differently-shaped proxy that happens to be written in Rust.

### What Ibex still takes from the ecosystem

Writing the scheduler does not mean writing an epoll wrapper. `mio` (or direct `epoll`
via `rustix`) supplies readiness notification; the scheduler above it is ours. Later,
`io_uring` via `io-uring` is a drop-in for the readiness layer without touching scheduler
design. Non-data-path work (DNS resolution, config reload, certificate loading) can use
whatever is convenient.

---

## 7. What Ibex builds

```rust
// Sketch only -- see 004 for the tree these keys live in.

pub struct TaskId(u32);                 // index into the per-thread task arena

pub enum WorkKind {
    Task { rq: Option<Eb32Ref>, wq: Option<Eb32Ref>, nice: i16, expire: Tick },
    Tasklet { class: Class, link: ListRef },
}

#[derive(Copy, Clone)]
pub enum Class { Rt, Urgent, Normal, Bulk, Heavy }

pub struct Scheduler {
    rqueue:  Eb32Tree,              // keyed: ticks + nice*RUNQUEUE_DEPTH
    timers:  Eb32Tree,              // keyed: expiry tick (wrapping)
    tasklets: [IntrusiveList; 5],
    rqueue_ticks: u32,
    shared: SharedInbox,            // MPSC from other threads
}
```

Required to be correct on day one, because retrofitting them is what goes wrong:

1. Class budgets with HAProxy's weights (tune later against real load; the *mechanism*
   must exist from the start).
2. `max_processed` clamps on **both** the run loop and the timer scan.
3. Lazy timer requeue — extending a timeout must not touch the tree.
4. Wrapping tick type with a reserved eternity value, as a newtype.
5. A `nice` field, even before anything sets it.

Deliberately deferred: thread groups, task profiling, `takeover()`, the full `TH_FL_*`
flag set.

### Test plan

The properties above are the test plan, and each is measurable:

- **Handshake flood** — N concurrent TLS handshakes must not raise p99 latency of
  established connections beyond a bound.
- **Slowloris** — 100k connections dribbling bytes must produce ~zero timer tree mutations
  (instrument the counter directly and assert on it).
- **Timer thundering herd** — 1M timers expiring in the same millisecond must not produce
  an unbounded pass; assert the scan stops at the clamp.
- **Adversarial keys** — insert keys chosen to maximise tree depth; assert depth ≤ 32.
- **Bulk vs. small** — one large download must not push small-request latency past a
  bound.

These are exactly the tests a general-purpose runtime would fail, which makes them the
justification for D1 as well as its verification.
