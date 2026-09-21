# 002 — Threading and Affinity

Reference: `/home/bhenc/reference/haproxy` @ `e6f616af` (3.5-dev7).

**Decision D2: thread-per-core with hard connection affinity.** A connection is assigned
to a thread at accept and never moves. Everything reachable from that connection is
therefore touched by exactly one thread, and the data path needs no locks at all.

This is not an optimisation layered on top of the design — it *is* the design. Every
lock-free property downstream is a consequence of it.

---

## 1. What a thread privately owns

`struct thread_ctx`, `include/haproxy/tinfo-t.h`:

| Field | Purpose |
|---|---|
| `struct eb_root rqueue` | run queue — eb32 keyed by priority (see [003](003-scheduler.md)) |
| `struct eb_root timers` | wait queue — eb32 keyed by expiry tick |
| `struct list tasklets[TL_CLASSES]` | five intrusive lists, one per scheduling class |
| `struct list pool_lru_head` | thread-local allocator caches |
| `struct list streams` | the streams living on this thread |
| `struct list buffer_wq[DYNBUF_NBQ]` | buffer waiters in four criticality bands |

Cross-thread entry points are deliberately few, and each is explicitly marked as such:

| Field | Mechanism |
|---|---|
| `struct mt_list shared_tasklet_list` | lock-free MPSC list |
| `struct eb_root rqueue_shared` | guarded by `rqsh_lock` spinlock |
| `accept_queue_rings[]` | MPSC ring, one per thread |

The struct is laid out with explicit `ALWAYS_ALIGN(64)` / `ALIGNED(128)` boundaries
separating thread-local fields from atomically-accessed shared ones — false sharing is
treated as a correctness concern, not a micro-optimisation.

## 2. Thread groups

Above threads sit thread *groups* (`MAX_TGROUPS`). They bound the cost of cross-thread
atomics on large NUMA machines: the shared runqueue and lock scope are per-group rather
than global, so a 128-core box does not turn every wakeup into a 128-way cache-line
bounce.

For Ibex this is a later concern. Single group until there is a machine that needs more.

## 3. Placement: power-of-two-choices, once, at accept

`src/listener.c:1700–1740`. On accept, HAProxy compares the queue depth of the local
thread against two round-robin-selected candidates:

```c
q0 = accept_queue_ring_len(&accept_queue_rings[tid]);           /* local     */
q1 = accept_queue_ring_len(&accept_queue_rings[g1->base + t1]); /* candidate */
q2 = accept_queue_ring_len(&accept_queue_rings[g2->base + t2]); /* candidate */

q0 += _HA_ATOMIC_LOAD(&l->thr_conn[ti->ltid]);   /* plus live conns per thread */
```

…and pushes the connection onto the winner's `accept_queue_ring` via
`accept_queue_push_mp()` (`src/listener.c:124`).

Load balancing happens **once, at admission, and never again**. Two-random-choices is
chosen over exact least-loaded because it gets nearly all the benefit for O(1) work and no
global state — the standard result.

There is also an early-exit: if another thread has already advanced the round-robin index
mid-computation, the whole calculation is abandoned rather than completed on stale inputs
(`if (n0 != _HA_ATOMIC_LOAD(thr_idx_ptr)) continue;`).

## 4. Migration: `takeover()`, idle connections only

The single escape from affinity, used when a thread wants to reuse an **idle backend
connection** currently owned by another thread. It is not general-purpose, and it can fail
at every layer:

```c
h1_takeover()                       /* src/mux_h1.c:5734 */
  -> fd_takeover(conn->handle.fd)   /* fd layer must agree      */
  -> conn->xprt->takeover(...)      /* xprt layer may refuse    */
```

The comment at `src/mux_h1.c:5746` notes an outstanding TODO about `buf_wait` when
takeover is used to free a connection — i.e. even upstream treats this as delicate.

That this needs three cooperating layers and ~60 lines of careful code *for the easy case
of an idle connection with no in-flight data* is the strongest available evidence for how
load-bearing affinity is. Ibex should expect the same, and should not offer a general
migration API.

## 5. Consequences for the Rust implementation

Affinity is what makes the Rust version pleasant rather than painful:

- Connection state is `!Send`. Not by accident — **by design, and enforced by the type
  system.** The compiler rejects the accidental cross-thread share that C can only
  document.
- No `Arc<Mutex<…>>` in the data path. `RefCell` or plain `&mut` where HAProxy uses a bare
  struct field.
- Thread-local pools are just an owned `Vec` per thread with no synchronisation.
- Per-thread counters are plain integers; only the aggregated stats view needs atomics.

The parts that must be `Send`/atomic are exactly the ones HAProxy also marks: the accept
rings, the shared tasklet list, the shared runqueue, and the stats aggregation. That is a
small, enumerable set — which is the point.

### What we give up, stated honestly

- **No automatic rebalancing.** The power-of-two-choices admission is mandatory, not
  optional, because it is the only balancing that will ever happen.
- **One pathological connection degrades its core** with no safety net. A work-stealing
  runtime would paper over this; we will not.
- **`takeover()` for idle backend connection reuse is real work**, exactly as it is in C.
  It can be deferred — until then, backend connections are reused only by their owning
  thread, which costs some connection reuse ratio under uneven load.

## 6. Watchdog

`src/wdt.c`. A timer signal checks per-thread progress; a thread that fails to clear
`TH_FL_STUCK` between two checks triggers `ha_panic()` (`src/wdt.c:192`). With hard
affinity and no stealing, a wedged thread silently strands every connection assigned to
it, so detecting it is not optional. Ibex needs an equivalent before it is ever run in
anger.
