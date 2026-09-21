# Ibex Design Notes

Working design documents for Ibex, a memory-safe reverse proxy that keeps HAProxy's
architecture and configuration language.

**Reference source:** `/home/bhenc/reference/haproxy` @ `e6f616af` (3.5-dev7, mainline,
cloned 2026-09-21). Every struct, line number, and constant cited in these documents was
read from that tree. When a claim here is about HAProxy, it has a file:line behind it.

## Documents

| # | Document | Status |
|---|---|---|
| 001 | [Layer model](001-layering.md) — connection / xprt / mux / stconn / stream / session | analysed |
| 002 | [Threading and affinity](002-threading-and-affinity.md) — thread-per-core, accept distribution, takeover | analysed |
| 003 | [Scheduler](003-scheduler.md) — run queue, timers, class budgets, and why not tokio | analysed, **to build** |
| 004 | [Elastic binary trees](004-ebtree.md) — design, and the arena/tagged-index translation | analysed, **to build** |
| 005 | [Sprint plan and delegation contract](005-sprint-plan.md) | active |
| 006 | [Data layout and observability tiers](006-data-layout.md) — measured sizes, why an enum beats a function pointer, debug/production tiering | analysed |
| 007 | Sample / converter / matcher lattice | after the scheduler |

## Decisions taken

- **D1 — Own scheduler, not tokio.** Ibex implements HAProxy's task/tasklet scheduler in
  Rust rather than adopting a general-purpose async runtime. Rationale and evidence in
  [003](003-scheduler.md). The short version: HAProxy's scheduler has four properties that
  exist specifically to survive adversarial load — class budgets, bounded work per pass,
  lazy timer requeue, and key-width-bounded tree depth. A general-purpose runtime optimises
  for throughput on cooperative workloads and provides none of them.
- **D2 — Thread-per-core with hard connection affinity.** Connections are assigned to a
  thread at accept and do not migrate. The data path is therefore lock-free by
  construction. See [002](002-threading-and-affinity.md).
- **D3 — ebtree as the core ordered structure**, implemented over an index arena with
  tagged `u32` references rather than tagged pointers. Same asymptotics and better cache
  density than the C original, with no `unsafe`. See [004](004-ebtree.md).
- **D5 — Representations are chosen by measured layout, not idiom.** Work kind is an
  8-byte enum rather than C's 16-byte function pointer + `void *`: smaller, no indirect
  call, and introspection comes free. `Box<dyn Task>` is rejected for its per-task
  allocation. See [006](006-data-layout.md).
- **D6 — Observability is tiered, never a per-connection layout tax.** Compile-time
  fields, runtime-gated writes, on-demand walking, and per-connection side tables behind
  a cold branch. Alternate structures per connection would make every connection pay for
  the few being debugged. See [006](006-data-layout.md) §5.
- **D4 — Scope cuts.** No Lua, no filters, no SPOE, no QUIC/H3, no FCGI. Target is a
  small-to-medium-site HTTPS load balancer with HAProxy config syntax, the runtime socket,
  and a stats page that works with (a lightly modified) hatop.

## Build order

1. ebtree (004) — everything else sits on it
2. scheduler (003) — task/tasklet, run queue, wait queue, class budgets
3. layer skeleton (001) — traits + a TCP passthrough proxy through all five layers
4. sample/converter/matcher engine (005)
5. HTX + H1 mux
6. config parser, CLI applet, stats applet
7. TLS behind the sealed transport trait
8. checks, LB algorithms, stick tables
9. HAProxy's own `reg-tests/*.vtc`, unmodified, as the scoreboard

## Non-goals, stated up front

Not "99% of HAProxy". HAProxy is ~338k lines of C across 572 files. The target is total
compatibility on a deliberately narrow surface, measured by passing HAProxy's own
regression tests, not a self-assessed percentage.
