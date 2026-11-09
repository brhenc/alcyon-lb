# Roadmap: after HTX

Written 2026-09-23 against `b632cd2`. Scoping, not a task list — the nudges stay the unit
of work. This exists to answer two questions: what comes after HTX, and whether HTTP/3
should be scoped now.

## Where the project actually is

Measured, not estimated:

| | |
|---|---|
| Rust source | 42,327 lines across 8 crates |
| HAProxy, in scope after §4.2 declines and rustls replacing `ssl_*.c` | ~240,000 lines of C |
| Per-request allocations | 17, 1,053 bytes (from 93 / 41,412) |
| Per-TCP-connection allocations | **0** |
| Implemented but unreachable from the daemon | **h2 (2,482 lines), HTX (1,991)** — and nothing else |

That last row is the important one. The capability matrix now says only two subsystems are
dark, and they are the same two, because one blocks the other. Everything else that exists
is reachable. The integration debt is concentrated rather than spread, which is the good
version of that problem.

---

## HTTP/3: defer, and say so properly

**Recommendation: keep it declined, and strengthen the reason in `tradeoff.md` §4.2 from
"a tractable project" to the structural one below.**

The line count is the least of it. `quic*.c` is 21,386 lines and `h3*.c` another 4,226, but
the real objection is that **Alcyon has no datagram I/O at all.** The entire UDP surface in
the runtime is three lines in `syslog.rs`. QUIC is not a protocol you add on top of the
existing I/O path; it needs a second one:

- **Connections are not file descriptors.** QUIC demultiplexes by connection ID from
  datagrams arriving on one shared socket. `fdtab`, the poller and the session arena are
  all built around one fd per connection, and `SO_REUSEPORT` with hard affinity (§1.1,
  §3.1) assumes the kernel does the steering. With QUIC, steering is ours.
- **Throughput needs `recvmmsg`, `sendmmsg`, GSO and GRO.** None of that machinery exists,
  and without it a QUIC implementation is a demo rather than a load balancer.
- **TLS moves inside the transport.** rustls terminates TLS over a byte stream, which is
  what `alcyon-tls` does today. QUIC needs the handshake driven at the record layer with its
  own key schedule and 0-RTT handling — a different integration, not a reuse.
- **Loss recovery and congestion control are the actual work.** They are where QUIC
  implementations are won or lost, they are stateful and timing-sensitive, and they would
  land on a scheduler that has never had to do them.

Against that: the stated scope is a small-to-medium-site HTTPS load balancer, where HTTP/2
is table stakes and HTTP/3 is a differentiator. **And h2 is currently unreachable.** Doing
h3 before h2 works would be building the second storey twice.

**Do not pre-shape anything for it either.** The mux seam already mirrors HAProxy's
`mux_ops`, so if QUIC ever arrives it has somewhere to plug in. Speculative generality
beyond that is a cost paid now for a benefit that may never come.

**Revisit when all three are true:** h2 is reachable and measured; the datagram I/O path
exists for some other reason (or someone decides to build it deliberately, as its own
project); and there is a concrete user asking for it. Until then the honest answer is that
QUIC is a second daemon wearing the same config parser.

---

## The order after HTX

### 1. Connect h2 — the highest value per unit of work in the project

2,482 lines are already written: preface, HPACK with a dynamic table, flow control,
`RST_STREAM`, `GOAWAY`, with its own conformance suite. HTX is the only thing standing
between that and a client being able to use it, because `mux_h2` produces HTX the way
`mux_h1` will.

Nothing else on this list turns that much existing work from zero into something that
serves traffic. It also closes the last dark row in the capability matrix.

**Oracle:** a real client negotiating h2 over TLS against a listener and getting a
response — `curl --http2`, then the existing `http2_conformance` suite driven through the
daemon rather than against `alcyon-proto` directly. The `+H2` in the `-vv` banner goes back
in the same commit, and not before.

### 2. `struct server` — the 60,000-backend claim

`tradeoff.md` §6.5 calls this "the single largest measured win available in the project and
nothing has been built for it yet": 3,456 bytes per server, so 207 MB at 60k backends,
against ~31 MB if the two embedded `struct check` become `Option<Box<_>>` with interned
strings and side-array counters.

It moves up the list now for a reason that did not hold last week: **it is finally
claimable.** The allocation oracle and `tools/allocprofile` exist, so a memory claim can be
measured instead of calculated. This is also the number the project is *about* — 60k
backends per process is in the project's own framing, and right now it is arithmetic.

**Oracle:** a test that instantiates 60,000 backends and asserts resident memory under a
bound, with the before and after in the commit.

### 3. Backend connection reuse at scale

Keep-alive reuse per session works — I verified three requests over one client connection
reaching a backend that accepted once. What does not exist is a **shared idle connection
pool** across sessions, which is what `http-reuse safe|aggressive|always` selects between
and what makes a real load balancer efficient when thousands of short client connections
map onto a small backend pool.

This is the difference between "proxies correctly" and "proxies well", and it interacts
with §6.5, since idle connections are per-server state.

### 4. Breadth — and this is the part that does not need an agent

134 of HAProxy's 211 converters are missing, along with a long tail of sample fetches.
These are pure functions with an existing template and a ratchet test that catches a
misspelled name. `bhenc-nudge-1.md` covers the first four.

This tier is deliberately last for agent time and first for human time: it is the work that
parallelises across evenings and needs no architectural judgement.

---

## The discipline that matters more than the order

The recurring defect in this codebase has never been bad code. It has been **code that is
complete, tested, and connected to nothing** — two `CURRENT_VARS`, three HTX
representations, `stick_rules` cloned and never read, `Pool<T>` with no callers, h2 and HTX
today.

`data/capability_matrix.md` is the instrument for that, and it works — it caught the `+H2`
banner claiming a capability no client could reach. Keep the rule that a row changes in the
same commit as the behaviour it describes, and treat any new row that lands `Yes / No / No`
as a defect rather than progress.

The same applies to the allocation numbers. `tools/allocprofile` and the pinned bounds in
`request_allocations.rs` are now the record. A change that raises them needs to say why in
the commit, and a change that lowers them should say by how much.

---

## Housekeeping found while scoping this

**`tradeoff.md` §6.6 is stale.** It describes `match_map` doing `std::fs::read_to_string`
and a linear scan per evaluation. That is fixed: `registry.rs` now has `MAP_CACHE` with a
read-lock fast path and the disk read happening once. The entry sits in "Open, unverified,
and owed" describing a solved problem, which is worse than not having it. It should move to
resolved, with the remaining cost noted honestly — an `RwLock` read per evaluation, which
is a lock on the data path but not a syscall.

**§4.2's reasoning for declining QUIC/H3** should be replaced with the structural argument
above. "A tractable project" invites the question every six months; "there is no datagram
I/O path and connections are not file descriptors" settles it until something actually
changes.

**The remaining 17 allocations per request** are `process_cli_io` (7), `h1::parse_header_field`
(4), `HtxBlock` growth (2, deliberately deferred to the HTX work), and four singletons.
Diminishing returns — worth leaving until HTX lands, since the HTX work removes the
`HtxBlock` ones and touches the parse path anyway.
