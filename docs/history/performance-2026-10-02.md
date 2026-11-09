# Performance: Alcyon against HAProxy

Measured 2026-10-02 on main `b61b340` (design 010 steps 1-4 merged) against the reference
HAProxy (`3.5-dev7-e6f616-55`, `/home/bhenc/reference/haproxy/haproxy`). The open question
this records: **where does Alcyon spend the CPU HAProxy does not?** The syscall profile
below found an architecture difference -- Alcyon read a socket on every pass over a session
where HAProxy reads it only when epoll says it is readable -- and it was fixed the same day,
ahead of the `patches/` integration, because every later change would have been built and
measured on top of it. See **Fixed: read only when readable** at the end; the tables before
it are the "before".

`data/perf_parity.md` (T39) is older and measured differently (unpinned, before the HTTP
transaction); prefer the numbers here.

## How it was measured

Same harness for both, one process per role, each pinned to its own core in one L3 group of
the 32-core EPYC 7542 (`taskset -c 4` proxy, `5` client, `6` backend), `nbthread 1`, the
`measure-bench` backend and client (`tools/measure/bench`), plain HTTP/1.1 keep-alive,
`GET /`, empty 200 response. CPU is the proxy's own time from
`/proc/<pid>/task/*/schedstat` over a fixed number of requests (`measure-bench fixed`).
Unpinned, one build's samples split into two clusters ~25% apart, depending on whether the
scheduler put the three processes in one L3.

The gate's A/B (`tools/measure/measure.py`, `measure_ab`) uses the same setup. Between two
identical builds it agrees to 0.3% on CPU per request at 50 connections.

## Results

| | HAProxy | Alcyon |
|---|---|---|
| CPU per request, 50 connections | **17.8 µs** | **20.6-21.0 µs** (+16-18%) |
| Requests/s, 50 connections (client-bound) | ~31.6k | ~31.9k |
| CPU per request, 1 connection | 33.5 µs | 41-44 µs |
| Requests/s, 1 connection | 16-17k | 14-19k |
| Syscalls per request, 1 connection | 10.2 | 17.0 |
| Syscalls per request, 50 connections | **4.2** | **13.1** |

At 1 connection both proxies sleep in `epoll_wait` between requests, and CPU per request
there also measures how often a process sleeps and wakes. c0e2ca6 (Alcyon's timer disarm)
moved Alcyon's 1-connection CPU by +29% while gaining 21% requests/s, by sleeping a quarter as
often, and left the 50-connection figure unchanged. **Compare the two at 50 connections.**

For history: Alcyon before the HTTP transaction (`cd435a8`) cost 18.4 µs at 50 connections,
and the transaction added 11.4% (part of which is request rules now running on every
request rather than only the first).

## Syscalls per request (strace -c, 1 connection, 20,000 requests)

| HAProxy | per request | Alcyon | per request |
|---|---|---|---|
| `recvmsg` | 2.00 | `read` | **10.99** (9.0 of them `EAGAIN`) |
| `sendmsg` | 2.00 | `write` | 2.00 |
| `epoll_wait` | 2.00 | `epoll_wait` | 2.00 |
| `clock_gettime` | 4.00 | `getpid` | 2.00 |

At 50 connections: HAProxy `recvmsg` 2.00, `sendmsg` 2.00, `epoll_wait` 0.04 (66 `EAGAIN` in
200,214 receives); Alcyon `read` 10.99 (**8.98 `EAGAIN` per request**), `write` 2.00,
`epoll_wait` 0.04.

## The lead

**Alcyon attempts nine reads per request that the kernel answers with `EAGAIN`; HAProxy
attempts almost none.** HAProxy tracks readiness per file descriptor: after a short read it
marks the fd unable to receive (`fd_cant_recv`) and does not try again until epoll reports
it readable. Alcyon has that for the server side only (`srv_cant_recv`, HTTP only) and
otherwise retries the read on every pass over the session -- the client socket on every
step, whether or not anything arrived. Nine extra syscalls per request at ~0.3-0.5 µs each
is a plausible share of the 3 µs gap, and the passes that issue them are themselves work.

Also seen, smaller:
* `getpid` twice per request at 1 connection (once per `epoll_wait`): something asks for
  the pid on every poll.
* `CURRENT_TIMEOUTS`, a `HashMap` rebuilt per request in `connect_http_backend` (18 SipHash
  inserts); `RandomState::hash_one` and `HashMap::insert` are ~8% of user samples.
* About 40,000 user-space instructions per request (`perf stat`), equal in Alcyon before and
  after c0e2ca6.

## Fixed: read only when readable (2026-10-02, uncommitted on `b61b340`)

* `cli_cant_recv` beside `srv_cant_recv` (`crates/alcyon-rt/src/proxy.rs`), and both are
  now set the way `raw_sock_to_buf` sets `fd_cant_recv`: on `EAGAIN` **or on a read shorter
  than the buffer**. The short read is what removes the `EAGAIN` entirely; marking on
  `EAGAIN` alone still costs one wasted read per wakeup. Cleared in `step_stream` when the
  poller reports the fd readable; a hang-up or error event now also counts as readable
  (`fdtab.set_ready`), so the read that finds the EOF is never skipped. HTTP over plain
  sockets only, as before: `mode tcp` sessions can be driven without a poller (tests do),
  and TLS can hold decrypted bytes the socket no longer shows.
* The engine reads its pid once at construction instead of `std::process::id()` (a
  `getpid` syscall) on every step.
* Pinned by `crates/alcyon-rt/tests/reads_per_request.rs`, which counts read syscalls in
  process (`raw::read_counters`): 200 keep-alive requests made 2000 reads, 1600 of them
  `EAGAIN`, before the fix, and 400 reads, 0 `EAGAIN`, after.

| | HAProxy | Alcyon before | Alcyon after |
|---|---|---|---|
| CPU per request, 50 connections | 17.4-17.6 µs | 20.6-21.0 µs | **15.8-15.9 µs** |
| Requests/s, 50 connections | ~32.2k | ~31.9k | **36-38k** |
| Syscalls per request, 1 connection | 10.2 | 17.0 | **6.0** |
| Syscalls per request, 50 connections | 4.2 | 13.1 | **4.05** |

Alcyon after, by syscall (strace -c): 1 connection, 20,000 requests -- `read` 40,011 (1
`EAGAIN`), `write` 40,000, `epoll_wait` 40,012, `getpid` 2; 50 connections, 200,000
requests -- `read` 400,162 (5 `EAGAIN`), `write` 400,098, `epoll_wait` 8,026. HAProxy and
Alcyon after were measured alternately, three rounds each, pinned as above; the gate's A/B
against `b61b340` measured 20,661 -> 15,635 ns (-24.3%) at 50 connections and +13.7%
requests/s at 1 connection.

Alcyon now does less per request than HAProxy, which is not the same as being cheaper for
the same work: HAProxy reads the clock four times per request (`clock_gettime`, the
remaining syscall difference) and keeps per-request statistics Alcyon may not yet. The
requests/s at 50 connections rose because the proxy, not only the client, had been a
bottleneck.

## Next steps

1. Replace `CURRENT_TIMEOUTS` with something that is not rebuilt per request.
2. `mode tcp` and TLS still read speculatively; the TCP side needs the sessions that run
   without a poller (tests) given readiness, or the flag made conditional on the engine.
3. Kernel-side profile (`perf` with kernel symbols needs `perf_event_paranoid` lowered).

Each change goes through the A/B (`tools/measure/run.sh --fast`, or `ALCYON_MEASURE_REF=<sha>`
to compare against a chosen commit).
