<!--
SPDX-License-Identifier: GPL-2.0-or-later
Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
-->
# Rust footguns: how a safe Rust program still goes down

Written 2026-10-17 for operators and reviewers; brought up to date with the code 2026-11-09.
Rust removes the memory-corruption bugs that turn a C proxy's crash into a remote code
execution: use-after-free, buffer overflows, NULL dereferences. It does not remove crashes.
Rust's answer to "this cannot go on" is to **stop the process**, and in Alcyon one process
serves every connection. A crash an attacker can cause whenever they like is a denial of
service. This file lists the ways that can happen, what Alcyon does about each today, and what
is still open (T357).

## 1. Why one failure takes down everything

- Alcyon serves from **one process with N worker threads** (one per core, `nbthread`). Each
  connection belongs to one thread. With `-W -S`, or `-W` with `user` / `group` / `chroot`, a
  master process runs beside it and starts it; plain `-W` and the default mode have no master.
- Alcyon turns **every panic into an abort of the whole process** (`crates/alcyon-rt/src/crash.rs`,
  T238). That is deliberate and matches HAProxy's `BUG_ON()`. Left to Rust's default, a panic
  ends only its own thread: the proxy went on with fewer threads and, with one thread, exited
  0, so systemd saw a clean stop and did not restart it.
- When the serving process dies, a master logs `Current worker (<pid>) exited with code 134
  (Aborted)`, stops any other workers and exits 134, as HAProxy's does (`exit-on-failure`,
  `bin/alcyon/master.rs`); without a master the process itself exits 134. The example systemd
  units (`admin/systemd/`, `contrib/systemd/`) have `Restart=always`, so the proxy comes back,
  but **every open connection on every thread is lost** and new ones are refused until it has
  restarted.

So "kills the worker" means the whole proxy, for a moment, for every visitor.

## 2. A failed memory allocation aborts the process

This is the one that surprises C programmers.

- In C, `malloc` returns NULL and the caller has to check. HAProxy's pools do check: an empty
  pool fails that one stream, and `tune.buffers.reserve` keeps buffers back for streams already
  running.
- In Rust, ordinary code (`Box::new`, `Vec::push`, `String`, `format!`, `clone`) has **no way
  to report failure**. When the allocator returns NULL, the standard library calls
  `handle_alloc_error`, which prints `memory allocation of N bytes failed` and **aborts**.
  You cannot catch it. Stable Rust offers no hook that makes it recoverable.
- The C bug where an unchecked NULL leads to a cascade cannot happen in Rust. The price is
  that every allocation failure outside code written to expect it is a whole-process crash.

When malloc actually returns NULL on Linux:

| situation | what happens |
|---|---|
| Default overcommit (`vm.overcommit_memory=0`), memory runs out | malloc rarely fails; the kernel OOM killer SIGKILLs the biggest process instead. The same happens to HAProxy. |
| **`-m <megs>`** (Alcyon sets `RLIMIT_DATA`, as HAProxy does), `ulimit -d` / `-v`, or `vm.overcommit_memory=2` | malloc returns NULL. A pooled buffer or session that cannot be had fails its stream (below); any other allocation aborts, where HAProxy would fail one stream. |
| **One request for a huge size** (a length read off the wire and passed to `Vec::with_capacity`) | fails at once **even with plenty of free memory**, so it aborts; above `isize::MAX` it is a `capacity overflow` panic, so it aborts too. This needs no memory pressure at all, so it is the attacker's best tool. |
| Slow, unbounded growth (a buffer, a table, a list that is never trimmed) | ends with the OOM killer, as in C. |

What protects Alcyon today:
- **No allocation per request in steady state** (tradeoff.md §6.13, built 2026-10-24/25). Buffers,
  sessions, applets and tasks come from `alcyon_alloc::Pool` and `Arena`
  (`docs/design/memory-2026-10-24.md`). Tests with a counting allocator pin it at zero
  allocations per request for proxied HTTP/1 keep-alive, h2c, TLS, TLS to TLS, HTTP/2 to
  servers, rules, `return` replies, logging, and HTTP/3 through the mux
  (`crates/alcyon-rt/tests/request_allocations.rs`, `tls_request_allocations.rs`,
  `request_allocations_h3.rs`).
- **Pooled objects are taken fallibly.** An empty buffer pool is answered by `pool_gc` and one
  retry, then the stream fails instead of the process. HAProxy's buffer wait queue (S6) is only
  partly done, so some waits that HAProxy queues still fail their stream.
- **Starting under `-m`** checks that each thread's stack and signal stack fit before spawning
  it (`alcyon-alloc/src/headroom.rs`), so a budget too small is refused with an `[ALERT]` instead
  of a panic in std.
- Sizes from the wire are bounded by `tune.bufsize`-style limits before buffers are taken.
- The fuzzers (libFuzzer, differential) feed hostile sizes to the parsers.

Still open:
- What stays on the heap and is infallible: rustls 0.23 on QUIC and the log forwarder, the
  HPACK / QPACK decoders, and std internals (tradeoff.md §6.13, §6.22, §6.23). A failure there
  aborts.
- No audit yet of every allocation whose size an attacker controls (T357).

## 3. Panics: ordinary operations that stop the process

Each of these is a panic, so (section 1) it aborts the whole proxy:

| operation | panics when |
|---|---|
| `x.unwrap()`, `x.expect("...")` | `x` is `None` or `Err` |
| `v[i]`, `&s[a..b]` | out of bounds |
| `&s[a..b]` on a `str` | `a`/`b` falls inside a multi-byte character |
| `a / b`, `a % b` (integers) | `b == 0` |
| `RefCell::borrow_mut()` | already borrowed (re-entrancy) |
| `Instant + Duration`, `Duration * n` | the result overflows (a huge timeout from config or the CLI) |
| `Duration::from_secs_f64(x)` | `x` is negative, NaN or too big |
| `println!`, `eprintln!` | the write fails, for example with EAGAIN on a full non-blocking stderr pipe. **This happened** (T342b: `log stderr` plus a stalled reader aborted Alcyon); `eprintln!` and `eprint!` are now disallowed by `clippy.toml` outside tests (a clippy warning; use `stderr_line!`). |
| `unreachable!()`, `panic!()`, `assert!()` | the "impossible" happens |

Today:
- `clippy::panic`, `todo` and `unimplemented` are warned workspace-wide. Warnings fail
  `make lint` (`-D warnings`) but not the check-in gate, whose lint stage fails only on clippy
  errors.
- `unwrap_used`, `expect_used`, `indexing_slicing` and `arithmetic_side_effects` are **not**
  enabled.
- `src/` has about 437 `.unwrap()` and 675 `.expect(` sites (2026-11-09, unit tests included).
  A static and fuzzed sweep of the request path (T357a, 2026-10-17) found no panic a client can
  reach; measuring the rest and turning those lints to `deny` in the data-path crates is still
  open (T357).

## 4. Integer overflow is silent in release builds

- Release builds do not check overflow (Rust's default; Alcyon does not set `overflow-checks`).
  `u32` arithmetic wraps around without a word.
- That is not a crash in itself. It can produce a wrong length or a wrong timeout, which then
  becomes a slice panic (section 3) or a logic bug further on. Debug builds and tests panic
  instead, so the fuzzers catch some of it.
- The fix is `checked_*` / `saturating_*` on every size and time derived from input.

## 5. Stack overflow cannot be caught

- Deep recursion ends at the thread's guard page. Examples: a recursive parser, regex
  backtracking, dropping a long linked structure.
- Rust prints `thread '...' has overflowed its stack` and aborts: the process dies with
  SIGABRT. No panic hook runs.
- The defence is no recursion on input-controlled depth, or an explicit depth limit (HAProxy
  limits nesting too). The JSON converters parse with serde_json, whose default limit of 128
  levels returns an error instead of recursing further; configuration regexes that need
  backtracking run under fancy-regex's backtracking limit.

## 6. Hangs: not a crash, still an outage for one thread

- Each thread runs an event loop. Anything that blocks it stalls every connection on that
  thread. Examples: a blocking DNS lookup, a file read on a slow disk, a lock held across I/O,
  an `O(n²)` loop on attacker-sized input.
- Rust does not prevent these.
- The defences:
  - name resolution at run time goes through `alcyon-dns`, which does no blocking I/O, as
    scheduler tasks (`resolvers` sections); `getaddrinfo` runs only while the configuration
    loads;
  - **the watchdog** (`crates/alcyon-rt/src/watchdog.rs`, T361, HAProxy's `src/wdt.c`): a worker
    that has made no progress is reported, and after a second of its own CPU time the process is
    aborted (exit 134) so that the master or the service manager restarts it. It measures CPU
    time like HAProxy's, so it catches a spinning thread but **not a thread that is blocked**
    (deadlocked, or waiting in a system call) (tradeoff.md §6.4);
  - load tests that watch a normal request's latency while an attack runs.

## 7. Smaller ones

- **Mutex poisoning:** after a panic, `lock().unwrap()` panics again. This doesn't matter for
  Alcyon, because the first panic already aborted.
- **Hash flooding:** `std::collections::HashMap` uses a keyed SipHash, so it is safe. A fast
  unkeyed hasher on attacker-chosen keys would be an `O(n²)` DoS. The only one in the graph is
  FxHash (`rustc-hash`), through quinn-proto, which keeps it to keys it creates itself (its own
  connection IDs) and to small maps bounded by QUIC's limits (stream IDs, sequence numbers); the
  maps keyed by what a client chooses (Initial connection IDs, addresses, reset tokens) are std
  `HashMap`s (`vendor/quinn-proto/src/endpoint.rs`). Checked 2026-11-09.
- **`unsafe` and FFI:** they bring back C's failure modes. `unsafe_code` is warned
  workspace-wide, eleven crates forbid or deny it, and it is confined to `alcyon-alloc` (the
  allocator and pools), `alcyon-mmsg` (`recvmmsg` / `sendmmsg`), `alcyon-h1-sys` (HAProxy's C
  parser, a test oracle; tradeoff.md §6.11) and the vendored crates. `alcyon-alloc` and
  `alcyon-mmsg` run clean under Miri (T623).

## What a reviewer checks on a data-path change

1. No new allocation per request (the `request_allocations` tests). Any size from the wire is
   bounded before it is allocated.
2. No `unwrap`/`expect`/indexing on a value an attacker can shape. Use `get()`, `?` and
   `checked_*`.
3. Time and size arithmetic is checked or saturating.
4. No recursion whose depth input can set.
5. Nothing blocking in the event loop.
