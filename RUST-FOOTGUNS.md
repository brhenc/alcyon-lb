<!--
SPDX-License-Identifier: GPL-2.0-or-later
Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
-->
# Rust footguns: how a safe Rust program still goes down

Written 2026-10-17 for operators and reviewers. Rust removes the memory-corruption bugs that turn
a C proxy's crash into a remote code execution: use-after-free, buffer overflows, NULL
dereferences. It does not remove crashes. Rust's answer to "this cannot go on" is to **stop
the process**, and in Alcyon one process serves every connection. A crash an attacker can cause
whenever they like is a denial of service. This file lists the ways that can happen, what Alcyon
does about each today, and what is still open (T357).

## 1. Why one failure takes down everything

- Alcyon is **one worker process with N threads** (one per core, `nbthread`). Each connection
  belongs to one thread. Under `-W` a master process watches that worker.
- Alcyon turns **every panic into an abort of the whole process** (`crates/alcyon-rt/src/crash.rs`,
  T238). That is deliberate and matches HAProxy's `BUG_ON()`. Left to Rust's default, a panic
  ends only its own thread: the proxy went on with fewer threads and, with one thread, exited
  0, so systemd saw a clean stop and did not restart it.
- When the worker dies, the master logs `exited with code 134 (Aborted)`, stops and exits
  134, as HAProxy's does. The example systemd unit has `Restart=always`, so the proxy comes
  back, but **every open connection on every thread is lost** and new ones are refused until
  it has restarted.

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
  that every allocation failure is a whole-process crash.

When malloc actually returns NULL on Linux:

| situation | what happens |
|---|---|
| Default overcommit (`vm.overcommit_memory=0`), memory runs out | malloc rarely fails; the kernel OOM killer SIGKILLs the biggest process instead. The same happens to HAProxy. |
| `ulimit -v` / `RLIMIT_AS`, or `vm.overcommit_memory=2` | malloc returns NULL, so Alcyon aborts where HAProxy would fail one stream. |
| **One request for a huge size** (a length read off the wire and passed to `Vec::with_capacity`) | fails at once **even with plenty of free memory**, so it aborts; above `isize::MAX` it is a `capacity overflow` panic, so it aborts too. This needs no memory pressure at all, so it is the attacker's best tool. |
| Slow, unbounded growth (a buffer, a table, a list that is never trimmed) | ends with the OOM killer, as in C. |

What protects Alcyon today:
- Sizes from the wire are bounded by `tune.bufsize`-style limits before buffers are taken.
  The I/O buffers come from a per-thread pool.
- The fuzzers (libFuzzer, differential) feed hostile sizes to the parsers.
- The `request_allocations` tests pin the per-request count.

Still open:
- About 6 allocations per request on the real binary (tradeoff.md §6.13). The goal is zero:
  pools taken with a fallible, bounded call, where an empty pool fails one stream.
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
| `println!`, `eprintln!` | the write fails, for example with EAGAIN on a full non-blocking stderr pipe. **This happened** (T342b: `log stderr` plus a stalled reader aborted Alcyon); `eprintln!` is now denied by clippy outside tests. |
| `unreachable!()`, `panic!()`, `assert!()` | the "impossible" happens |

Today:
- `clippy::panic` is warned workspace-wide.
- `unwrap_used`, `expect_used`, `indexing_slicing` and `arithmetic_side_effects` are **not**
  enabled.
- `src/` has about 311 `.unwrap()` and 413 `.expect(` sites. Many are in unit tests inside
  those files. How many sit on the request path has not been measured (T357).

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
- Rust prints `thread '...' has overflowed its stack` and the process dies with SIGSEGV
  (SIGABRT). No hook runs.
- The defence is no recursion on input-controlled depth, or an explicit depth limit (HAProxy
  limits nesting too).

## 6. Hangs: not a crash, still an outage for one thread

- Each thread runs an event loop. Anything that blocks it stalls every connection on that
  thread. Examples: a blocking DNS lookup (`getaddrinfo`), a file read on a slow disk, a lock
  held across I/O, an `O(n²)` loop on attacker-sized input.
- Rust does not prevent these.
- The defences:
  - the V&V canary (p99 of a normal request during an attack) and netfuzz's stall rule,
    > 5 s (T347);
  - HAProxy's watchdog has no Alcyon counterpart yet (tradeoff.md §6.4).

## 7. Smaller ones

- **Mutex poisoning:** after a panic, `lock().unwrap()` panics again. This doesn't matter for
  Alcyon, because the first panic already aborted.
- **Hash flooding:** `std::collections::HashMap` uses a keyed SipHash, so it is safe. A faster
  unkeyed hasher (FxHash, ahash without a random key) on attacker-chosen keys would be an
  `O(n²)` DoS. None is in the workspace's `Cargo.toml` files today (checked 2026-10-17).
- **`unsafe` and FFI:** they bring back C's failure modes. Alcyon keeps `unsafe` warned
  workspace-wide and confined to a few crates (tradeoff.md §6.11).

## What a reviewer checks on a data-path change

1. No new allocation per request (the `request_allocations` tests). Any size from the wire is
   bounded before it is allocated.
2. No `unwrap`/`expect`/indexing on a value an attacker can shape. Use `get()`, `?` and
   `checked_*`.
3. Time and size arithmetic is checked or saturating.
4. No recursion whose depth input can set.
5. Nothing blocking in the event loop.
