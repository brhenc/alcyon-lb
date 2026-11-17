# Where Rust itself held Alcyon back: first candidates for upstream work (2026-11-17)

Alcyon is a proof of concept: HAProxy translated to safe Rust, function by function, with the
running HAProxy binary as the oracle. Most of what that took was ordinary porting work. A few
things could not be done well in Rust as it is today: the language, the compiler or the standard
library was missing a piece, and Alcyon worked around it. This file lists the first five, with
the evidence in this tree. Each one is a candidate for work in rustc, std or a crate, not in
Alcyon.

Nothing here has been proposed upstream. Whether and how to do that is the maintainer's decision.

## 1. MC/DC coverage

**What Alcyon needs.** HAProxy's parsers are dense boolean logic: a request is valid when a
dozen conditions hold together. Line coverage says a line ran, not that each condition in it was
shown to change the outcome. MC/DC (modified condition/decision coverage, DO-178C level A) does,
and it is the standard for code that must not misparse.

**What Rust has.** rustc had `-Zcoverage-options=mcdc` (built on LLVM's MC/DC support) on
nightly until 2025-08-08; it was removed after that (`tasks/T311-rustc-mcdc-coverage.md`). LLVM
still has it.
Still absent in 1.100.0 and on nightly as of 2026-11-17: `-Zcoverage-options` offers `block`,
`branch` and `condition` (condition coverage, not MC/DC); the tracking issue is rust-lang/rust#124144.

**Evidence.** Measured once with the last nightly that had it (T311, 2026-10-11): 3,367
conditions in the workspace, 64.42% covered; `h1.rs` 75.21%, `mux_h1.rs` 34.04%, `mux_h2.rs`
49.32%. The gate's `covercheck` uses line coverage, because that is what a current toolchain gives.

**Candidate.** Bring MC/DC back to rustc, and stabilise it: `-C instrument-coverage` with an MC/DC
option, and `llvm-cov` reporting it for Rust's `&&`, `||`, `matches!` and `if let` chains.

## 2. Allocation failure

**What Alcyon needs.** HAProxy checks every `malloc`: on NULL it gives memory back, retries
once, and fails that one stream. The process goes on.

**What Rust has.** An infallible allocation (`Vec::push`, `Box::new`, `format!`) that fails
calls `handle_alloc_error`, which aborts the process. `try_reserve` exists for `Vec`, `String`
and `VecDeque`; `Box::try_new`, the `Allocator` trait and `-Z oom=panic` are unstable. No
dependency (rustls, ring, the HTTP/2 decoder) reports a failure.

**Evidence.** `tradeoff.md` 6.23 and 3.4: Alcyon made its own sites fallible (buffers,
sessions, the arena, the timer tree, the idle lists; T445, T465, T465b), and each of those fails
one stream as HAProxy does. Every other allocation still aborts.

**Rust 1.100.0 (2026-11-12)** stabilised the `Allocator` trait (`Global`, `System`, and the
`*_in` constructors of `Box` and `Vec`; rust-lang/rust#156882). That is half of the candidate below:
an `alcyon_alloc::Pool` can now be the allocator of a `Box` or `Vec` on stable. The fallible
constructors (`Box::try_new`, `Vec::try_with_capacity`) and `oom=panic` are still unstable, so an
infallible allocation still aborts. Alcyon builds with 1.99.1 today.

**Candidate.** Stable fallible allocation on `Box`, `Rc`/`Arc` and the collections
(`try_new`, `try_with_capacity`), a stable allocator parameter, and a stable recoverable OOM
(`oom=panic`), so that a library can report the failure and the caller can fail one unit of work.

## 3. Panics

**What Alcyon needs.** A bug in one stream should close that stream, not the process serving
every other connection.

**What Rust has.** `catch_unwind` works, and Alcyon uses it per stream (`tradeoff.md` 6.26,
T447). But std itself panics, or aborts, where it could return an error: a thread whose
alternative signal stack cannot be mapped panics inside std before the thread's closure runs, and
the process aborts ("failed to allocate an alternative stack"). Alcyon maps both of a thread's
mappings itself before each spawn to turn that into a clean refusal
(`crates/alcyon-alloc/src/headroom.rs`).

**Candidate.** `std::thread::Builder::spawn` returns `Err` when the signal stack cannot be
mapped; more generally, an audit of the places std panics or aborts on resource exhaustion where
it has an `io::Result` to return.

## 4. `sendmsg` and `recvmsg` for UDP

**What Alcyon needs.** QUIC over UDP: `recvmmsg`/`sendmmsg` to move a batch of datagrams per
system call, and ancillary data (`IP_PKTINFO`, `IPV6_RECVPKTINFO`) to answer from the address a
datagram was sent to, on a socket bound to a wildcard address.

**What Rust has.** `std::net::UdpSocket` has `send_to`/`recv_from` only: one datagram, no
ancillary data. The ancillary-data API in std (`unix_socket_ancillary_data`) is unstable and for
Unix-domain sockets only.

**Evidence.** `crates/alcyon-mmsg` exists for this alone and holds the most `unsafe` of any
Alcyon crate: 34 sites, all building or reading `msghdr`, `mmsghdr`, `cmsghdr` and
`sockaddr_storage` by hand.

**Candidate.** A safe `sendmsg`/`recvmsg` on `UdpSocket` with typed control messages
(packet info, GSO segment size, GRO, ECN), and a batched variant; or the same in `rustix`, which
Alcyon already uses for its other system calls.

## 5. The `unsafe` left in the tree

Every Alcyon crate that can is `#![forbid(unsafe_code)]`: `alcyon-rt`, `alcyon-proto`,
`alcyon-config`, `alcyon-sample`, `alcyon-sched`, `alcyon-tls`, `alcyon-quic`,
`alcyon-stick-table`, `alcyon-regex`, `ebtree`, `slz`. What is left (2026-11-17, counted as
`unsafe` blocks, functions and impls, comments excluded):

| where | sites | why | what would remove it |
|---|---|---|---|
| `alcyon-mmsg` | 34 | UDP batches and ancillary data | §4 |
| `alcyon-alloc/src/zero_on_free.rs` | 31 | wipe freed memory inside the global allocator (`tune.alcyon.zero-on-free`, 6.29) | a `GlobalAlloc` wrapper is `unsafe` by definition; a std hook to wipe on free, or an allocator that offers it |
| `alcyon-alloc/src/lib.rs` | 7 | the counting allocator (allocations per request, `show pools`) and `malloc_trim` | the same; a safe `malloc_trim` in a crate |
| `alcyon-alloc/src/headroom.rs` | 1 | map a thread's stacks before the spawn | §3 |
| `alcyon-h1-sys` | 5 | FFI to HAProxy's own C parser, used only as a differential oracle in tests (6.11) | nothing: it is a test of the translation, not part of Alcyon |
| `alcyon-alloc/src/stack_probe.rs`, `pool.rs` tests | 3 | test-only: read the stack a call left behind, set a test vector's length | nothing needed |
| `vendor/quinn-proto` | 5 | upstream quinn-proto, vendored | upstream |
| `vendor/ringalcyon` | 257 | ring's cryptography: assembly and its FFI | a pure-Rust constant-time crypto provider with the same performance |

Below these, `rustix` and `nix` hold the `unsafe` for the other system calls (epoll, sockets,
signals); that is their job, and it is audited there.

**Candidate.** The two rows that are not tests or vendored crates come down to §3 and §4, plus an
allocator hook (zero on free, trim) that would let the global-allocator wrapper go.
