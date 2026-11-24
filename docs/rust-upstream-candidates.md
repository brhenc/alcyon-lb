# Where Rust itself held Alcyon back: first candidates for upstream work (2026-11-17)

Alcyon is a proof of concept: HAProxy translated to safe Rust, function by function, with the
running HAProxy binary as the oracle. Most of what that took was ordinary porting work. A few
things could not be done well in Rust as it is today: the language, the compiler or the standard
library was missing a piece, and Alcyon worked around it. This file lists the first five, with
the evidence in this tree. Each one is a candidate for work in rustc, std or a crate, not in
Alcyon. A sixth (§6, a stable ABI) did not block the port; it is about how Rust programs are
shipped and updated, and it was added on 2026-11-23.

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

## 6. A stable ABI for Rust-to-Rust linking

This one did not block the port. Alcyon ships as one static binary. The problem shows when Rust
programs are packaged, updated and fitted onto small systems.

**What is needed.** One shared copy of a library that many programs link against, versioned
by soname, the way a C system shares libc, libssl and libpcre2:
- **On an embedded system with little storage,** each program would carry only its own code.
- **On a distribution,** a security fix in a library would mean shipping one package, not
  rebuilding every program that uses it.
- **For an operating system written in Rust from top to bottom,** this is a precondition: its
  system libraries would need an interface that stays stable across compiler releases.

**What Rust has.**
- **A C boundary only.** `extern "C"`, `#[repr(C)]` and `crate-type = "cdylib"` (with `cargo-c`
  for the soname and pkg-config) give a C-style shared library. Across that boundary there are
  no generics, enums with data, slices, `String`, `Vec` or traits.
- **No stable layout for Rust's own types.** The default layout (`repr(Rust)`) and calling
  convention are unspecified on purpose, so the compiler can reorder fields and pack enum tags
  into unused bit patterns. That is how `Option<&T>` is the size of a pointer.
- **A `dylib` that works with one compiler only.** A Rust `dylib` links only with the exact
  compiler that built it. Generic code is compiled into the caller for each type, so most of a
  Rust API could not live in a shared library even with a stable layout.
- **Unstable or third-party attempts.** An opt-in stable ABI, crABI (`extern "crabi"`,
  `repr(crabi)`; rust-lang/rfcs#3470, tracking rust-lang/rust#111423), is not in stable Rust as
  far as this file knows. Check its status before proposing anything. The crates `abi_stable` and
  `stabby` build stable layouts on top of the C ABI.

**Evidence.** Measured on 2026-11-23 with Fedora's rustc 1.100.0, x86-64, `-C opt-level=s`,
stripped:

| program | size |
|---|---|
| C `puts("hello")`, glibc linked dynamically | 11,176 bytes |
| Rust `println!("hello")`, std linked statically (the default) | 337,584 bytes |
| Rust `println!("hello")`, `-C prefer-dynamic` | 11,080 bytes |

- **The shared std is tied to one compiler build.** The 11,080-byte binary needs
  `libstd-b77c5b484b975315.so` (1,249,768 bytes). The hash in that file name changes with each
  compiler build, and Fedora installs it under `/usr/lib/rustlib/`, outside the loader's path, so
  the binary does not run as built. In practice every Rust program carries its own copy of std
  and its crates.
- **Every crate update means a rebuild.** Alcyon's `alcyon-rt` links 125 third-party crates
  (`cargo tree -p alcyon-rt -e normal`, 2026-11-23). A fix in any one of them means rebuilding
  Alcyon, and every other program that uses that crate.

**What Swift did.** Swift became ABI-stable in Swift 5 (2019) so that Apple's system frameworks
could be shared libraries. It uses "library evolution": inside a library the compiler optimises
freely, and across the library boundary, layouts, sizes and generic code go through indirection
(type metadata and witness tables, looked up at run time). Aria Beingessner, "How Swift Achieved
Dynamic Linking Where Rust Couldn't" (2019, faultlore.com/blah/swift-abi/), explains the design
and why Rust's choices (monomorphization, static layout) make the same thing harder. It is the
best starting point for this work.

**What C++ shows about the other extreme.** C++ keeps a de facto stable ABI (Itanium), and in
2020 its committee declined to break it. Known-slow designs (`std::regex`, `std::unordered_map`,
`unique_ptr` not passed in registers) are now frozen ("ABI: Now or Never", P1863). A Rust ABI
should be opt-in at chosen boundaries, as Swift's is, not a freeze of the whole language.

**Candidate.** Compiler work, to try in the Swift manner:
- An opt-in ABI-stable boundary for a crate (crABI or a successor) that covers enums with data,
  slices, `str`, `Option` and `Result`, and trait objects.
- A resilient mode in which generic functions and types can cross a shared-library boundary
  through indirection, at a cost paid only there.
- A versioned, shareable std built on top of those two.
