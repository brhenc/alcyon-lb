# Rust performance survey: do Rust projects beat C, and what Alcyon can take from them (T550, 2026-10-31)

Status: research and audit only. No code was changed and nothing was timed or counted for this
report: both measuring slots were busy. Every Alcyon number below comes from an earlier
measurement, named where it is used. Most are from T544's IBS profile
(`docs/design/quic-profile-2026-11-01.md`, raw data in `~/ibex-worktrees/review/t544-2026-11-01/`).
T539's `instructions:u` samples are not used, because T544 showed they skid onto syscalls.

## 0. Verdict

**"Rust is faster than C" is mostly hype. "Rust can match C, and makes the better algorithm
safe to write" holds up.**

- **Faster cases.** Every well-measured case where a Rust program beats its C counterpart comes
  from a better algorithm, library, or architecture that C could also use. Examples: ripgrep's
  literal extraction and Teddy, the SwissTable layout, rustls against a regressed OpenSSL 3, and
  Pingora's shared connection pool.
- **Like-for-like ports.** Where the same algorithm was ported carefully, the Rust version lands
  0-6 % *slower* (rav1d, zlib-rs at fair build settings). The cost is bounds checks, panic
  paths, and zero-initialisation.
- **No language-level win.** No source we found credits a measured speedup to the language
  itself (noalias, monomorphisation).

For Alcyon the lesson is the same. Alcyon is 1.49x HAProxy on h2: 79.6k against 53.4k instructions
per request (T544 §1). The gap is not a Rust tax:

- **Rust taxes are small.** UTF-8 validation, `str` char-boundary checks, and bounds checks
  together cost about 2-3k per request (3 %), which is in line with rav1d and zlib-rs.
- **Most of the gap is design.** Of the h2 request, 63.6k is the common stream engine, against
  HAProxy's 26.9k (T544 §2). In that engine, Alcyon parses and re-encodes the same head several
  times through HTTP/1.1 text, reads the clock about 40 times per request, and builds a new
  session per h2 stream.
- **The one large build-level lever is already measured.** PGO gave -13.4 % instructions and
  -35 % user cycles (T435). It is not the default.

## 1. The evidence

Attribution: **A** = the algorithm, **L** = the library or data structure, **Lang** = the
language itself.

| project | result | why | sources |
|---|---|---|---|
| ripgrep vs GNU grep | 2016 benchmarks: `Sherlock Holmes` 0.27 s vs 0.52 s; Russian literal 0.33 vs 0.78 s; 5-way alternation 0.29 vs 2.96 s. The 37x unicode-word case is against `git grep`, not GNU grep | **A**: memchr on the rarest byte (frequency table) instead of Boyer-Moore's last byte; Teddy (SIMD multi-literal); literal extraction ahead of the DFA; UTF-8 decoding compiled into the DFA. The author does not credit the language, and all of it is writable in C | https://burntsushi.net/ripgrep/ |
| `memchr` crate | Matches glibc rather than beating it. Its own benchmarks compare only against Rust std (std is ~6x slower). A third-party table has libc `memmem` faster on small inputs | **A/L**. glibc's hand-written AVX2 sets the bar. The crate's edge is a prebuilt reusable searcher and runtime CPU detection on stable Rust | https://github.com/BurntSushi/memchr , https://docs.rs/crate/memx/0.2.1/source/docs/README.memmem.md |
| `simdutf8` | Up to 23x / 4x (non-ASCII / ASCII) over Rust std `from_utf8`, not over C. Inputs under 64 B go to std | **A**: the Keiser/Lemire algorithm, which C++ simdutf also uses | https://lib.rs/crates/simdutf8 |
| `simd-json` | **Slower** than C++ simdjson. Rough, not same-machine: ~1.1 GB/s vs 2.2-2.5 GB/s on twitter.json. Its README says it "aims to get as close as possible" | **A/L** (tracks an older simdjson) | https://github.com/simd-lite/simd-json |
| `hashbrown` | Find-existing: std+SipHash 23.8 µs, FxHashMap 5.95 µs, hashbrown+Fx 2.9 µs. Roughly 4x from the hasher and 2x from the layout | **L**: SwissTable is Abseil's (C++) design. std has used hashbrown since 2019; what is left of std's cost is SipHash-1-3, kept for HashDoS resistance | https://docs.rs/crate/hashbrown/0.2.0/source/README.md |
| rustls vs OpenSSL | 2019: bulk +5-15 %, full handshakes +10-40 %, resumed +10-70 %, under half the memory. 2024 (vs OpenSSL 3.2): RSA server handshakes 27-30 % *fewer* until AVX-512 RSA reached aws-lc; resumed handshakes +80-330 %; ~13 KiB vs 69 KiB per session | **L**: the crypto is aws-lc/ring assembly derived from BoringSSL/OpenSSL. **A**: smaller session state, and OpenSSL 3.x's own regressions. This is "faster than OpenSSL 3", not "faster than C". Loopback in-memory tests | https://jbp.io/2019/07/01/rustls-vs-openssl-performance.html , https://www.memorysafety.org/blog/rustls-performance/ , https://memorysafety.org/blog/rustls-performance-outperforms/ |
| zlib-rs vs zlib-ng | Feb 2025, "faster than C": decompression +6-10 %, compression ±10 % by level. Part of that came from compile-time SIMD against zlib-ng's runtime detection. The later "current performance" post has zlib-rs 3-20 % slower, executing 37-58 % more instructions (mostly well-predicted bounds checks) | **A/L** ported from zlib-ng; the language is a small net cost | https://trifectatech.org/blog/zlib-rs-is-faster-than-c/ , https://trifectatech.org/blog/current-zlib-rs-performance/ |
| rav1d vs dav1d | **Slower**: c2rust output +3.8 %, up to +11 % during the safety rewrite, back to under 6 %. The assembly (~half the decode time) is shared. A $20k bounty is open for the last ~5 % | **Lang** (a cost): bounds checks (~2 % of the extra 7 % instructions), panic paths raising stack use, zero-initialisation (fixed with `MaybeUninit`) | https://www.memorysafety.org/blog/rav1d-performance-optimization/ , https://www.memorysafety.org/blog/rav1d-perf-bounty/ |
| pgrust | Claims are its own and unreplicated: "hundreds of x" on ClickBench (a columnar layout against Postgres's row store, **A/L**), +30 % on sysbench read-only on a tuned build. Its README says "not performance optimized yet" | unverified | https://github.com/malisper/pgrust/releases/tag/v0.2-release |
| uutils coreutils | No "beats GNU" figure. Issue #13204: GNU `sort` 3.4x faster on 95 MB. The 20-35x `wc` claims are a different project (fcoreutils: SIMD + threads, **A**) | - | https://github.com/uutils/coreutils/issues/13204 |
| fish 4.0 | No benchmark; reviewers say "about the same". The port was for concurrency and maintainability | - | https://fishshell.com/blog/rustport/ |
| Pingora vs NGINX | -70 % CPU and -67 % memory, measured against Cloudflare's old NGINX+**Lua** service. Connection reuse went from 87.1 % to 99.92 %. Cloudflare: "This is not because we run code faster." | **A**: a connection pool shared by all threads (NGINX has one per worker), and Rust replacing Lua. HAProxy already shares idle connections across threads | https://blog.cloudflare.com/how-we-built-pingora-the-proxy-that-connects-cloudflare-to-the-internet/ |
| **Alcyon itself** | QUIC crypto: ring HP+AEAD 3.9k per request against OpenSSL's 15.1k (T544 §2) | **L/A**: ring's assembly, and OpenSSL's `evp_cipher_init_internal` running on every packet. Not the language | T544 |

Tooling status:
- `std::simd` (portable SIMD) is still nightly-only in 2026, and tracking issue #86656 is open
  (https://github.com/rust-lang/rust/issues/86656).
- `wide` gives stable fixed-width vectors, with no runtime dispatch.
- `multiversion` gives function cloning per target feature with runtime selection, like GCC's
  `target_clones` (https://docs.rs/multiversion).

## 2. The techniques, and what each costs

| technique | what it buys | cost in safety and maintenance |
|---|---|---|
| SIMD through crates (`memchr`, `simdutf8`) | Long-haystack search and validation at memory speed, with runtime CPU detection | The crate's internal `unsafe` (std::arch intrinsics). Alcyon already depends on `memchr` (`Cargo.toml:47`). **Short haystacks gain little**: a header line is 20-60 B, and per-line calls pay the setup each time (see §3.4) |
| Our own `std::arch` | The same | `unsafe` of ours: ruled out (AGENTS.md, memory-safety rule) |
| `std::simd` | Portable, safe SIMD | Nightly only: ruled out for a stable build |
| SWAR (`u64::from_ne_bytes` over `chunks_exact(8)`) | 8 bytes per step in safe Rust, e.g. "first non-zero byte", "any byte >= 0x80", "any `\n`". LLVM does not vectorise early-exit loops such as `position()` | None (safe, no dependency). Needs a scalar tail and a test against the byte loop |
| Bounds-check elision | Iterators, `chunks_exact`, slice patterns, one `assert!(i + n <= s.len())` that hoists the checks out of a loop | None. The checks are usually well predicted, so the gain is instructions, not cycles (zlib-rs: +37-58 % instructions, 3-20 % time) |
| `&[u8]` instead of `&str` for wire bytes | No UTF-8 validation, no char-boundary checks on slicing | None. HTTP field bytes are not UTF-8 by contract anyway |
| Less `Vec`/`String`/`Arc` churn | Borrowed slices, reused buffers, `SmallVec`, arenas | Alcyon rule 8: a pool or arena is `alcyon_alloc::Pool`/`Arena`. The request path is already at 0 mallocs on h2 (T544: malloc 0) |
| Lookup tables, `match` on length and first byte | Replaces linear scans (HPACK static table) | None |
| `#[cold]`, `#[inline]`, `#[inline(never)]` on error paths | Keeps hot loops small. `likely`/`unlikely` are still unstable; `#[cold]` on a function is the stable lever | Low. Easy to overdo without a profile |
| Hashers | SipHash-1-3 is ~4x FxHash on small keys. Fx, or our `HandleHasher`, for keys the peer does not choose; a keyed fast hash (foldhash/ahash) or re-keying by index for keys it does | Fx on a peer-chosen key opens HashDoS. foldhash contains `unsafe` internally (13 occurrences in 0.2.0) and is a new dependency |
| `bytes`-style zero-copy | Shared buffers without copies | An atomic refcount per clone/drop: 1.9k per h3 request (T544, hypothesis 7). Not free |
| Enum/struct layout | Niches (`Option<NonZeroU32>`), smaller hot structs (T540) | None |
| LTO fat, `codegen-units=1` | Measured on Alcyon: -9.1 % user cycles, -5.1 % CPU (T433). Already in `release-perf` (`Cargo.toml:110-113`) | ~7 min cold build |
| `panic = "abort"` | Smaller code, no landing pads | **Not available**: T447's per-stream panic containment needs unwinding (`crates/alcyon-rt/src/crash.rs:32-33` refuses to compile with it) |
| `target-cpu` | AVX2 for LLVM's autovectoriser; it is the flag that made zlib-rs look faster than zlib-ng | The binary refuses older CPUs. `memchr` already picks AVX2 at runtime |
| PGO | Alcyon, T435: keep-alive 44,114 -> 38,197 instructions per request (-13.4 %), user cycles -35 %. External: rustc -20 % (Android), rust-analyzer up to -20 % | A training load and a 2x build (`tools/pgo-build.sh`). Not the default |
| BOLT | Alcyon, T435: +1.7 % cycles on top of PGO, only from an instrumented profile, reorder only. `--bolt` in the script fails on mold's PLT | Low gain, fragile |
| Allocator (mimalloc/jemalloc) | Real gains are for allocation-heavy servers | Alcyon's request path does no mallocs on h2 (T544 §2: malloc 0). Not worth a C dependency (mimalloc and jemalloc are C) |

## 3. Alcyon audit

### 3.1 Build settings

- **`release`.** `Cargo.toml:102-103`: `debug = true`, default LTO (thin-local), 16 codegen
  units.
- **`release-perf`.** `Cargo.toml:110-113`: fat LTO with `codegen-units = 1`. This is the
  profile insreq measures.
- **`panic`.** Unwind, deliberately (`crash.rs:32`).
- **`target-cpu`.** None set (`.cargo/config.toml` has only the linker and test threads).
- **PGO.** Available (`tools/pgo-build.sh`, T435) but not used for the default build or the
  board figures.
- **Global allocator.** `crates/alcyon-rt/src/bin/alcyon.rs:24`. It is `AlcyonAllocator`, which is
  glibc `System` plus zero-on-free (`crates/alcyon-alloc/src/zero_on_free.rs:570-576`).

The only open build-level lever is PGO.

### 3.2 Where an h2 request goes (T544 IBS, h2s1, 79,609 instructions per request)

T544's phase rows: HTTP engine and backend h1 35.4k; scheduler, loop, and `engine::*` 17.4k;
mux<->stream bridge 10.5k; h2+HPACK 7.5k; TLS record 3.4k; shared header codec 2.2k.

The per-function figures below are mine, from T544's folded IBS stacks
(`ibs/alcyon-h2.folded`). I dropped the samples on syscall entry, as T544 did (29.2 %), and
scaled the rest to 79,609. They are dispatched ops, not instructions: read each as ±10-20 %.
Figures are inclusive unless marked "self".

| what | per request | where |
|---|---:|---|
| h2 bridge `start_request` | 7.2k | `crates/alcyon-rt/src/h2_bridge.rs:154` |
| of which `H1Parser::parse` of the HTTP/1.1 text the h2 mux just wrote (the re-parse) | **4.7k** | `h2_bridge.rs:208` |
| `H2ReqHead::write` (HPACK fields -> HTTP/1.1 text) | 1.9k | `crates/alcyon-proto/src/mux_h2.rs:213` |
| `send_h1_head` (response HTTP/1.1 text -> `from_utf8_lossy`, `lines`, `split_once`, `trim` -> HPACK) | **3.4k** | `mux_h2.rs:935-955` |
| of which `hpack::find_table_entry`: a linear scan of the 61-entry static table with `eq_ignore_ascii_case`, once per header | **1.9k** | `crates/alcyon-proto/src/hpack.rs:656-669` |
| `apply_http_response_rules`, with **no** response rules configured | 5.7k | engine.rs (`grep -n 'fn apply_http_response_rules'`) |
| of which `HeadFacts::scan` (a further pass over the response head: `is_ascii`, memchr per line, framing fields) | 2.4k | `crates/alcyon-rt/src/txn.rs:1644-1660` |
| of which `check_response_head`, `status_of_line`, `websocket::check_response` (three more passes) | 1.3k | same caller |
| `rewrite_header_names_before` (lowercases names: one more pass, memchr per line) | 0.7k | `crates/alcyon-rt/src/engine.rs:16574-16590` |
| clock reads: vDSO `clock_gettime` (`Engine::step` 4 reads per pass at `engine.rs:5900, 5968, 6053, 6146`, `current_tick` `engine.rs:5548`, `statcnt::now_ms` `statcnt.rs:177-179`, `StreamLog::start`'s `SystemTime::now` `txnlog.rs:160`) | ~2.2k (T544: 37.6 reads at ~50 instructions; IBS ops say 3.8k) | as listed |
| `TcpSession::h2_child_of` (a new session per h2 stream: `new_with_mode` 1.1k, `StreamLog` clone 0.3k) | 2.5k | `crates/alcyon-rt/src/proxy.rs` (`grep -n 'fn h2_child_of'`) |
| `IdlePools::with_count`: `RwLock` read plus a SipHash lookup on `(usize, usize)` per request | 0.7k | `engine.rs:369, 427-431` (also `engine.rs:170, 179`) |
| `Arc<[(String, usize)]>` clone and drop (`capture_write::enter/leave`, `stream_vars_enter`) | 0.7k | `crates/alcyon-sample/src/capture_write.rs`, engine `stream_vars_enter` |
| `TimeStat::add` `fetch_max` (a `lock cmpxchg` loop on a shared counter) and other atomics | 0.35k (all atomics 1.0k) | `crates/alcyon-rt/src/statcnt.rs:34` |
| UTF-8 validation (`from_utf8`, `run_utf8_validation`: `req_htx_init`, `start_request`, `send_h1_head`) | 1.0k | as listed |
| `str` char-boundary checks (`check_range`) in `DecodedFields::iter` | 0.5k | `crates/alcyon-proto/src/hpack.rs:860-861` (`&self.text[n..v]` on a `String`) |
| memmove (head copies between text buffers) | 3.4k | spread; T544 cross-cut 3.5k |
| `memchr` (the crate, AVX2) | 3.0k | spread; mostly per-line calls on 20-60 B lines |

Read together, the table says this:

- **The head is parsed or scanned 8-9 times.** The request goes HPACK -> HTTP/1 text -> H1
  parse -> HTX. The response goes H1 parse -> `find_eoh`, `rewrite_header_names_before`,
  `HeadFacts::scan`, `check_response_head`, `status_of_line`, `websocket::check_response` ->
  `send_h1_head`'s re-split -> HPACK with a linear table search.
- **HAProxy does it once each way.** It parses each head once into HTX and encodes HPACK from
  HTX, with its static-table index known from the header name.
- **The re-parse family costs about 15-18k per request, the largest single item.** That is the
  re-parse, `write`, `send_h1_head`, the response scans, and the name rewrite.

### 3.3 Rust-specific costs, honestly

These exist only because the code is Rust, or because it uses `str` where C would use bytes:

- UTF-8 validation: 1.0k.
- `str` slicing boundary checks: 0.5k.
- Bounds and index checks visible as leaves (`SliceIndex<[Task]>::index` 0.23k,
  `RawVecInner::current_memory` 0.28k): ~0.5k.
- Panic-path code size: not measurable from a profile.

That is about 2-3k per request, or 3 % of h2. It matches rav1d and zlib-rs. Removing it is
mostly a matter of keeping wire data in `&[u8]`, which is safe.

### 3.4 SIMD in Alcyon

`memchr` is already used, with AVX2 picked at runtime (it appears as `find_avx2` in the profile).

**More SIMD is not the lever.** HTTP heads are a few hundred bytes, and Alcyon calls `memchr`
once per line (`engine.rs:16576-16579`, `txn.rs` `scan_plain`). On 20-60 B haystacks the call
and setup cost about as much as the search. The win is fewer passes, not wider ones.

The one clear vector-shaped spot is QUIC: quinn's PADDING run scan,
`self.bytes.iter().position(|&b| b != 0)`. It is on fix/t542 at
`vendor/quinn-proto/src/frame.rs:584` and costs 1.75k per h3 request (T544 hypothesis 17). LLVM
does not vectorise that early-exit loop. A safe SWAR loop over `chunks_exact(8)` cuts it about
8x (estimate). HAProxy pays 1.8k for the same scan, so this is a place to beat it.

### 3.5 Hashers

- **Internal maps on SipHash.** Several maps keyed by internal indices use std `HashMap` with
  SipHash: `engine.rs:170, 179, 369` (`(usize, usize)` server keys). T544's h2 cross-cut puts
  SipHash at 0.6k per request.
- **ConnectionId maps.** The maps keyed by the client-chosen `ConnectionId` are at
  `crates/alcyon-quic/src/table.rs:55`, `crates/alcyon-rt/src/quic_listener.rs:94, 109, 130, 141`,
  and `endpoint.rs:428` `get_handle`. They cost 3.1k per h3 request (T544 hypothesis 9). These
  need a keyed hash, or better, re-keying by `ConnectionHandle` once the packet is routed.
- **Already in the tree.** `alcyon_quic::table::HandleHasher` (`table.rs:27`, our own code, no
  `unsafe`) is the right tool for index keys. `rustc-hash` (Fx, no `unsafe`) is already in
  `Cargo.lock` as a transitive dependency.

## 4. Ranked candidates

The savings are for h2s1 (79.6k) unless marked h3. They are estimates from the profile shares
above, not measurements, so each needs its own insreq A/B (rule 8). The ranges overlap: do not
add them.

### Quick wins (safe Rust, local, no new dependency)

| # | candidate | where | expected saving | sureness | effort | risk | unsafe |
|---|---|---|---|---|---|---|---|
| Q1 | **PGO for the deployed build** (the script exists) | `tools/pgo-build.sh`, `Cargo.toml:110` | -10 to -14 % instructions (8-11k on h2), about -35 % user cycles (T435, keep-alive) | high: measured on Alcyon | low (packaging and CI time) | a stale profile only warns; build time doubles; A/B against a non-PGO HAProxy is no longer like for like | no |
| Q2 | One clock read per loop pass: pass `pass_start` down; `current_tick`, `statcnt::now_ms`, and the QUIC `Instant::now`s read a per-pass cell (`txnlog::loop_now` already exists, `txnlog.rs:152`) | `engine.rs:5548, 5900, 5968, 6053, 6146`; `statcnt.rs:177`; `txnlog.rs:160` | 1.2-2.0k (from 37.6 reads to ~7) | medium-high (call count measured, T544 §3) | low | timer semantics (a deadline computed from a stale `now`); HAProxy does the same thing (`now_ms` per loop) | no |
| Q3 | HPACK static-table lookup by `match` on length and first byte (or a sorted name table with a binary search), as `qpack::static_ref` does since T539 | `hpack.rs:656-669`, `hpack.rs:693` | 1.4-1.8k | high (1.9k measured; the linear scan is 61 `eq_ignore_ascii_case` per header) | low | low: one exhaustive test against the scan, as `h3_mux::the_static_encoder_finds_what_a_scan_of_the_table_finds` | no |
| Q4 | Wire bytes as `&[u8]`: `DecodedFields::text` as bytes (no `check_range`), no `from_utf8_lossy` in `send_h1_head`, no `from_utf8` in `req_htx_init`/`start_request` | `hpack.rs:860-861`, `mux_h2.rs:942`, `h2_bridge.rs`, engine `req_htx_init` (`engine.rs:15428`) | 1.0-1.5k | medium | medium (API churn through `&str` users) | low | no |
| Q5 | Internal-key maps off SipHash and off the `RwLock`: servers by dense index into a `Vec` (or `HandleHasher`) | `engine.rs:170, 179, 369, 427-431` | 0.5-0.9k | medium | low | low; the keys are not peer-chosen | no |
| Q6 | Request-path refcount and atomic churn: borrow the `Arc<[(String, usize)]>` instead of clone/drop per stream; `TimeStat::add` does `load` and stores only when greater instead of `fetch_max` | `alcyon-sample` `capture_write`, engine `stream_vars_enter`; `statcnt.rs:34` | 0.5-1.0k | medium | low | `fetch_max` semantics under races (a lost max between threads; the counter is advisory) | no |
| Q7 (h3) | SWAR PADDING scan in the vendored quinn | fix/t542 `vendor/quinn-proto/src/frame.rs:584` | 1.3-1.5k per h3 request | high (1.75k measured) | low | low; a test on run lengths 0-1500 | no |
| Q8 (h3) | Drop `getsockname` per h3 request: take `bc_src` from the idle connection that is reused | `proxy.rs:1733` | one syscall (~0.3-0.5k user plus kernel) | high | low | `%bi/%bp` must stay right | no |

### Structural (the gap itself)

| # | candidate | where | expected saving | sureness | effort | risk | unsafe |
|---|---|---|---|---|---|---|---|
| S1 | **Parse once.** The h2 (and h3) mux goes frames -> HTX without HTTP/1.1 text. The response goes HTX -> HPACK with the static index carried from the parse. The facts that `HeadFacts::scan`, `check_response_head`, `status_of_line`, and `websocket::check_response` re-derive are taken from that parse | `mux_h2.rs:99-135, 213, 935`; `h2_bridge.rs:154-208, 448`; `txn.rs:1644`; engine `apply_http_response_rules` | **8-13k on h2** (of the ~15-18k this family costs today; HTX building and HPACK coding stay); similar on h3 | medium (the shares are measured; the residual cost of a direct path is an estimate, using HAProxy's h2+HTX figures) | large (the M2 direction, T536 relay->mux) | high: behaviour parity of every rewrite that now works on text; needs the full h2/h3 battery | no |
| S2 | A cheaper h2/h3 child stream: a stream object per request rather than a new `TcpSession` per stream (`new_with_mode`, `StreamLog` clone, `VarStore` set-up) | `proxy.rs` `h2_child_of`/`h2_child_done`; engine `spawn_h2_children` | 2-4k | low-medium | medium-large | session-level state (logs, counters, stick keys) that children now copy | no |
| S3 | The scheduler and loop row: 17.4k on h2 against HAProxy's 2.3k (T544 §2, by first matching frame, so the split with the engine is soft). `Engine::step` self 2.6k and `run_loop` 1.3k for 7.15 passes per request; `account_stream` 1.3k; `end_stream` 0.8k | `engine.rs:5863`, `engine.rs:6668`, `engine.rs:3304` | unknown, plausibly 3-8k | low: needs its own profile slice | medium | low-medium | no |
| S4 (h3) | quinn's per-datagram pass and `poll_transmit` sweeps (8.25 `send_batch` per request), timer re-keying, ConnectionId SipHash (re-key by handle) | T544 §6 items 2-3 | 5-10k per h3 request | medium (T544) | medium-large | medium (vendored quinn diverges) | no |

### Not recommended

- **Our own SIMD**: `unsafe`, and the haystacks are short.
- **`std::simd`**: nightly.
- **`target-cpu=native` or `x86-64-v3`**: little to win in branchy header code (memchr already
  dispatches at runtime), and the binary would refuse older hosts.
- **`panic=abort`**: refused by T447.
- **mimalloc/jemalloc**: C, and there are no request-path mallocs to speed up.
- **BOLT**: +1.7 % at best on this host (T435), and broken with mold.

## 5. Decisions for the user

1. **PGO (Q1).** Should the shipped `release-perf` binary be PGO-built, and should the board
   report PGO figures as well? Alcyon's rule is fair A/B against HAProxy, and HAProxy is built
   without PGO. One option is to report both, with the non-PGO figure as the comparison.
2. **A keyed fast hasher for peer-chosen keys (h3 ConnectionId maps).** foldhash or ahash would
   be a new dependency with internal `unsafe`. The safe alternative is to re-key the maps by
   `ConnectionHandle` after routing, which needs only our own code and is preferred.
3. **S1 (parse once)** is a design commitment that overlaps the M2 h3-into-engine plan
   (`docs/design/h3-engine-2026-10-26.md`). It is the only item large enough to move the ratio
   by itself.

Q2-Q8 need no decision: they are safe, local, and testable.

## 6. What it would take to reach 1.1x HAProxy on h2

HAProxy is at 53.4k, so 1.1x is 58.8k. That is -20.8k (-26 %) from 79.6k.

- **Quick wins.** Q2-Q6 together: ~5-7k, giving ~73k (1.37x).
- **Parse once.** S1 adds 8-13k, giving ~61-65k (1.14-1.22x).
- **PGO.** -10 to -14 % on top of that gives ~53-58k, which is at or under 1.1x. That comparison
  is a PGO Alcyon against a non-PGO HAProxy.
- **Without PGO, at like-for-like builds.** 1.1x also needs S2 and S3: 5-10k out of the
  per-stream session and the loop. The rows add up to it, but S3 is the least certain.

**Conclusion.** No language trick closes this gap. 1.1x is reached by doing the work once
instead of several times (S1) and touching the clock and the shared counters less (Q2, Q6). The
Rust-specific share of the cost (~3 %) is the smallest lever on the list.
