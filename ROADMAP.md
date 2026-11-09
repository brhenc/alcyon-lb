<!--
SPDX-License-Identifier: GPL-2.0-or-later
Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
-->
# Roadmap

Written 2026-11-09 against `3ea291cb`. What comes next and in what order. It is not a promise
of dates. The previous roadmap (2026-09-23, written before HTX, HTTP/3 and the memory pools)
is in `docs/history/roadmap-2026-09-23.md`.

## Where the project is

- 18 crates: about 161,000 lines of Rust in `src/` and 173,000 lines of tests.
- **Client side:** HTTP/1.1, HTTP/2 and HTTP/3. **To servers:** HTTP/1.1 and HTTP/2. Plus
  `mode tcp`.
- No allocation per request in steady state, measured for every protocol listed above. The
  per-request cost is close to HAProxy's (`performance.md`), except for HTTP/3 and rules on a
  single connection.
- Every change goes through `tools/checkin.sh`. It runs:
  - the test suite;
  - line coverage of every changed line;
  - the HAProxy oracles;
  - differential fuzzing;
  - lint;
  - an instructions-per-request budget.

## 1. Robustness: what can still stop the process

These come first, because the project's question is whether a Rust rewrite is safer in
practice (RUST-FOOTGUNS.md).

- **Panics a client could reach.** `src/` has about 437 `unwrap()` and 675 `expect()` calls.
  A sweep of the request path found none that a client can reach.
  - Measure the rest.
  - Then turn `unwrap_used`, `expect_used` and `indexing_slicing` to `deny` in the data-path
    crates.
- **One lint policy, enforced.** The workspace lint section reaches two crates, and the gate
  passes clippy warnings (2,067 today). Give every crate the workspace policy. Make the safety
  lints errors now, and ratchet the rest down with a per-lint baseline until the gate runs
  `-D warnings`.
- **Allocation failure.** A failed allocation outside the pools still aborts the process,
  where HAProxy fails one stream. The causes are rustls on QUIC and the log forwarder, the
  HPACK / QPACK decoders, and std internals. HAProxy's buffer wait queue is partly built, so
  some streams that HAProxy would queue still fail. One example: a new HTTP/2 stream with no
  buffer gets a 500, where HAProxy pauses the connection until memory frees.
- **QUIC connection IDs** are signed with quinn's default FxHash-based generator, which is not
  a MAC. Replace it with a keyed tag from the crypto provider, one key per worker. Prove it
  first with a forging test.

## 2. Behaviour HAProxy has and Alcyon refuses

All of these are refused when the configuration loads, never accepted and ignored.

- **Slow-client limits:** `maxconnrate`, `maxsessrate`, `rate-limit sessions`,
  `timeout client-fin`. `tcp-request content` rules decide on a partial first segment instead of
  waiting for the inspect delay.
- **Larger subsystems:** `peers`, `cache`, `fcgi-app`, Lua and SPOE. Each is worth doing only
  if a user needs it. Lua and SPOE also bring back C or an embedded interpreter, so they are
  the last.

## 3. Performance

From `performance.md` (2026-11-09, one core). HAProxy was also built with LTO, PGO and clang,
so each comparison is between builds made the same way.

- **HTTP/3:** 29-43% more instructions per request than HAProxy 3.5-dev10, in every pairing of
  builds and with either TLS library. Profile the QUIC path before choosing a change. It is
  quinn-proto, vendored and already patched for allocations.
- **Rules:** 11-16% more user-space instructions than HAProxy, but level in cycles and +2% with
  the kernel counted. Look at what runs per request outside the rules themselves.
- **Plain proxying** is level or ahead in every pairing, and PGO is worth 30-45% of cycles to
  both proxies. Releases should ship the PGO build (`tools/pgo-build.sh`).
- **dpbench** (a server connection per request, 1 and 4 threads): Alcyon 1-5% below HAProxy's
  maximum, same latency. The connect path is the next place to look.
- **Not measured yet:** more than 4 threads against HAProxy's thread groups, and large bodies.

## 4. The research questions

Alcyon is a test of rewriting a large C system in Rust (README). The work that answers that
question, rather than adding features:

- **Parser seam.** `crates/alcyon-proto/src/parser.rs` selects an HTTP/1 parser by name.
  - Write the `pingora` adapter, so Pingora's Rust HTTP parser can be measured against
    Alcyon's own parser and against HAProxy's C parser (`haproxy-ffi`).
  - Then check that compiler changes do not make any of the three slower.
  - Switching parsers while running, per route, is the longer-term goal.
- **MC/DC coverage.** Rust has no stable MC/DC instrumentation, and `scripts/coverage_mcdc.sh`
  does what the toolchain allows. Closing that gap in the compiler is one of the project's
  stated aims.
- **Library gaps found on the way.** Each is a candidate to fix upstream rather than keep
  patched here:
  - ring does not zeroize key material, so there is an opt-in fork, `vendor/ringalcyon`;
  - TCP TLS runs on a pre-release rustls 0.24;
  - quinn-proto is vendored with a padding fix and pooled allocations;
  - std aborts on a failed allocation everywhere except a few `try_` methods
    (`Vec::try_reserve`); fallible collections and a recoverable allocation-error hook are
    still unstable.
- **Record what Rust did better and worse than C.** The project's notes (`tradeoff.md`,
  RUST-FOOTGUNS.md) record this as it is measured. A written summary of the rewrite's cost and
  of what it bought is owed.

## 5. Making the repository usable by others

- **CI on GitHub.** A fresh clone builds and tests without HAProxy (`cargo build`,
  `cargo test`), so a CI job can run that much. The oracle stages need the reference builds
  in `ALCYON_REFERENCE` (README, "Running the oracle tests"). A container image with them would
  let the whole gate run anywhere.
- `tradeoff.md` is a running log, and some of its older entries are out of date. For example,
  section 4.2 still says QUIC is out of scope. Revise it alongside this roadmap.
