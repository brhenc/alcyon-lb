# Vendored crates

Alcyon builds these from the tree, as path dependencies (user, 2026-10-24: "vendor it as part of the
tree. i have no plans to reuse it outside of alcyon"). They keep their own licences (the `LICENSE*`
files in each directory); no Alcyon licence header is added to them. They are excluded from the
Alcyon workspace (`exclude` in the root `Cargo.toml`): `cargo test --workspace` and clippy do not
run or lint them, and they use the root `Cargo.lock`.

## `ringalcyon` and `rustls-ringalcyon` (T460)

The crypto provider of `tune.alcyon.crypto-provider ring-alcyon`: a fork of ring 0.17.14 that wipes
key material when it is freed (feature `zeroize`, which `rustls-ringalcyon` turns on), and its
rustls 0.24 provider, a fork of `rustls-ring` 0.24.0-dev.2. What it wipes and what it cannot:
`ringalcyon/ZEROIZE.md`. Why vanilla ring stays the default: `tradeoff.md` 6.27.

- **Source:** `~/ring-ibex`, branch `zeroize`, commit `b023c4ec9baf5fc6ca8ba14609b1c0e6eb7693fe`
  (branch `zrev-fix` on 741d7a8: the zrev review wipes, see `ringalcyon/ZEROIZE.md`; 741d7a8 was T462, vector
  registers cleared after AEAD, key agreement, signing and HMAC; 237a254 at T460), `git archive` of the tracked files: no `.git`, no `target/`, no `.cargo-ok`.
  `rustls-ringalcyon/` there is `vendor/rustls-ringalcyon/` here.
- **Left out:** ring's `tests/` (1.9 MB of test vectors; Alcyon does not run ring's suite), and the
  two crates' `Cargo.lock`. `ringalcyon/Cargo.toml` still lists the `[[test]]` targets: they are
  only read when ring's own tests are built, which is not done from here.
- **Licences:** `ringalcyon/LICENSE`, `LICENSE-BoringSSL`, `LICENSE-other-bits`,
  `third_party/fiat/LICENSE`, `src/polyfill/once_cell/LICENSE-{APACHE,MIT}` (ring's own).
  `rustls-ringalcyon/LICENSE-{APACHE,ISC,MIT}`: rustls's, copied from the `rustls` 0.24.0-dev.2
  crate (the `rustls-ring` crate package carries none; it is the same project and licence,
  `Apache-2.0 OR ISC OR MIT`).

### Changes made here (not in ~/ring-ibex 237a254; 1 and 3 are in it since 3d454d8 and bc75ed8)

1. `ringalcyon/pregenerated/ring_core_generated/prefix_symbols{.h,_asm.h,_nasm.inc}`: the symbol
   prefix `ring_core_0_17_14_` renamed `ringalcyon_core_0_17_14_`. Without a `.git` directory
   ring's `build.rs` takes these pregenerated headers instead of generating them, and the stale
   prefix left every C and assembly symbol undefined at link time (in `~/ring-ibex` itself, which
   has a `.git`, the headers are generated and the bug does not show). Ported back to ring-alcyon as 3d454d8.
2. `rustls-ringalcyon/Cargo.toml`: `ring = { package = "ringalcyon", path = "../ringalcyon" }` (was
   `".."`), and its `[workspace]` table removed, so that it builds as a dependency of Alcyon's
   workspace rather than as a workspace of its own.
3. `rustls-ringalcyon/src/lib.rs`: the provider's `Ring` value prints as `RingAlcyon` (`Debug`), so a
   `CryptoProvider` tells which of the two crates it comes from (`secure_random`); their
   `DEFAULT_PROVIDER`s are otherwise alike, and a `const` has no address to tell them by. Ported back to ring-alcyon as bc75ed8 (with the licence files); only change 2 is vendor-specific.

### Running ring's own tests

From the fork, not from here (it has the test vectors):

    cd ~/ring-ibex && git checkout zeroize && cargo test --features zeroize

### Updating

`git -C ~/ring-ibex archive <commit> | tar -x -C /tmp/ringalcyon`, drop `tests/` and the
`Cargo.lock`s, copy over `vendor/ringalcyon` and `vendor/rustls-ringalcyon`, apply the three changes
above (or drop the ones the fork now carries), update the commit here, then
`cargo build --offline -p alcyon-tls` and `cargo test -p alcyon-tls --test it crypto_provider::`.

## `quinn-proto` (T542)

The QUIC state machine under `alcyon-quic` (and quinn's rustls 0.23 test clients in the dev-deps of
`alcyon-proto`, `alcyon-quic` and `alcyon-rt`), vendored to patch it (user, 2026-10-31). The root
`Cargo.toml` takes it for the whole graph with `[patch.crates-io] quinn-proto = { path =
"vendor/quinn-proto" }`; the crates keep asking for `quinn-proto = "0.11"` with their own
features (`default-features = false`; the dev-deps add `rustls-ring`).

- **Source:** crates.io `quinn-proto` 0.11.18, the `.crate` package as published
  (sha256 `a9746dbde176634f4f2f1faf2404e30a31b2bc1e9cafb5329c95d8177a18c9fc`, the `Cargo.lock`
  checksum before vendoring; upstream git `eaec0db4bcb698f76df736d89938743c88a2ad5f`, from
  `.cargo_vcs_info.json`). Pure Rust; no C, no build script.
- **Left out:** the package's `Cargo.lock` (the root one is used). Everything else is as
  published, `Cargo.toml` (normalised by cargo) and `Cargo.toml.orig` included.
- **Licences:** `LICENSE-APACHE`, `LICENSE-MIT` (quinn's, `MIT OR Apache-2.0`).

### Changes made here

The first vendor commit is the pristine 0.11.18; each change below is its own commit on top
(`git log -- vendor/quinn-proto`), each a diff that could go upstream as it is. None has.

1. `src/frame.rs`, `Iter::try_next`: a run of PADDING bytes is one `Frame::Padding` (was one
   per byte). RFC 9000 19.1: PADDING has no content, so a run is equivalent. h2load and browsers
   pad each request packet to ~1200 bytes: ~1150 `next()` calls per packet were half of Alcyon's
   h3 per-request instructions (T539). Test: `frame::test::padding_run_is_one_frame`.
2. `src/connection/streams/{state,send,recv,mod}.rs`, `send_buffer.rs`, `range_set/btree_range_set.rs`
   (T543, e0e30bee): a connection reuses its freed stream state. A freed `Send` is reset
   (`Send::free`/`reinit`, `SendBuffer::reinit`, `RangeSet::clear` popping so the `BTreeMap`
   root node stays) and kept on a per-connection `free_send` list; a freed `Recv` is taken from
   `free_recv` at the stream's first use, not when its slot is made available (the list was
   empty for the first ~100 streams). Both lists are bounded by the most streams the connection
   had open at once and are freed with it. 3.9 -> 1.1 allocations per h3 request.
3. `src/connection/send_buffer.rs` `ack` (T543, 875596f0): the segment deque shrinks only above
   16 entries (`RETAINED_SEGMENTS`, 512 bytes) and not below; it was freed whenever the last
   ACK emptied it and allocated again on the next write. 1.1 -> 0.08.
4. `src/connection/{mod,spaces,packet_builder}.rs` (T543, 816391ad): up to 8 emptied
   `Retransmits` boxes per connection (`spare_retransmits`); each packet starts with one, an
   unused one goes back in `finish_and_track`, an acked or lost packet's is emptied and kept.
   0.08 -> 0. Pinned by `crates/alcyon-rt/tests/request_allocations_h3.rs` (GET and POST: 0).
5. `src/frame.rs` `zero_run` (T543, 013efdec): the end of a PADDING run is found 32 bytes a
   step (an OR-fold the compiler vectorises), not with a byte-at-a-time `position`. Test:
   `frame::test::zero_run_finds_the_first_nonzero_byte`.
6. `src/connection/spaces.rs` `Retransmits::is_empty` (T543, ff26c231): the two stream sets'
   lengths are checked before iterating them (an emptied hashbrown set scans every bucket).
   No behaviour change. Items 5 and 6 with Alcyon's `ConnectionId` hash (57b26eff): h3c1
   121.8k -> 113.0k ins/req at 1.5 client datagrams per request (T543 progress, batch 4).
7. P1, feature `alcyon-pools` (off by default; `alcyon-quic` turns it on; upstreamable: no, it links
   `alcyon-alloc`): `Send`, `Recv` and the `Retransmits` records of sent packets come from
   `alcyon_alloc` pools `quic_send`, `quic_recv`, `quic_retransmits` (`show pools`) instead of the
   per-connection spare lists (`streams/{send,recv,state}.rs`, `spaces.rs`, `src/alcyon_pools.rs`).
   A `Retransmits` is taken when the first control frame needs it, no longer one per packet.
   Unconditional, upstreamable: `SendBuffer.acks` is an `ArrayRangeSet` (`ArrayRangeSet::clear`).
   `QP_FEATURES=alcyon-pools tools/quinn-proto-tests.sh` runs the unit tests with the pools.
8. T569 (upstreamable: yes): `src/connection/{stats,mod,ack_frequency,packet_builder}.rs`,
   `ConnectionStats::ack` (`AckStats`, also `Connection::ack_stats`, which copies only it): the
   ack-eliciting 1-RTT packets sent, the 1-RTT packets received with an ACK and nothing
   ack-eliciting, the threshold of the first ACK_FREQUENCY frame the peer acknowledged, and the
   ACK-only packets after it that neither that threshold, the requested `max_ack_delay`, a gap nor
   an IMMEDIATE_ACK explains (`on_ack_received` judges, `process_payload` counts; the judging runs
   only once a frame was acknowledged, so a connection without ACK_FREQUENCY pays two counter
   increments). Test: `crates/alcyon-rt/tests/it/quic_ack_frequency_compliance.rs`
   (quinn-proto's own end-to-end suite is not built here).

### Running quinn-proto's own tests

`tools/quinn-proto-tests.sh [filter]` runs its unit tests (`--lib`, 182 of them) offline, on a
copy in /tmp: `assert_matches` and `hex-literal` (not in the registry cache) are replaced by
local shims, `fastbloom` (feature `bloom`) and the other uncached optional dependencies are
taken out, and `src/tests/` (the end-to-end suite: needs `rcgen` 0.14, not cached) is not
built. With network access, upstream's full suite runs from a quinn checkout.

### Updating to a new release

Extract the new `.crate` (`~/.cargo/registry/cache/*/quinn-proto-<v>.crate`, after a
`cargo fetch` of it) over `vendor/quinn-proto/` in one commit (drop its `Cargo.lock`; update
the sha256 and git sha above), then reapply the changes above one commit each
(`git format-patch` of each change commit, `git am`), dropping those upstream now carries.
Then `cargo build --offline --workspace`, `tools/quinn-proto-tests.sh`, and the alcyon-quic,
alcyon-proto h3 and alcyon-rt h3 tests.
