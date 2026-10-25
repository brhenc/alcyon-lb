# ring-ibex: zeroizing key material

Fork of ring 0.17.14 (crates.io, pregenerated asm), branch `zeroize`. Feature `zeroize`
(off by default, pulls in the `zeroize` crate, pure Rust, volatile writes) wipes secrets.
Base commit 6f002bb; 4f02ff8 restores upstream test vectors the crates.io package omits
(without them `cargo test` does not compile; taken from upstream commit 2723abbca "0.17.14.").

## 1. Inventory

R = secret lives in Rust-owned memory; C = in C/asm-owned or asm-written memory (Rust still
owns the struct, asm reads/writes it). "Status": DONE = patched, TODO = not yet. ring has no
memset_s / OPENSSL_cleanse equivalent, so every wipe is a Rust-side `Zeroize` of the
Rust-owned bytes (C/asm functions only write into Rust-owned buffers; they keep no state).
File:line are in the unmodified 0.17.14 tree (line shifts a few after the patch).

| # | Holder | file:line | Mem | Wipe | Status |
|---|--------|-----------|-----|------|--------|
| 1 | `ec::Seed` (X25519/P-256/P-384 ephemeral private key, also ECDSA/Ed25519 seed) | src/ec/keys.rs:26 | R, [u8;48] inline | `Drop` zeroizes bytes | DONE |
| 2 | `EphemeralPrivateKey` | src/agreement.rs:93 | R (holds Seed) | via #1 | DONE |
| 3 | shared secret buffer in `agree_ephemeral_` | src/agreement.rs:~293 | R, stack [u8;48] | guard wipes the used slice on all paths | DONE |
| 4 | `MaskedScalar` (X25519 clamped private scalar, 2 copies: ecdh + public_from_private) | src/ec/curve25519/scalar.rs:58 | R stack, passed by ref to asm | `Drop` | DONE |
| 5 | P-256/P-384 private `Scalar` (`Elem<N,_>`, Copy, limbs array) in `ecdh` | src/ec/suite_b/ecdh.rs:~125, ops/elem.rs:47 | R stack | `wipe()` after point_mul; copies the compiler made are not reachable | DONE (best effort) |
| 6 | ECDH product `Point` (determines shared secret) | src/ec/suite_b/ops.rs:54 | R stack, written by asm | `wipe()` after use | DONE |
| 7 | `big_endian_affine_from_jacobian` temporaries (Elem x/y of the secret point) | src/ec/suite_b/ecdh.rs / ops.rs | R stack | not wiped | TODO (x coordinate = shared secret) |
| 8 | `Seed` copies in `KeyPair`, `generate` return, `from_bytes` | src/ec/keys.rs:5,41-60 | R stack moves | Drop wipes the final owner only; moved-from stack slots remain | accepted limit |
| 9 | AES key schedule `aes::hw::Key` (AES-NI/ARMv8 round keys, `AES_KEY`) | src/aead/aes/hw.rs:40 | R struct, filled by asm | Drop zeroize | DONE |
| 10 | `aes::fallback::Key` / vpaes `Key` | src/aead/aes/fallback.rs:19, vp.rs | R struct | Drop zeroize | DONE |
| 11 | GHASH key tables (H, Htable): clmul, clmulavxmovbe, vclmulavx2, neon, fallback | src/aead/gcm/*.rs (clmul.rs:34, clmulavxmovbe.rs:21, vclmulavx2.rs:25, neon.rs:26, fallback.rs:29) | R struct | derived from key, not the key itself but H=E_K(0); wipe for completeness | DONE |
| 12 | `aes_gcm::Key(DynKey)` and `Combo` | src/aead/aes_gcm.rs:41,502 | R | contains 9+11; wiping those suffices | DONE (via 9, 11) |
| 13 | `chacha::Key` (32 bytes, `[u32;8]`) | src/aead/chacha.rs:41 | R | Drop zeroize | DONE |
| 14 | `aead::UnboundKey` / `LessSafeKey` / `SealingKey` / `OpeningKey` | src/aead/unbound_key.rs:28, less_safe_key.rs:24 | R wrappers | via 9-13 | DONE (via 9-13) |
| 15 | `poly1305::Key` (one-time key r,s, derived per record from ChaCha block 0) | src/aead/poly1305.rs:26 | R stack | Drop zeroize | DONE |
| 16 | `HeaderProtectionKey` (QUIC) | src/aead/quic.rs:25 | R | via 9/13 | DONE (via 9/13) |
| 17 | `hmac::Key` (inner/outer digest contexts holding the keyed block state) | src/hmac.rs:155 | R, two `digest::BlockContext` | Drop zeroize both contexts | DONE |
| 18 | `hmac::Context` (running keyed state) | src/hmac.rs:304 | R | Drop | DONE (via 21) |
| 19 | `hkdf::Salt` / `Prk` (wrap hmac::Key) | src/hkdf.rs:56,109 | R | via 17 | DONE (via 17) |
| 20 | `hkdf::Okm` + `fill` output (caller-owned; rustls zeroizes its own) | src/hkdf.rs:161 | R | caller | n/a |
| 21 | `digest::Context` / `BlockContext` / `Output` (used under HMAC with key-derived blocks) | src/digest.rs:39,187,510 | R | Drop on Context; hmac pad blocks on stack too | DONE (DynState; see notes) |
| 22 | `Ed25519KeyPair` (seed + expanded scalar) | src/ec/curve25519/ed25519/signing.rs:26 | R | Drop zeroize (`Scalar`, `[u8;32]`) | DONE (scalar + prefix; the SHA-512 `Digest` of the seed on the stack is not wiped) |
| 23 | `EcdsaKeyPair` (holds `ec::KeyPair`, i.e. Seed #1) | src/ec/suite_b/ecdsa/signing.rs:61 | R | via #1 once Seed drop covers KeyPair (done); per-signature nonce `NonceRandomKey` signing.rs:346 and ECDSA nonce scalar are TODO | partial: seed wiped; ECDSA nonce and per-signature temporaries TODO |
| 24 | `rsa::KeyPair` (n,e public; p,q,dP,dQ,qInv and `d`-free CRT) as `PrivatePrime`/`PrivateCrtPrime` | src/rsa/keypair.rs:35,410,450 | R heap `BoxedLimbs` | Drop on `BoxedLimbs` (src/arithmetic/bigint/boxed_limbs.rs:27, shared with public values; cheap) | DONE (primes, dP/dQ via BoxedLimbs/PrivateExponent Drop; qInv, `One`, Elem temporaries too) |
| 25 | RSA signing temporaries (bigint `Elem`, `Storage`, blinding) | src/arithmetic/bigint.rs:68,83 | R heap | via 24 | DONE (Elem/Storage own BoxedLimbs; temporaries are wiped when freed) |
| 26 | pkcs8 parse buffers (`Document`) | src/pkcs8.rs | R | caller-owned PKCS#8 bytes; rustls/Ibex owns | n/a |

Count: 26 holders listed, 22 in Rust-owned memory, 0 in memory owned by C/asm (asm only reads and
writes Rust buffers: AES_KEY, Htable, Point, EncodedPoint); 4 are caller-owned. Wiping from Rust
therefore reaches all of them. What cannot be reached: stack slots left by moves (`Seed` by value
into `agree_ephemeral`, return-value copies), registers (xmm spills), and asm internal
stack temporaries. For TLS the ones that matter most: shared secret (3), key schedules (9,10,13),
HMAC/HKDF states (17-19), RSA primes (24). rustls zeroizes its own traffic secrets.

Existing tests: for #5 and the x25519 masked scalar the stack probe test was **not** red before
the patch (needle not found with or without the fix), so those two tests are not evidence; they are
kept as regression checks. The Seed drop and the three shared-secret tests were red.

Notes on 9-21 (session 2): the Drop impls sit on the leaf types that own key-derived bytes:
`digest::DynState` (SHA chaining value, so every `BlockContext`, `digest::Context`, `hmac::Key`,
`hmac::Context`, `hkdf::Salt/Prk` is covered by composition), `aes::ffi::AES_KEY` (hw, vp, fallback,
bsaes keys), `gcm::ffi::HTable` and `KeyValue`, `gcm::fallback::Key`, `chacha::Key`,
`poly1305::Key`. `aes_gcm::Key`/`Combo`, `LessSafeKey`, `UnboundKey`, `SealingKey`/`OpeningKey`,
`HeaderProtectionKey` own no key bytes themselves. Copy types cannot have Drop: `U128`
(inside `HTable`, covered by HTable's Drop; it gets a local `Zeroize` impl), `digest::Output` and
`Digest`/`hmac::Tag` (public hash outputs; but the HKDF-extract result before it becomes the `Prk`
key, and `hmac::try_new`'s `key_hash`, live in such values on the stack and are NOT wiped). The
digest `pending` buffer of `digest::Context` holds message bytes, not key bytes, and is not wiped.
Stack temporaries wiped explicitly: `hmac` padded key (ipad/opad block) and `construct`'s key buffer,
`UnboundKey::from(Okm)` key buffer, ChaCha20-Poly1305's derived Poly1305 key block. By-value
moves of `[u8; 32]` keys into `chacha::Key::new` / `poly1305::Key::new` leave stack copies (accepted
limit, like #8). `Context` of AES-GCM/Poly1305 per-record state (running hash, no key) is untouched.

## 2. What is patched (feature `zeroize`)

- `Cargo.toml`: feature `zeroize = ["dep:zeroize"]`, optional dep `zeroize` 1.5, no default features.
- `src/ec/keys.rs`: `impl Drop for Seed`.
- `src/agreement.rs`: `WipeOnDrop` guard around the shared-secret slice in `agree_ephemeral_`.
- `src/ec/curve25519/scalar.rs`: `Drop for MaskedScalar` (+ `From<MaskedScalar>` no longer destructures).
- `src/ec/suite_b/ops/elem.rs`, `ops.rs`, `ecdh.rs`: `wipe()` on Elem and Point; called in `ecdh`.
- Tests: `src/agreement/zeroize_tests.rs` (cfg feature zeroize), declared at end of `src/agreement.rs`.
- `src/digest/dynstate.rs`: `Drop for DynState`; `src/aead/aes/ffi.rs`: `Drop for AES_KEY`;
  `src/aead/gcm/ffi.rs`: `Drop` for `HTable`, `KeyValue`, `Zeroize for U128`; `src/aead/gcm/fallback.rs`,
  `src/aead/chacha.rs`, `src/aead/poly1305.rs`: `Drop for Key`; explicit stack wipes in `src/hmac.rs`,
  `src/aead/unbound_key.rs`, `src/aead/chacha20_poly1305/mod.rs`. All `#[cfg(feature = "zeroize")]`: with the
  feature off these files compile to the upstream code (only cfg(test) hooks differ).
- Tests: `src/aead/zeroize_tests.rs`, `src/hmac/zeroize_tests.rs`, `src/hkdf/zeroize_tests.rs`, helper
  `src/zeroize_testutil.rs` (heap-box a value, snapshot its bytes, `drop_in_place`, snapshot with volatile
  reads; needle = the key bytes, or the digest state via the cfg(test) hook `state_bytes_for_test`, or
  "whole struct all zero"). All 17 new tests (12 AEAD, 3 HMAC, 2 HKDF) were red before the patch with
  "survived drop"; the needle tests first assert the needle is present before the drop, so none was vacuous.
  Green after. AES-NI/clmul tests return early if the CPU lacks the feature; vp and fallback schedules are
  checked as "whole struct zero".

### Vector registers (Ibex T462)

`src/vregs.rs`: `clear()` zeroes the vector registers: `vzeroall` when ring's CPU detection reports AVX
(`cpu::intel::Avx`, the same `GetFeature` check ring's AVX code uses), else `pxor` on xmm0-15; on AArch64
`eor` on v0-v31; 32-bit x86 `pxor` on xmm0-7. With the feature off, `clear_if_zeroize` is empty. It runs once
at the end of each public operation that ran assembly with key material in registers, not after every
assembly call inside it (ring's Rust code runs in between, and only the last call's registers remain):

- AEAD: `Algorithm::new_key` (AES key setup, GHASH table init, ChaCha20 key), `Algorithm::seal`,
  `Algorithm::open_within` (`src/aead/algorithm.rs`; every AES-GCM and ChaCha20-Poly1305 seal and open
  goes through these), QUIC `HeaderProtectionKey::new_mask`.
- Key agreement: `EphemeralPrivateKey::generate` and `compute_public_key`, `agree_ephemeral_` after the
  scalar multiplication and again after the caller's KDF (rustls runs HKDF-extract on the secret there).
- Signatures: `EcdsaKeyPair::sign`, `Ed25519KeyPair::sign`, `RsaKeyPair::sign` (guard `ClearOnDrop`, all
  exit paths). HMAC: `Key::sign` and `Context::try_sign` (SHA-NI/AVX2 state is key-derived under HMAC).

Cost per record: one load of ring's feature word, one test and branch, one `vzeroall`: about 5
instructions per seal or open (measured from Ibex, `tradeoff.md` 6.27). So it stays per record.

What the test found: BoringSSL's AES-NI assembly already clears the round keys it loaded
(`aes_hw_ctr32_encrypt_blocks` ends with a register-bank clear, and the tag is computed with it), so after
a seal no round key was in xmm0-15 even without the patch. The GHASH code does not clear: xmm6 and xmm7
held two entries of the H-power table (key-derived: whoever has H can forge tags). Test
`aead::zeroize_tests::seal_leaves_no_aes_or_ghash_key_in_the_xmm_registers` (x86_64): seals 576 bytes with
AES-128-GCM and reads xmm0-15 with `asm!` immediately after; the needles are the 11 round keys, H, and
the 16-byte entries of the `clmulavxmovbe` table built from the same key. Red with `clear_if_zeroize`
emptied (`[(6, 12), (7, 14)]`: xmm6 = table entry 12, xmm7 = entry 14), green with it.

Not cleared: general-purpose registers. They are overwritten within a few instructions of the return
(the caller's code reuses them at once), and the assembly keeps addresses and counters there in its loops,
key words only transiently (ChaCha20's scalar path, the bignum code). AVX-512 registers zmm16-31 and the
upper halves of zmm0-15: ring 0.17.14 has no AVX-512 code. The kernel's saved copy of the registers on a
context switch is not reachable from user space.

### Stack (Ibex T462)

Stack copies (inventory 7 and 8, the moved-from `Seed` and `[u8; 32]` keys, `digest::Output`/`hmac::Tag`
values including the HKDF-extract result, asm spill slots) are not wiped by ring. Ibex scrubs the stack
below its TLS layer after each handshake step (`ibex_alloc::scrub_stack`, Ibex `tradeoff.md` 6.27), which
covers every frame ring and rustls used during the handshake. Per-record operations are not followed by
a scrub; their keys live in the structs wiped on drop.

## Renaming for side-by-side linking (DONE): package and lib `ringibex`
`Cargo.toml`: `name = "ringibex"`, `links = "ringibex_core_0_17_14_"`, `[lib] name = "ringibex"` (chosen so
the crate name cannot clash with vanilla `ring` even without `package =` renames; tests and doc comments use
`ringibex::`). build.rs and `src/prefixed.rs` derive the prefix from `CARGO_PKG_NAME`, so they needed no
edit. The headers in `pregenerated/ring_core_generated/` still say `ring_core_0_17_14_` but are not used:
build.rs regenerates `prefix_symbols*.h` into OUT_DIR with the new prefix (verified by `nm`). Debug strings
such as "ring::error::Unspecified" are unchanged on purpose (upstream tests compare them).
Proof, scratch crate `/tmp/ring-both` (not in the repo; `ring = "=0.17.14"` plus `ringibex` by path with
`zeroize`): both X25519 agreements succeed in one binary; `nm` shows 118 `ring_core_0_17_14_*` and 118
`ringibex_core_0_17_14_*` defined symbols and no symbol defined twice.

## `rustls-ringibex/` (DONE)
Fork of `rustls-ring` 0.24.0-dev.2 (what Ibex uses). Own package (its Cargo.toml has `[workspace]`; it is not a
member of ring's), dependency `ring = { package = "ringibex", path = "..", features = ["zeroize"] }`, so the
source still says `ring::` and is unchanged except the `include_bytes!` test-key paths (crates.io `rustls`
does not ship `src/testdata`; the same keys are copied from rustls-pki-types into `testdata/`). Lib name
`rustls_ringibex`; `rustls_ringibex::DEFAULT_PROVIDER` replaces `rustls_ring::DEFAULT_PROVIDER`. Its own
tests pass (30). In /tmp/ring-both an in-memory TLS 1.3 handshake (rustls 0.24.0-dev.2 sans-io API, rcgen
ECDSA P-256 self-signed cert) completes with the ringibex provider and again with vanilla rustls-ring in the
same binary (TLS13_AES_128_GCM_SHA256 both). `cargo tree -i ringibex` shows rustls-ringibex uses ringibex.

## Upstream position
ring#15 was closed "not planned" in Feb 2025. Brian Smith wrote (2022) that wiping in destructors "has
limited value" and that an allocator that zeroizes on deallocation (as BoringSSL does in FIPS mode) would be
better. Ibex plans that separately (Ibex task T459). Nothing is posted upstream.

## Upstream

Existing discussion (fetched 2026-10-24, read only; nothing posted): https://github.com/briansmith/ring/issues/15 ("Decide what zeroization, if any, we should do", opened by briansmith, closed Feb 25, 2025, 5 comments) and https://github.com/briansmith/ring/issues/2005 ("Consider using zeroize crate for key materials", duplicate, closed May 18, 2024). Maintainer shown: briansmith (owner of the repo). Read #15's closing comment before filing; `agreement.rs`
itself says the NSA "zeroize" requirement is not met. Draft issue text for the user to decide on:

> Title: Optional zeroization of key material (agreement, AEAD keys, HMAC, RSA)
> `agree_ephemeral` and `EphemeralPrivateKey` document that they do not "zeroize" per the NSA
> guide. Long-lived TLS servers keep session secrets in freed memory. Would you accept a PR
> adding an off-by-default `zeroize` feature (the `zeroize` crate, volatile writes, `Drop` on
> `ec::Seed`, `MaskedScalar`, key schedules, hmac::Key, bigint limbs)? Cost is one memset per key,
> nothing per record. Happy to keep the patch minimal and in ring's style.

## Progress

Done: inventory; key exchange (1-6); HMAC/HKDF/digest state (17-19, 21); AEAD key schedules (9-16);
rename to `ringibex`; `rustls-ringibex`; side-by-side proof. Counts: `cargo test` 183 passed, `cargo test
--features zeroize` 211 passed (1 ignored in both).
Also done (session 2, after the rename): Ed25519KeyPair Drop (22), RSA BoxedLimbs and PrivateExponent Drop
(24, 25). RSA tests observe heap memory with a test-only global allocator (`zeroize_testutil::spy`, active
under `cfg(test, feature = "zeroize")`) that scans each block just before it is freed; control test
`spy_sees_an_unwiped_block`. Red before (3 tests: p, q, dP), green after. Counts now: `cargo test` 183, with
`--features zeroize` 211.
Next: (c) 7 elem temporaries in big_endian_affine_from_jacobian; (d') ECDSA nonce (23) and the RSA signing
stack temporaries; the by-value copies listed in the notes under the inventory.
Open questions: whether to wipe moved-from stack (needs a stack-sweep call at the end of
`agree_ephemeral`, e.g. a function that writes N KiB of zeros below the frame; not done); whether
`Okm`/hkdf output buffers should be wiped (caller-owned). Step 5 (cost): ring has no benches
(`ls benches` absent); skipped; the cost is one memset of <=48 bytes per handshake plus Drop.
Step 4 (wiring) was changed by the coordinator: no `[patch]`; Ibex worktree untouched.

## Commands

    cd /home/bhenc/ring-ibex
    export CARGO_TARGET_DIR=/home/bhenc/ibex-targets/ring-ibex CARGO_INCREMENTAL=0
    cargo test                              # baseline, 183 passed
    cargo test --features zeroize           # 211 passed
    cargo test --lib --features zeroize zeroize_tests
    cd rustls-ringibex && cargo test        # 30 passed
    # side by side: /tmp/ring-both (scratch, recreate: deps ring =0.17.14, ringibex path+zeroize,
    # rustls =0.24.0-dev.2, rustls-ring =0.24.0-dev.2, rustls-ringibex path, rcgen 0.13); cargo run; nm target/debug/ring-both
