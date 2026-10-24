# Vendored crates

Ibex builds these from the tree, as path dependencies (user, 2026-10-24: "vendor it as part of the
tree. i have no plans to reuse it outside of ibex"). They keep their own licences (the `LICENSE*`
files in each directory); no Ibex licence header is added to them. They are excluded from the
Ibex workspace (`exclude` in the root `Cargo.toml`): `cargo test --workspace` and clippy do not
run or lint them, and they use the root `Cargo.lock`.

## `ringibex` and `rustls-ringibex` (T460)

The crypto provider of `tune.ibex.crypto-provider ring-ibex`: a fork of ring 0.17.14 that wipes
key material when it is freed (feature `zeroize`, which `rustls-ringibex` turns on), and its
rustls 0.24 provider, a fork of `rustls-ring` 0.24.0-dev.2. What it wipes and what it cannot:
`ringibex/ZEROIZE.md`. Why vanilla ring stays the default: `tradeoff.md` 6.27.

- **Source:** `~/ring-ibex`, branch `zeroize`, commit `237a2547ddfbe612d0f6edad2b37047082a45775`
  (237a254), `git archive` of the tracked files: no `.git`, no `target/`. `rustls-ringibex/` there
  is `vendor/rustls-ringibex/` here.
- **Left out:** ring's `tests/` (1.9 MB of test vectors; Ibex does not run ring's suite), and the
  two crates' `Cargo.lock`. `ringibex/Cargo.toml` still lists the `[[test]]` targets: they are
  only read when ring's own tests are built, which is not done from here.
- **Licences:** `ringibex/LICENSE`, `LICENSE-BoringSSL`, `LICENSE-other-bits`,
  `third_party/fiat/LICENSE`, `src/polyfill/once_cell/LICENSE-{APACHE,MIT}` (ring's own).
  `rustls-ringibex/LICENSE-{APACHE,ISC,MIT}`: rustls's, copied from the `rustls` 0.24.0-dev.2
  crate (the `rustls-ring` crate package carries none; it is the same project and licence,
  `Apache-2.0 OR ISC OR MIT`).

### Changes made here (not in ~/ring-ibex 237a254)

1. `ringibex/pregenerated/ring_core_generated/prefix_symbols{.h,_asm.h,_nasm.inc}`: the symbol
   prefix `ring_core_0_17_14_` renamed `ringibex_core_0_17_14_`. Without a `.git` directory
   ring's `build.rs` takes these pregenerated headers instead of generating them, and the stale
   prefix left every C and assembly symbol undefined at link time (in `~/ring-ibex` itself, which
   has a `.git`, the headers are generated and the bug does not show). To report to ring-ibex.
2. `rustls-ringibex/Cargo.toml`: `ring = { package = "ringibex", path = "../ringibex" }` (was
   `".."`), and its `[workspace]` table removed, so that it builds as a dependency of Ibex's
   workspace rather than as a workspace of its own.
3. `rustls-ringibex/src/lib.rs`: the provider's `Ring` value prints as `RingIbex` (`Debug`), so a
   `CryptoProvider` tells which of the two crates it comes from (`secure_random`); their
   `DEFAULT_PROVIDER`s are otherwise alike, and a `const` has no address to tell them by.

### Running ring's own tests

From the fork, not from here (it has the test vectors):

    cd ~/ring-ibex && git checkout zeroize && cargo test --features zeroize

### Updating

`git -C ~/ring-ibex archive <commit> | tar -x -C /tmp/ringibex`, drop `tests/` and the
`Cargo.lock`s, copy over `vendor/ringibex` and `vendor/rustls-ringibex`, apply the three changes
above (or drop the ones the fork now carries), update the commit here, then
`cargo build --offline -p ibex-tls` and `cargo test -p ibex-tls --test it crypto_provider::`.
