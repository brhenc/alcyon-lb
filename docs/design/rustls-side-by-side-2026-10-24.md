# A forked rustls next to upstream rustls: scoping (T460 stage 3, 2026-10-24)

No code. The question (user, 2026-10-24): could Alcyon link two rustls builds, upstream and an Alcyon
fork, and switch between them at run time, for a rustls CVE that hits one and not the other, the
way T460 switches the crypto provider (`set ssl crypto-provider`)?

Short answer: it links, but it is not a provider swap. It needs a second copy of the TLS
connection layer, and it protects only against bugs in the lines where the fork differs from
upstream. A fork that is only renamed shares every upstream bug. The cheaper escape hatches are at
the end.

## 1. What a `rustls-alcyon` fork would change

- **The name, and nothing for the linker.** rustls is pure Rust. Two crates with different names
  (or two versions of one crate) link side by side, because symbol mangling carries the crate's
  identity. Alcyon already does this: `rustls` 0.23 (QUIC, `quinn-proto` 0.11) and `rustls` 0.24
  (`rustls24`, TCP since T440). ring needed `links` and a C symbol prefix (`ringalcyon_core_*`) only
  because of its C and assembly code. rustls has none.
- **Its providers.** A `CryptoProvider` is a type of one rustls. `rustls-ring` and
  `rustls-ringalcyon` implement the traits of `rustls` 0.24. A fork needs its own provider crates
  (`rustls-ring-alcyon` and so on), forked again. That makes 2 x 2 provider builds for the T460
  choice.
- **Its verifier.** Certificate verification is `rustls-webpki`, a separate crate. A CVE in webpki
  is a webpki fork, not a rustls one. `rustls-pki-types` can be shared, since it is plain types.
- **The patch itself.** It only helps where the fork's code differs from upstream (section 4).

## 2. What linking it next to upstream costs

- **Size.** Linking 0.23 and 0.24 together already grew rc3's binary by 12.6% (task figure). A
  third rustls, with its ring provider and webpki unless webpki is shared, adds about one more
  such share. This is an estimate, not a measurement: about +6%, half of the 12.6% that two copies
  added. The ring code itself is shared through the provider. Only the provider glue is copied.
- **Build time.** Each rustls copy is one more large crate to compile, in debug and in release.
  The release `--timings` of T460 (report) give the per-crate time.
- **Upkeep.** 0.24 is a pre-release pinned exactly (`=0.24.0-dev.2`, tradeoff.md 6.22). Each
  upstream release means rebasing the fork and its providers, and porting the duplicated
  connection layer (section 3) to any API change twice.

## 3. What `alcyon-tls/src/conn.rs` and `tcp.rs` would need

The 0.24 types reach into everything below the configuration:

- `conn.rs` (647 lines): `Session` holds `rustls24::NeedsInput<ServerSide>`. `Srv` and `Cli` hold
  `server::Accepted`, `split::SplitConnection<_>` and `VerifyPeerIdentity`. `Traffic<S:
  SideData>` holds `ReceiveTraffic`/`SendTraffic`. Input goes through the `TlsInputBuffer` trait,
  and errors are `rustls24::Error`.
- `tcp.rs`: `ServerConfig`/`ClientConfig`, `CertResolver<Credentials>`, both verifiers, the
  ticket rotator and the session store.
- `alcyon-rt`: `xprt.rs` (`TlsConn` wraps a `TlsCtx`, and `openssl_error` maps `rustls24::Error`
  to OpenSSL's texts), `check.rs` (downcasts `rustls24::Error` for a name mismatch), `srv_tls.rs`.

A provider swap changes a value inside these types. A rustls swap changes the types themselves.
Two ways to do it:

1. **The same source compiled twice.** Move `conn.rs` and `tcp.rs` behind a crate alias:
   `mod up { use rustls24 as r; include!(...) }` and `mod fork { use rustls_alcyon as r; ... }`.
   Then `enum AnyTlsCtx { Up(up::TlsCtx), Fork(fork::TlsCtx) }` dispatches each call in `xprt.rs`,
   with one `match` per call and no allocation. Error mapping and the `check.rs` downcast get one
   arm per copy. This only works while the two APIs stay identical. The first divergence (which
   is what a fork exists for) breaks the shared source.
2. **A trait over the connection.** Write `trait TlsEngine { type Ctx; type ServerCfg; ... }`
   with the operations `TlsConn` uses (accept, connect, handshake step, read plain, write plain,
   pending tx, close notify, `tls_info`), and implement it once per rustls. This is more code,
   but it survives divergence. `TlsConn<E: TlsEngine>`, or an enum over two `TlsConn`s, carries
   it into `xprt.rs`.

Either way the swap itself is T460's mechanism: build every bind's and server's configuration on
the other engine, publish them together, and let new handshakes take the active one.

## 4. Rough size, and why it may not pay

- Fork and rename rustls, fork its provider crates (and webpki if needed): 1 day.
- The connection layer behind option 1: 3 to 4 days. Behind option 2: 5 to 7 days.
- Run the TLS tests of `alcyon-tls` and `alcyon-rt` against both engines, plus a swap test: 2 days.
- Total: about 1.5 to 2.5 weeks, then the upkeep in section 2 for every rustls release.

**The catch.** Linking two copies helps against a CVE only when the vulnerable code is not in the
copy you switch to. A fork that is upstream renamed, plus a few Alcyon patches, shares every other
line, and with them every bug outside the patches. The escape hatch works only for bugs in the
code where the two differ, which is the code Alcyon wrote or changed. That is the code least likely
to get an upstream CVE. Provider diversity (T460) is worth more: ring and ringalcyon share most of
their code too, but the provider is where the constant-time and key-handling code is.

## 5. Alternatives

1. **Patch in place and ship the fix (recommended).** A rustls CVE gets fixed upstream or in a
   vendored patch, followed by a new binary and a seamless reload. Alcyon reloads without dropping
   connections (master-worker, socket handover). A runtime switch avoids a new binary, but the
   fixed side of the switch has to be built in advance, before the CVE is known, so the switch
   cannot carry the fix. The operational cost of a new binary is one reload.
2. **Use the two rustls versions Alcyon already links.** 0.23 and 0.24 really are different code:
   0.24 rewrote the connection API to use caller-owned buffers. Keeping a TCP path on 0.23 alive
   (the pre-T440 `RustlsTransport` in `alcyon-tls/src/transport.rs`, which `alcyon-rt` no longer
   uses) as a fallback engine would give a switch between two codebases that differ in fact, at
   the price of option 2 in section 3 and of the 0.23 path's allocations per record while it
   runs. Worth considering only if a switch without a new binary is a hard requirement.
3. **Narrow the exposure.** `ssl-min-ver`/`ssl-max-ver` (TLS 1.2 or 1.3 only), cipher choices and
   turning off resumption (`no-tls-tickets`) work around many protocol-level CVEs at run time with
   a reload, and no second rustls.
