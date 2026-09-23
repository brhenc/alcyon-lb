# T18: Livepatch Cost Measurement

## 1. Build Commands

Both builds use standard cargo invocations from the repository root:
- **Plain release:** `cargo build --release`
- **Livepatch build:** `cargo build-livepatch`

The livepatch build utilizes a custom alias defined in `.cargo/config.toml` that passes the required `rustflags` array and selects the `[profile.livepatch]` defined in `Cargo.toml`. This preserves single-command builds for both configurations.

## 2. Stage Boundary Symbol Survival

In a plain release build (`cargo build --release`), out of ten selected logical stage boundaries from the data path, only **4** survived as distinct ELF symbols.

The survival list:
1. `ibex_rt::engine::Engine::accept_from_listener` — **SURVIVED**
2. `ibex_rt::engine::Engine::step_stream` — **INLINED**
3. `ibex_rt::proxy::TcpSession::process` — **SURVIVED**
4. `ibex_rt::engine::Engine::run_once` — **INLINED**
5. `ibex_rt::proxy::eval_acl_condition` — **INLINED** (only monomorphizations survived)
6. `ibex_rt::proxy::TcpSession::process_cli_io` — **INLINED**
7. `ibex_rt::proxy::TcpSession::process_srv_io` — **INLINED**
8. `ibex_rt::proxy::TcpSession::validate_request_head` — **INLINED**
9. `ibex_rt::proxy::TcpSession::apply_response_rules` — **INLINED**
10. `ibex_rt::xprt::ClientXprt::recv` — **SURVIVED**

**Conclusion for Pillar 1:** Because 6 of 10 stage boundaries were aggressively inlined and eliminated from the symbol table, Pillar 1's claim is necessary for this codebase. Using `#[inline(never)]` at these strategic points is required to expose them for patching.

## 3. Function Alignment Verification

We read the ELF symbol table and checked 16-byte alignment (`readelf -sW | awk '$4=="FUNC" {print $2}'`) for both builds:

- **Plain release:** 5977 aligned / 6096 total (~98.05% aligned). 119 functions were unaligned.
- **Livepatch:** 3739 aligned / 3742 total (~99.92% aligned). 3 functions unaligned (assembly stubs/entry points).

The livepatch flags (`-align-all-functions=4`) successfully force the remaining functions into 16-byte alignment.

## 4. Cost Table

| metric | release build (spread) | livepatch build (spread) |
|---|---|---|
| steady-state allocations per request | 5.0 (0.0) | 5.0 (0.0) |
| bytes allocated per request | 125.7 (2.6) | 124.0 (0.0) |
| requests/second, one connection, keep-alive | 468 (±2) | 468 (±4) |
| requests/second, 50 concurrent connections | 272 (±18) | 274 (±27) |
| binary size (.text / total) | 4.43 MB / 5.91 MB | 3.79 MB / 4.51 MB |
| build wall time (cold / warm) | 14.31s / 0.07s (±0.2s) | 49.36s / 0.06s (±0.6s) |

## 5. Test Board Regression

- **Release Build:**
  - Reg-test board: 7 passing / 164 failing / 52 out of scope / 89 skipped
  - Workspace tests: 3 targets failed (`canonical_haproxy_35_e2e`, `cli_options`, `h2_flood_knobs`)
- **Livepatch Build:**
  - Reg-test board: 7 passing / 164 failing / 52 out of scope / 89 skipped
  - Workspace tests: 3 targets failed (`canonical_haproxy_35_e2e`, `cli_options`, `h2_flood_knobs`)

## 6. Conclusion

Pillar 1 is entirely justified on this codebase. Aggressive inlining by the Rust compiler destroys 60% of natural proxy stage boundaries in a standard release build, rendering them unpatchable. Enforcing `#[inline(never)]` is required to preserve these boundaries. Next, I would measure the exact performance cost of adding `#[inline(never)]` to these specific boundaries, which is the missing piece of the livepatch cost equation.
