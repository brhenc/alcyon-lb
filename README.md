# Ibex: High-Performance Soft-Realtime Reverse Proxy & Load Balancer

**Ibex** is a memory-safe, soft-realtime reverse proxy and load balancer written in pure Rust with Pingora integration. Designed to meet modern CISA memory-safety directives and aerospace-grade soft-realtime reliability (NASA JPL Power of 10), Ibex provides seamless migration from HAProxy via configuration compatibility, stick-table synchronization (Peers protocol), and support for HAProxy's `vtest` regression framework.

---

## Key Highlights

- **CISA Memory-Safety & Pure Rust Core**: Zero memory-corruption vulnerabilities, eliminating use-after-free and buffer overflows.
- **NASA JPL Power of 10 Soft-Realtime Safety**:
  - Pre-allocated static arenas and fixed object pools (**Rule 3: Zero heap allocation after initialization**).
  - Statically bounded execution loops with upper limits (**Rule 2**).
  - High assertion density with invariant tracking (**Rule 5**).
  - Small modular functions with zero unhandled panics (**Rule 4, 7, 10**).
- **Aerospace MC/DC Quality Assurance**:
  - LLVM source-based code coverage instrumented for DO-178C Level A Modified Condition / Decision Coverage tracking.
- **HAProxy Configuration & Migration Compatibility**:
  - Drop-in parser for `haproxy.cfg` (`global`, `defaults`, `frontend`, `backend`, `listen`, `peers`, `acl`, `use_backend`, `bind`).
- **Elastic Binary Trees (`ebtree`)**:
  - Safe, deterministic $O(k)$ bit-indexed radix search trees (`eb32`, `eb64`, `ebst`, `ebmb`) for IP prefixes, URIs, and binary tokens.
- **Stick Tables & HAProxy Peers Protocol (v2 / v2.1)**:
  - Wire-compatible binary synchronization protocol allowing mixed clusters of HAProxy and Ibex instances.
  - Sliding-window frequency and connection rate limiters.
- **Runtime-Swappable Dual HTTP Parsers**:
  - Pure Rust rewrite of HAProxy's **HTX** (HTTP Transfer eXchange) intermediate representation.
  - Pingora HTTP parser adapter.
  - **Dynamic runtime switching** between HTX and Pingora parser engines on the fly per request/stream.
- **Modern I/O & Concurrency**:
  - Lock-free Read-Copy-Update (RCU) routing tables (`arc-swap`) for hitless configuration reloading without worker thread lock contention.
  - SIMD-accelerated tokenization and delimiter scanning (SSE4.2 / AVX2 / NEON).
  - Multi-TLS provider abstraction (Rustls default, OpenSSL/BoringSSL).

---

## Workspace Structure

```
project-ibex/
├── Cargo.toml
├── ARCHITECTURE.md
├── crates/
│   ├── ibex-core/          # Soft-realtime primitives, JPL rules, arenas, fixed pools
│   ├── ibex-ebtree/        # Elastic Binary Trees (eb32, eb64, ebst, ebmb)
│   ├── ibex-stick-table/   # Stick table storage, rates, connection counters
│   ├── ibex-peers/         # HAProxy Peers Protocol v2 binary synchronization
│   ├── ibex-parser/        # Dual HTTP Parsers (HTX + Pingora) & SIMD scanner
│   ├── ibex-tls/           # Multi-TLS engine provider (Rustls / OpenSSL)
│   ├── ibex-config/        # HAProxy syntax parser, AST, ACL evaluation engine
│   ├── ibex-vtest/         # HAProxy vtest / VTC regression test runner
│   ├── ibex-runtime/       # Pingora runtime, RCU dynamic table, proxy engine
│   └── ibex-lb/            # Daemon executable & CLI
├── examples/
│   ├── haproxy.cfg         # Sample HAProxy-compatible configuration
│   └── regression.vtc      # Sample VTC regression test case
└── scripts/
    └── coverage_mcdc.sh    # MC/DC & LLVM coverage verification script
```

---

## Quick Start

### 1. Build and Check Syntax
```bash
cargo build --workspace
cargo run --bin ibex -- -f examples/haproxy.cfg -c
```

### 2. Run Test Suite
```bash
cargo test --workspace
```

### 3. Execute VTC Regression Test
```bash
cargo run --bin ibex -- -t examples/regression.vtc
```

### 4. MC/DC & Coverage Verification
```bash
./scripts/coverage_mcdc.sh
```
