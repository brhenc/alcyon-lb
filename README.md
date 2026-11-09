# Alcyon: High-Performance Soft-Realtime Reverse Proxy & Load Balancer

**Alcyon** is a memory-safe, soft-realtime reverse proxy and load balancer written in pure Rust with Pingora integration. Designed to meet modern CISA memory-safety directives and aerospace-grade soft-realtime reliability (NASA JPL Power of 10), Alcyon provides seamless migration from HAProxy via configuration compatibility, stick-table synchronization (Peers protocol), and support for HAProxy's `vtest` regression framework.

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
  - Wire-compatible binary synchronization protocol allowing mixed clusters of HAProxy and Alcyon instances.
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
│   ├── alcyon-core/          # Soft-realtime primitives, JPL rules, arenas, fixed pools
│   ├── alcyon-ebtree/        # Elastic Binary Trees (eb32, eb64, ebst, ebmb)
│   ├── alcyon-stick-table/   # Stick table storage, rates, connection counters
│   ├── alcyon-peers/         # HAProxy Peers Protocol v2 binary synchronization
│   ├── alcyon-parser/        # Dual HTTP Parsers (HTX + Pingora) & SIMD scanner
│   ├── alcyon-tls/           # Multi-TLS engine provider (Rustls / OpenSSL)
│   ├── alcyon-config/        # HAProxy syntax parser, AST, ACL evaluation engine
│   ├── alcyon-vtest/         # HAProxy vtest / VTC regression test runner
│   ├── alcyon-runtime/       # Pingora runtime, RCU dynamic table, proxy engine
│   └── alcyon-lb/            # Daemon executable & CLI
├── examples/
│   ├── haproxy.cfg         # Sample HAProxy-compatible configuration
│   └── regression.vtc      # Sample VTC regression test case
└── scripts/
    └── coverage_mcdc.sh    # MC/DC & LLVM coverage verification script
```

---

## Quick Start & Build Automation

Project Alcyon provides a production-grade, standardized Unix `Makefile` adhering to standard packaging conventions (`PREFIX ?= /usr/local`, `DESTDIR ?=`, `CARGO ?= cargo`, `CARGO_FLAGS ?= --release`).

### 1. Self-Documenting Help
```bash
make help
```
Displays an aligned, ANSI-colored summary of all build targets, verification workflows, and overrideable configuration variables.

### 2. Compilation & Execution
```bash
# Build optimized release binary (target/release/alcyon)
make build

# Build debug binary (target/debug/alcyon)
make debug

# Run Alcyon with the canonical HAProxy 3.5 configuration
make run

# Launch Alcyon with the dedicated single-page Web Stats Dashboard on port 8404
make run-stats
```

### 3. Testing & Verification
```bash
# Run all workspace unit, integration, and proptest suites
make test

# Run strict Clippy linter (-D warnings) across all targets
make lint

# Verify code formatting conformance
make fmt-check

# Run differential test harness against reference HAProxy 1.0.2
make difftest

# Run differential comparison (reference HAProxy vs candidate Alcyon)
make difftest-candidate

# Run standalone VTC test runner against HAProxy regression tests
make vtc

# Run all compatible VTC regression tests
make vtc-all
```

### 4. Installation & Packaging
```bash
# Install alcyon binary with mode 755
sudo make install

# Install to custom staging directory for packaging
make install DESTDIR=/tmp/alcyon-pkg PREFIX=/usr

# Remove installed binary
sudo make uninstall

# Clean build artifacts and temporary files
make clean
```

