# tools/parity-bench

Automated performance parity investigation harness and profiling tool for Alcyon vs HAProxy.

## Overview
This suite benchmarks Alcyon against reference HAProxy (`/home/bhenc/reference/haproxy-quic/haproxy`) across multiple configurations:
1. **baseline**: Standard reverse proxying of HTTP/1.1 requests.
2. **+ set-header**: `http-request set-header X-Trace %[uuid()]` (defeats unmodified-request fast path by mutating headers on every request).
3. **+ acl**: `acl is_get method GET; http-request set-var(txn.m) str(get) if is_get` (forces ACL evaluation and rule traversal per request).
4. **+ httplog**: `log 127.0.0.1:<port> local0; option httplog` (forces log-line formatting).

## Components
- `Cargo.toml` & `src/main.rs`: High-performance compiled Rust client and mock HTTP backend designed to drive 300,000+ RPS without GIL or runtime bottlenecks.
- `run_benchmarks.py`: Python orchestrator that runs the 4 configurations, performs `strace` syscall accounting, captures `perf` stack traces, generates flamegraphs (`alcyon.svg` and `haproxy.svg`), and tests byte-for-byte non-canonical header forwarding.
- `haproxy.svg` & `alcyon.svg`: Inferno flamegraphs captured under steady-state single-connection keep-alive load.

## Running the Benchmarks
```bash
# 1. Build the parity-bench tool
export CARGO_TARGET_DIR=/tmp/t39-target
cargo build --manifest-path tools/parity-bench/Cargo.toml --release

# 2. Build Alcyon release daemon with frame pointers
RUSTFLAGS="-C force-frame-pointers=yes" cargo build --bin alcyon --release

# 3. Run the full automated parity benchmark suite
python3 tools/parity-bench/run_benchmarks.py
```
