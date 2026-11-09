# livepatch-bench

A standalone tool outside the workspace that measures proxy performance without modifying the core daemon.

## What it measures
- **steady-state allocations per request**: Counts the number of allocations (and bytes) per request using `alcyon-alloc`'s pattern with a backtrace-capturing `GlobalAlloc`.
- **bytes allocated per request**
- **requests/second, 1 connection, keep-alive**: Throughput over a single HTTP keep-alive connection.
- **requests/second, 50 concurrent connections**: Throughput using 50 concurrent threads driving the proxy.

## How to re-run it
Run the benchmark against a standard release build:
```bash
cargo run --manifest-path tools/livepatch-bench/Cargo.toml --release
```

Run the benchmark against the livepatch build:
```bash
cargo run --manifest-path tools/livepatch-bench/Cargo.toml --profile livepatch
```
