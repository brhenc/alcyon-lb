# Continuous Measurement Dashboard

**Last Updated:** `2026-09-23T18:50:35.980533+00:00`  
**Git Commit:** `e22b854b` on branch `main`  
**Message:** *tasks: T35 converters redone, T36 health checks, T37 backend TLS*  

---

## Executive KPI Summary

| Metric | Current | Baseline | Target | Status |
|---|---:|---:|---:|:---:|
| Allocations / Request | **5** allocs | 93.0 allocs | <= 5.0 allocs | `PASS` |
| Bytes Allocated / Request | **132** B | 41412.0 B | <= 150.0 B | `PASS` |
| Throughput (1 conn keep-alive) | **13013** req/s | 9400 req/s | >= 12000 req/s | `PASS` |
| Throughput (50 conns concurrent) | **34769** req/s | 30000 req/s | >= 33000 req/s | `PASS` |
| VTC In-Scope Tests Passing | **7 / 171** | 7 / 171 | >= 10 | `WARN` |
| Prometheus Metrics Emitted | **42** | 42 | >= 50 | `WARN` |
| Prometheus Render Allocations | **0** allocs | 0 allocs | == 0 allocs | `PASS` |

---

## 1. Memory & Allocation Profile

- **Steady-State Allocations / Request:** `5`
- **Steady-State Bytes / Request:** `132 B`

### Top Allocation Call Sites

| Count | Total Bytes | Call Site |
|---:|---:|---|
| 2 | 12 B | `<alcyon_rt::proxy::TcpSession>::process_cli_io` |
| 1 | 32 B | `<alloc::vec::Vec<usize> as alloc::vec::spec_from_iter_nested::SpecFromIterNested<usize, core::iter::adapters::filter::Filter<core::ops::range::Range<usize>, <alcyon_rt::engine::Proxy>::eligible_server_indices::{closure#1}>>>::from_iter` |
| 1 | 48 B | `<alloc::boxed::Box<alcyon_proto::h1::H1Parser>>::new` |
| 1 | 40 B | `<no alcyon frame>` |

## 2. VTC Regression Board

Tested against HAProxy 3.5-dev regression test suite.

- **Total Tests in Suite:** `312`
- **Passed:** `7`
- **Failed (In-Scope):** `164`
- **Skipped (Gated/Empty):** `89`
- **Out of Scope (Declined Features):** `52`
- **In-Scope Pass Rate:** `4.09%` (7 / 171)

### Category Breakdown

| Category | Total | Passed | Failed | Out of Scope | Skipped |
|---|---:|---:|---:|---:|---:|
| `balance` | 5 | 1 | 3 | 1 | 0 |
| `cache` | 14 | 0 | 0 | 13 | 1 |
| `checks` | 25 | 0 | 21 | 3 | 1 |
| `compression` | 5 | 0 | 0 | 0 | 5 |
| `connection` | 19 | 0 | 11 | 6 | 2 |
| `contrib` | 1 | 0 | 0 | 0 | 1 |
| `converter` | 25 | 1 | 24 | 0 | 0 |
| `decompression` | 5 | 0 | 0 | 0 | 5 |
| `filters` | 1 | 0 | 0 | 0 | 1 |
| `http-capture` | 1 | 0 | 1 | 0 | 0 |
| `http-cookies` | 2 | 0 | 1 | 1 | 0 |
| `http-errorfiles` | 5 | 0 | 5 | 0 | 0 |
| `http-messaging` | 24 | 2 | 7 | 11 | 4 |
| `http-rules` | 22 | 2 | 17 | 2 | 1 |
| `jwt` | 2 | 0 | 1 | 0 | 1 |
| `log` | 11 | 0 | 11 | 0 | 0 |
| `lua` | 10 | 0 | 0 | 0 | 10 |
| `mailers` | 1 | 0 | 0 | 0 | 1 |
| `mcli` | 3 | 0 | 0 | 2 | 1 |
| `peers` | 4 | 0 | 0 | 4 | 0 |
| `protobuf` | 1 | 0 | 0 | 1 | 0 |
| `proxy` | 3 | 0 | 3 | 0 | 0 |
| `qmux` | 2 | 0 | 0 | 0 | 2 |
| `quic` | 30 | 0 | 0 | 0 | 30 |
| `resolvers` | 1 | 0 | 0 | 1 | 0 |
| `sample_fetches` | 12 | 1 | 11 | 0 | 0 |
| `seamless-reload` | 1 | 0 | 0 | 1 | 0 |
| `server` | 11 | 0 | 8 | 3 | 0 |
| `spoe` | 1 | 0 | 0 | 1 | 0 |
| `ssl` | 47 | 0 | 25 | 0 | 22 |
| `startup` | 3 | 0 | 3 | 0 | 0 |
| `stats` | 3 | 0 | 3 | 0 | 0 |
| `stick-table` | 3 | 0 | 3 | 0 | 0 |
| `stickiness` | 2 | 0 | 0 | 2 | 0 |
| `stream` | 4 | 0 | 4 | 0 | 0 |
| `tcp-rules` | 1 | 0 | 1 | 0 | 0 |
| `webstats` | 2 | 0 | 1 | 0 | 1 |

## 3. Proxy Performance Benchmark

| Workload | Throughput | Target Baseline |
|---|---:|---:|
| 1 Connection (HTTP/1.1 Keep-Alive) | **13013 req/s** | ~13,100 req/s |
| 50 Connections (Concurrent Keep-Alive) | **34769 req/s** | ~33,300 req/s |

## 4. Prometheus Telemetry Verification

- **Alcyon Emits:** `42` metrics
- **HAProxy Oracle:** `227` metrics
- **Metric Parity Coverage:** `18.5%`
- **Rendering Allocations:** `0` allocs, `0` bytes (Zero-Allocation verified: `True`)
- **Differential Schema Conformance:** `PASS`
