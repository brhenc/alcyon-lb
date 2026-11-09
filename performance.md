<!--
SPDX-License-Identifier: GPL-2.0-or-later
Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
-->
# Performance: Alcyon against HAProxy

Measured 2026-11-09 on Alcyon `3ea291cb` against HAProxy 3.5-dev8 (HTTP/1, HTTP/2, TLS) and
3.5-dev10 (HTTP/3), on one quiet host. Every figure below comes from the same harness, client
and backend for both proxies. The previous version of this file (2026-10-02, when Alcyon used
16-18% more CPU per request than HAProxy) is in `docs/history/performance-2026-10-02.md`.

These figures are for one small, synthetic workload: an empty `GET /`, a 200 response, one
core. They say where the per-request cost stands. They do not say how either proxy behaves
under real traffic, with many cores, or with large bodies.

## Setup

- **Host:** AMD EPYC 7542 (32 cores), Linux 7.2.15, governor `performance`. Nothing else ran
  (checked before and after, `/tmp/alcyon-load.lock` held).
- **Pinning:** proxy on CPU 4, client on 5, backend on 6 (one L3 group), `nbthread 1`.
- **Alcyon:** `cargo build --profile release-perf` (fat LTO, `codegen-units = 1`), rustc 1.99.1;
  TLS is rustls 0.24 with ring.
- **HAProxy:** built from source with its defaults: `CFLAGS = -O2 -g -fwrapv`, OpenSSL 3.5.8
  (3.5.9 for the QUIC build), PCRE2 without JIT.
- **Configurations:** `tools/measure/scenarios/*.body`. The same file runs on both proxies.
  `keepalive` is a plain proxy; `rules` adds a typical set of `http-request` /
  `http-response` rules; `tls` terminates TLS; `h3` binds QUIC.

Instructions per request (`tools/measure/insreq.sh`, `perf stat -e instructions:u` on the proxy
process, minimum of 5 rounds) are the figure the project budgets on. They vary by under 0.3%
between runs, where wall time varies by a few percent. They are user-space only, because this
host does not allow counting kernel instructions. Fewer instructions is not the same as less
time: the CPU-time figures are below.

## Instructions per request

| Workload | Client | HAProxy | Alcyon | Alcyon vs HAProxy |
|---|---|---:|---:|---:|
| HTTP/1.1 keep-alive | 1 connection (`ab -k -c 1`) | 36,100 | 35,104 | -2.8% |
| HTTP/1.1 keep-alive | 50 connections (`measure-bench`) | 32,637 | 28,098 | -13.9% |
| HTTP/1.1 with rules | 1 connection | 43,711 | 50,492 | **+15.5%** |
| HTTP/1.1 with rules | 50 connections | 41,438 | 42,373 | +2.3% |
| HTTPS keep-alive | 1 connection (`ab1s`) | 49,354 | 41,211 | -16.5% |
| HTTPS, one handshake per request | 1 connection (`hs1`) | 2,997,694 | 1,441,002 | -51.9% |
| HTTP/2 over TLS | 1 connection, 1 stream (`h2load`) | 53,161 | 50,660 | -4.7% |
| HTTP/3 | 1 connection (`h3fit`, at 1.97 client datagrams/request) | 63,783 | 82,705 | **+29.7%** |

Notes:

- **TLS handshakes** compare two cryptography libraries (ring under rustls against OpenSSL 3.5)
  as much as two proxies. The figure counts only the proxy's user-space instructions, so the
  handshake's kernel work is not in it.
- **HTTP/3** is measured with Alcyon's own client (`tools/measure/h3bench`, T555), because
  `h2load`'s acknowledgement pattern varies too much between rounds. The client's datagram
  rate is fixed by fitting two runs, as `insreq.sh` describes. Alcyon's QUIC is quinn-proto
  (vendored); HAProxy's is its own.
- **Rules at one connection** is the largest HTTP/1 gap. At 50 connections it shrinks to 2.3%,
  so most of it is a fixed cost paid on every wakeup rather than work done per rule.

## CPU time and throughput, one core

From `measure_ab` (`tools/measure/measure.py`), the gate's own A/B, with HAProxy as the second
binary. It runs 6 rounds in alternating order, with a fresh proxy for each sample, on the
`keepalive` configuration.

| | HAProxy | Alcyon | |
|---|---:|---:|---:|
| CPU per request, 50 connections | 16.35 µs | 15.67 µs | -4.2% |
| Requests/s, 1 connection | 18,495 | 19,774 | +6.9% |

- **CPU per request at 50 connections** is the proxy's own CPU time (from `/proc/<pid>/schedstat`)
  over a fixed number of requests. It is the figure to compare: the proxy is busy and rarely
  sleeps.
- **Requests/s at 1 connection** also measures how quickly each proxy goes to sleep and wakes
  up again between requests.
- **Samples:** HAProxy 16,539 / 16,456 / 16,367 / 16,323 / 16,326 / 16,288 ns; Alcyon 15,604 /
  15,722 / 15,707 / 15,719 / 15,624 / 15,605 ns.

## Memory and allocations

- **Allocations per request:** 0 (0 bytes) for proxied HTTP/1 keep-alive, measured by
  `tools/allocprofile` in the same run. The tests in `crates/alcyon-rt/tests/request_allocations*.rs`
  pin the same for h2c, TLS, HTTP/2 to servers, rules, `return`, logging and HTTP/3
  (RUST-FOOTGUNS.md section 2).
- **60,000 backends** (`measure_60k_backends_memory`): 18.59 MB resident after loading, against
  15.84 MB when last measured on 2026-09-24, before the memory pools (2026-10-24). This is
  Alcyon only: HAProxy was not measured in this run.

## How to reproduce

```
export ALCYON_REFERENCE=<directory with haproxy/ and haproxy-quic/>
cargo build --profile release-perf --bin alcyon
flock -x /tmp/alcyon-load.lock tools/measure/insreq.sh <label> <proxy-binary> \
    tools/measure/scenarios/keepalive.body ab1 20000 5 /tmp/<label>
```

The other rows use the same command with the scenario and client from the first table
(`tls.body` with `ab1s`, `hs1` and `h2s1`, at 5,000 requests; `h3.body` with `h3fit`). The CPU
table calls `measure.measure_ab(alcyon, haproxy, target_dir, rounds=6)`. The check-in gate runs
the keep-alive and rules A/B on every main commit, against the previous one
(`data/measurements.jsonl`).

## Open

- **HTTP/3 (+30%)** and **rules at one connection (+15%)** are the two gaps worth work. Profile them
  with `tools/measure/insprof.sh` before choosing a change.
- **Syscalls per request** were not counted in this run. The 2026-10-02 profile found 9 `EAGAIN`
  reads per request, and that was fixed the same day (`docs/history/performance-2026-10-02.md`,
  `crates/alcyon-rt/tests/it/reads_per_request.rs`).
- **Multi-core scaling** and **large bodies** are not measured here.
