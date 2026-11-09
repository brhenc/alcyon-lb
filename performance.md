<!--
SPDX-License-Identifier: GPL-2.0-or-later
Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
-->
# Performance: Alcyon against HAProxy

Measured 2026-11-09 on one quiet host. Alcyon is `3ea291cb`. HAProxy is 3.5-dev8 for HTTP/1,
HTTP/2 and TLS, and 3.5-dev10 for HTTP/3. Every figure comes from the same harness, client,
backend and configuration file for both proxies. The previous version of this file
(2026-10-02, when Alcyon used 16-18% more CPU per request than HAProxy) is in
`docs/history/performance-2026-10-02.md`.

These figures are for one small, synthetic workload: an empty `GET /`, a 200 response, one
core. They say where the per-request cost stands. They do not say how either proxy behaves
under real traffic, with many cores, or with large bodies.

## Built the same way

A default HAProxy build is `-O2` without link-time optimisation. Alcyon's measured build is
fat LTO. Comparing those two would credit the language with what the build did. So HAProxy was
built seven ways from the reference sources (`tools/measure/haproxy-variants.sh`), and Alcyon
two ways:

| Build | Compiler | Optimisation |
|---|---|---|
| `alcyon-rp` | rustc 1.99.1 (LLVM) | `--profile release-perf`: fat LTO, 1 codegen unit |
| `alcyon-pgo` | rustc 1.99.1 (LLVM) | release-perf plus PGO (`tools/pgo-build.sh`) |
| `hap-o2` | gcc 16.2 | HAProxy's defaults, `-O2 -fwrapv` (the reference binary's flags) |
| `hap-o2-jit` | gcc 16.2 | `-O2` with `USE_PCRE2_JIT=1`, as distribution packages ship it |
| `hap-lto` | gcc 16.2 | `-O2 -flto=auto` |
| `hap-pgo` | gcc 16.2 | `-O2` plus PGO |
| `hap-pgo-lto` | gcc 16.2 | `-O2 -flto=auto` plus PGO |
| `hap-clang-lto` | clang 23.1 (LLVM) | `-O2 -flto=full`, lld |
| `hap-clang-pgo-lto` | clang 23.1 (LLVM) | `-O2 -flto=full` plus PGO |

- **PGO training is the same for every PGO build.** Each is trained on one request mix: the
  `train()` function of `tools/pgo-build.sh`, run against `tools/pgo/train.cfg`, with the
  HTTP/3 part only for the QUIC build.
- **The clang builds use the same LLVM backend as rustc.** So `alcyon-pgo` against
  `hap-clang-pgo-lto` is the closest this setup gets to the language against the language.
  The gcc against clang rows show how much the compiler alone moves HAProxy.
- **The TLS library is still not the same.** Alcyon uses ring under rustls 0.24; HAProxy uses
  OpenSSL 3.5. The HTTP/2-over-TLS rows include that difference.

## Setup

- **Host:** AMD EPYC 7542, Linux 7.2.15, governor `performance`. No other load: checked before
  and after every run, with `/tmp/alcyon-load.lock` held.
- **Pinning:** proxy on CPU 4, client on 5, backend on 6, `nbthread 1`. The configurations are
  `tools/measure/scenarios/*.body`:
  - `keepalive`: a plain HTTP/1.1 keep-alive proxy;
  - `rules`: adds a typical set of `http-request` / `http-response` rules, including one
    `path_reg`;
  - `tls`: HTTP/2 over TLS with `h2load -c 1 -m 1`;
  - `h3`: HTTP/3, measured with `h3fit`.
- **Instructions** per request (`insreq.sh`, user space, minimum of 5 rounds) vary by under 0.3%
  between runs.
- **Cycles** per request (`hwcounters.sh`, user space, median of 5 rounds) are closer to time,
  but code layout moves them. `hap-o2` and `hap-o2-jit` run the same code for `keepalive`, which
  has no regex: 36,101 against 36,100 instructions, yet 36,468 against 39,395 cycles. **Read a
  difference in cycles under about 8% as noise.**
- **Kernel counters:** this host does not allow counting kernel instructions or cycles, so
  neither appears here.

## Like for like

Instructions and cycles per request, user space. Lower is better.

| Comparison | keep-alive | rules | HTTP/2 over TLS | HTTP/3 |
|---|---:|---:|---:|---:|
| **Best against best:** `alcyon-pgo` / `hap-clang-pgo-lto`, instructions | 29,494 / 30,638 (−4%) | 42,473 / 36,922 (**+15%**) | 44,051 / 47,205 (−7%) | 71,810 / 52,792 (**+36%**) |
| the same, cycles | 19,654 / 20,401 (−4%) | 26,419 / 25,708 (+3%) | 29,340 / 40,938 (−28%) | |
| **Same compiler, no PGO:** `alcyon-rp` / `hap-clang-lto`, instructions | 35,106 / 37,661 (−7%) | 50,490 / 45,392 (+11%) | 50,553 / 55,039 (−8%) | 82,983 / 64,169 (+29%) |
| the same, cycles | 28,611 / 35,200 (−19%) | 44,865 / 44,888 (0%) | 48,434 / 70,480 (−31%) | |
| **Default builds:** `alcyon-rp` / `hap-o2`, instructions | 35,106 / 36,101 (−3%) | 50,490 / 43,710 (+16%) | 50,553 / 52,772 (−4%) | 82,983 / 63,653 (+30%) |

HTTP/3 is instructions only (`h3fit`, at 1.97 client datagrams per request, median of 3).
HAProxy's QUIC is its own implementation; Alcyon's is vendored quinn-proto.

What it shows:

- **Plain proxying (keep-alive):** Alcyon is level with HAProxy or slightly ahead in every
  pairing. The cycles gap without PGO (−19%) is larger than the noise. With PGO both proxies
  gain 30-40% and end within 4% of each other.
- **Rules:** HAProxy executes 11-16% fewer instructions in every pairing. In cycles the two are
  level (0% and +3%), so Alcyon's extra instructions are cheap ones. PCRE2's JIT changes little
  here: `hap-o2-jit` saves 178 instructions per request over `hap-o2`.
- **HTTP/2 over TLS:** Alcyon's lead in cycles (−28 to −31%) is mostly the TLS library (ring
  against OpenSSL 3.5), not the proxy. The instruction gap is smaller (−7%).
- **HTTP/3** is the clear gap: 29-36% more instructions than HAProxy in every pairing.
- **PGO matters more than the language.** It cuts 30-45% of cycles for both proxies. With PGO
  and LTO on both, gcc and clang end within 7% of each other on HAProxy for HTTP/1, and 12% in
  cycles on TLS, and clang PGO+LTO is
  HAProxy's best build in every column.

## Every build

| Build | keep-alive ins | rules ins | h2 TLS ins | keep-alive cycles | rules cycles | h2 TLS cycles | IPC keep-alive | req/s 1 conn | req/s 50 conn |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| alcyon-rp | 35,106 | 50,490 | 50,553 | 28,611 | 44,865 | 48,434 | 1.23 | 18,783 | 37,204 |
| alcyon-pgo | 29,494 | 42,473 | 44,051 | 19,654 | 26,419 | 29,340 | 1.51 | 19,824 | 43,782 |
| hap-o2 | 36,101 | 43,710 | 52,772 | 36,468 | 43,112 | 71,254 | 0.99 | 17,819 | 34,075 |
| hap-o2-jit | 36,100 | 43,532 | 52,773 | 39,395 | 45,256 | 71,539 | 0.92 | 17,768 | 34,425 |
| hap-lto | 35,559 | 43,156 | 52,452 | 35,984 | 44,185 | 70,523 | 0.99 | 17,837 | 34,167 |
| hap-pgo | 33,322 | 40,309 | 49,728 | 22,501 | 28,143 | 47,394 | 1.48 | 19,318 | 36,088 |
| hap-pgo-lto | 31,982 | 38,765 | 48,359 | 21,896 | 27,514 | 45,999 | 1.46 | 19,282 | 36,268 |
| hap-clang-lto | 37,661 | 45,392 | 55,039 | 35,200 | 44,888 | 70,480 | 1.07 | 17,917 | 34,329 |
| hap-clang-pgo-lto | 30,638 | 36,922 | 47,205 | 20,401 | 25,708 | 40,938 | 1.50 | 19,442 | 36,274 |

HTTP/3 instructions per request, by build: alcyon-rp 82,983; alcyon-pgo 71,810; hap o2 63,653;
lto 62,352; pgo 58,955; pgo-lto 56,708; clang-lto 64,169; clang-pgo-lto 52,792.

- **Requests per second** are the keep-alive scenario: `ab -k -c 1`, and `measure-bench` with
  50 connections, median of 5. They are timing figures, valid because the host was quiet.
- **At 50 connections** the client shares the machine and may limit both proxies, so these
  differences are a lower bound.

## Default builds, other workloads

Measured the same day on `alcyon-rp` against `hap-o2` (the reference binary) only.

| Workload | HAProxy `-O2` | Alcyon release-perf | |
|---|---:|---:|---:|
| keep-alive, 50 connections, instructions | 32,637 | 28,098 | −14% |
| rules, 50 connections, instructions | 41,438 | 42,373 | +2% |
| HTTPS keep-alive, 1 connection, instructions | 49,354 | 41,211 | −17% |
| HTTPS, a handshake per request, instructions | 2,997,694 | 1,441,002 | −52% (mostly ring against OpenSSL) |
| CPU per request, 50 connections (`measure_ab`, 6 rounds) | 16.35 µs | 15.67 µs | −4% |
| requests/s, 1 connection (`measure_ab`) | 18,495 | 19,774 | +7% |

## Memory and allocations

- **Allocations per request:** 0 for proxied HTTP/1 keep-alive (`tools/allocprofile`). The
  tests in `crates/alcyon-rt/tests/request_allocations*.rs` pin the same for h2c, TLS, HTTP/2
  to servers, rules, `return`, logging and HTTP/3.
- **60,000 backends:** 18.59 MB resident after loading, against 15.84 MB when last measured
  (2026-09-24, before the memory pools). This is Alcyon only.

## How to reproduce

```
export ALCYON_REFERENCE=<directory with haproxy/ and haproxy-quic/>
tools/pgo-build.sh --target-dir <dir>/t603-alcyon --out <dir>/t603-alcyon/alcyon-pgo
tools/measure/haproxy-variants.sh build d8        # 3.5-dev8, all seven variants
tools/measure/haproxy-variants.sh build q10 o2 lto pgo pgo-lto clang-lto clang-pgo-lto
tools/measure/variants-matrix.sh <out> <label> <binary> insreq   # then hw, tp; h3 for QUIC builds
```

## Open

- **HTTP/3 (+29-36%)** and **rules (+11-16% in instructions)** are the gaps. Profile both with
  `tools/measure/insprof.sh`.
- **The TLS rows compare two cryptography libraries.** Building HAProxy against AWS-LC
  (`USE_OPENSSL_AWSLC=1`), which shares ring's BoringSSL lineage, would make them compare the
  proxies.
- **Kernel instructions and cycles** need `kernel.perf_event_paranoid` of 1 or lower while
  measuring.
- **Not measured:** many cores (`nbthread` above 1, with HAProxy's thread groups) and large
  bodies.
