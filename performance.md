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
| `hap-o2-awslc` | gcc 16.2 | `hap-o2` built against AWS-LC 1.72.1 instead of OpenSSL |
| `hap-clang-pgo-lto-awslc` | clang 23.1 (LLVM) | `hap-clang-pgo-lto` built against AWS-LC 1.72.1 |

- **PGO training is the same for every PGO build.** Each is trained on one request mix: the
  `train()` function of `tools/pgo-build.sh`, run against `tools/pgo/train.cfg`, with the
  HTTP/3 part only for the QUIC build.
- **The clang builds use the same LLVM backend as rustc.** So `alcyon-pgo` against
  `hap-clang-pgo-lto` is the closest this setup gets to the language against the language.
  The gcc against clang rows show how much the compiler alone moves HAProxy.
- **The TLS library.** Alcyon uses ring under rustls 0.24, and the reference HAProxy uses
  OpenSSL 3.5. The `-awslc` builds use AWS-LC instead. AWS-LC and ring both descend from
  BoringSSL, so with those builds the TLS rows compare the proxies rather than two crypto
  libraries (section "Same crypto family").

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
- **Kernel counters:** the first matrix (`data/perf-2026-11-09/matrix/`) ran with
  `kernel.perf_event_paranoid` 2, so its figures are user space only. The second
  (`matrix2/`) ran with 1, and it adds kernel instructions and the AWS-LC builds. The six builds
  measured in both matrices reproduced their user-space instruction counts to within 0.15%.
- **A disturbed stretch:** an unpinned training job from another project ran from 15:32,
  partly on the measurement CPUs, until it was moved off them at about 16:15. The second
  matrix's runs after 15:32 overlap it: the two `-awslc` builds and all of HTTP/3. Instruction
  counts are unaffected (the counts above held), so those are reported. The cycle counts from
  that stretch are not used.

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
  against OpenSSL 3.5), not the proxy. The instruction gap is smaller (−7%), and against AWS-LC
  it becomes +2% in user space (below).
- **HTTP/3** is the clear gap: 29-36% more instructions than HAProxy in every pairing.
- **PGO matters more than the language.** It cuts 30-45% of cycles for both proxies. With PGO
  and LTO on both, gcc and clang end within 7% of each other on HAProxy for HTTP/1, and 12% in
  cycles on TLS, and clang PGO+LTO is
  HAProxy's best build in every column.

## Kernel side

Instructions per request: user space, kernel, and their total (`insreq.sh`, minimum total of 5
rounds, `matrix2/`). Most of a proxied request's instructions are in the kernel. They are the
system calls each proxy makes: receive, send, `epoll`.

| Build | keep-alive user / kernel / total | rules total | HTTP/2 over TLS total |
|---|---|---:|---:|
| `alcyon-pgo` | 29,471 / 63,842 / **93,314** | 106,288 | 108,288 |
| `hap-clang-pgo-lto` | 30,637 / 67,266 / **97,903** | 104,255 | 120,951 |
| `alcyon-rp` | 35,091 / 63,695 / 98,787 | 114,311 | 115,145 |
| `hap-o2` | 36,105 / 67,393 / 103,499 | 111,208 | 126,697 |

- **Fewer kernel instructions:** Alcyon spends about 3,500 fewer kernel instructions per HTTP/1
  request than HAProxy (63.7-63.8k against 67.3-67.5k), in every build.
- **Rules:** best against best, the +15% gap in user space becomes **+2% in total** (106,288
  against 104,255).
- **Keep-alive:** best against best, Alcyon is **−5%** in total.
- **Not counted:** `h3fit` does not report kernel instructions, so HTTP/3 has none here.

## Same crypto family: AWS-LC

The same rows with HAProxy built against AWS-LC 1.72.1, user-space instructions per request
except where it says total.

| Workload | `alcyon-pgo` | `hap-clang-pgo-lto` (OpenSSL) | `hap-clang-pgo-lto-awslc` | Alcyon vs AWS-LC build |
|---|---:|---:|---:|---:|
| TLS handshake per request (`hs1`) | 1,431,800 | 2,898,193 | 1,432,989 | −0.1% |
| HTTPS keep-alive (`ab1s`), total | 99,183 | 114,781 | 110,189 | −10% |
| HTTP/2 over TLS, user | 44,050 | 47,210 | 43,009 | +2.4% |
| HTTP/2 over TLS, total | 108,288 | 120,951 | 116,738 | −7% |
| HTTP/3, user (3.5-dev10) | 71,479 | 52,820 | 50,074 | +43% |

The default builds tell the same story: `hap-o2-awslc` makes a handshake in 1,439,771 user
instructions where `hap-o2` with OpenSSL takes 2,905,502, and `alcyon-rp` 1,441,348.

- **The handshake gap was entirely the crypto library.** With AWS-LC, HAProxy's handshake
  costs what Alcyon's does, to within 0.1%. The −52% in the default-build table further down
  is OpenSSL 3.5 against ring, and says nothing about the proxies.
- **HTTP/2 over TLS:** with the same crypto family, Alcyon is 2% behind in user space and 7%
  ahead in total.
- **HTTP/3** gets worse for Alcyon with AWS-LC. HAProxy gains 5% from AWS-LC there, so the
  gap grows from +35% to +43%.

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
| HTTPS, a handshake per request, instructions | 2,997,694 | 1,441,002 | −52% (ring against OpenSSL: level with an AWS-LC build, above) |
| CPU per request, 50 connections (`measure_ab`, 6 rounds) | 16.35 µs | 15.67 µs | −4% |
| requests/s, 1 connection (`measure_ab`) | 18,495 | 19,774 | +7% |

## dpbench: throughput and latency, 1 and 4 threads

The method of [dpbench](https://github.com/dpbench/dpbench) (Willy Tarreau's proxy benchmark),
with its `h1load` and `httpterm` (commit `622d9d4`) and its forwarder configuration: 8 servers,
`balance random`, an empty `GET /?s=0`, the same configuration file for every proxy. One proxy
at a time on CPU 8 (or 8-11, one CCX), servers on 16-23, the load generator (`h1load -t 8 -c 400`)
on 24-31. First each proxy's maximum. Then every proxy at the same fixed rate, 80% of the
weakest maximum, with a separate low-rate probe client (`-c 4`, 1% of the rate) whose
percentiles are the latency. Two runs, 16:39 and 16:47, on the quiet host. `tools/measure/dpbench.sh`.

| | alcyon-pgo | hap-clang-pgo-lto | alcyon-rp | hap-o2 |
|---|---:|---:|---:|---:|
| max req/s, 1 thread (run 1 / run 2) | 26,202 / 26,483 | 27,063 / 26,807 | 24,766 / 24,186 | 25,167 / 25,270 |
| max req/s, 4 threads | 101,583 / 102,510 | 106,987 / 106,379 | 95,942 / 97,736 | 99,546 / 98,470 |
| CPU at 19,000 req/s, 1 thread (cores) | 0.73 | 0.71 | 0.76 | 0.75 |
| CPU at 78,000 req/s, 4 threads (cores) | 2.85 | 2.82 | 2.96 | 2.96 |
| probe p50 / p99.9, 4 threads (ms) | 0.16 / 4.9 | 0.19 / 4.7 | 0.24 / 5.1 | 0.23 / 6.6 |

- **Best against best,** Alcyon reaches 1-3% less than HAProxy at 1 thread and 4-5% less at 4 (3.6% and 5.1%),
  and uses 1-3% more CPU at the same rate. That is one notch behind the one-core instruction
  counts above (keep-alive 4% fewer instructions): this configuration opens **a new server
  connection for nearly every request** (HAProxy's stop line: 405 client connections, 557,430
  server connections in a 1-thread maximum run), since an idle connection is seldom on the server
  `balance random` picks next. So it measures connection setup and the kernel's TCP path more than
  request handling, and a quarter of every proxy CPU is loopback softirq.
- **Default builds** are level: `alcyon-rp` 1-4% below `hap-o2` at the maximum, same CPU.
- **Latency** is the same for all four within run-to-run noise. At 1 thread the probe's p99 and
  above jump between runs by up to 20x for the same binary (alcyon-pgo p99 0.59 ms in run 1,
  12.1 ms in run 2), so those percentiles say nothing about the proxies; the p50s (0.16-0.20 ms)
  do.
- **CPU** is the proxy CPUs' busy time from `/proc/stat`, softirq included. The process's own
  time (utime + stime, in the raw logs as well) leaves out the softirq, which the kernel does not
  charge to the process, and shows about 0.55 of a core when the CPU is in fact saturated.
- Run 1's CPU column is the process time only; its throughput and percentiles stand. Raw output:
  `data/perf-2026-11-09/dpbench/`.

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
# AWS-LC: build it (cmake -DBUILD_SHARED_LIBS=1 -DCMAKE_INSTALL_PREFIX=<prefix>), then
HAPV_AWSLC=<prefix> tools/measure/haproxy-variants.sh build d8 o2-awslc clang-pgo-lto-awslc
# kernel counts: sudo sysctl kernel.perf_event_paranoid=1 for the run
# dpbench: git clone https://github.com/dpbench/dpbench; ./tools/build-all.sh (puts h1load, httpterm in bin/)
DPBENCH_BIN=<dpbench>/bin tools/measure/dpbench.sh <out> alcyon-pgo=<bin> hap-clang-pgo-lto=<bin> ...
```

## Open

- **HTTP/3** is the gap that remains in every comparison: +29-43% in instructions, depending on
  the builds. Profile it with `tools/measure/insprof.sh`.
- **Rules** is +11-16% in user-space instructions, but level in cycles and +2% in total with the
  kernel. That makes it a smaller target than it first looked.
- **Kernel cycles** were not measured cleanly; only kernel instructions are reported.
- **dpbench** has Alcyon 4-5% behind at 4 threads, on a workload that opens a server connection
  per request: the connect path, not the request path, is the place to look.
- **Not measured:** more than 4 threads (HAProxy's thread groups), server-side keep-alive under
  dpbench (`balance roundrobin` or one server), and large bodies.
