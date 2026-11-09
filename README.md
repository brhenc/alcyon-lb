# Alcyon

Alcyon is a test project inspired by DARPA's
[TRACTOR](https://www.darpa.mil/research/programs/translating-all-c-to-rust) program. Its main
goal is to determine the feasibility of rewrites to Rust, and to improve the Rust compiler and
library ecosystem where gaps exist compared to C/C++ compilers and libraries.

The subject of the rewrite is [HAProxy](https://www.haproxy.org/): Alcyon is a reverse proxy and
load balancer in Rust that reads HAProxy's configuration language. HAProxy is the oracle: where
HAProxy and its documentation disagree, Alcyon follows the binary, and most of the behaviour here
is checked by running the same configuration and traffic through both. The known divergences are
listed in [docs/differences.md](docs/differences.md).

This is a research project. It is not a drop-in replacement for HAProxy and should not be used
where HAProxy's maturity matters.

## What is there

- HTTP/1.1, HTTP/2 and HTTP/3 (QUIC) on the client side, HTTP/1.1 and HTTP/2 to servers, and
  `mode tcp`.
- TLS through rustls. An opt-in zeroizing fork of ring (`vendor/ringalcyon`, selected with
  `tune.alcyon.crypto-provider ring-alcyon`) wipes key material when it is freed.
- A large part of HAProxy's configuration: `global`, `defaults`, `frontend`, `backend` and
  `listen`, ACLs, `http-request` / `http-response` / `tcp-request` rules, sample fetches and
  converters, stick tables and `track-sc`, health checks, load-balancing algorithms, the stats
  page and the stats socket CLI.
- Keywords Alcyon does not implement are refused when the configuration is loaded rather than
  accepted and ignored. Among them are `peers` sections, `cache`, `fcgi-app`, Lua and SPOE.

## How it is tested

- **Differential tests against HAProxy.** Integration tests and the `harness/` scripts start
  the reference HAProxy and Alcyon with the same configuration and compare what each answers.
- **HAProxy's own regression tests.** `harness/vtc_runner.py` runs HAProxy's `.vtc` test cases
  against Alcyon.
- **Fuzzing.** `fuzz/` holds a differential fuzzer (generated configurations and traffic against
  both proxies) and libFuzzer targets.
- **Coverage.** LLVM source-based coverage (`cargo llvm-cov`). The check-in gate requires every
  changed source line to be executed by a test (`harness/covercheck.py`). MC/DC coverage is
  limited: Rust has no stable MC/DC instrumentation, so `scripts/coverage_mcdc.sh` does what the
  toolchain allows.
- **The check-in gate.** `tools/checkin.sh` runs the suite, coverage, lint, the HAProxy oracles
  and an instructions-per-request measurement.
- **Other HTTP/1 parsers behind one interface.** `crates/alcyon-proto/src/parser.rs` selects an
  HTTP/1 parser by name. `h1`, Alcyon's own, is the one in use. `haproxy-ffi` (Cargo feature of
  the same name, through `alcyon-h1-sys`) runs HAProxy's C parser as an oracle. `pingora` is
  reserved for Pingora's Rust HTTP parser, as a parsing provider tested so that compiler changes
  can be checked for not making its performance worse; its adapter is not written yet, and a build refuses it
  by name. Hot-swapping parsers is a research goal, so that requests can be routed to different parsers if
  needed. 

## Workspace

```
alcyon-lb/
├── crates/
│   ├── alcyon-rt/           # runtime: thread-per-core pollers, listeners, the proxy engine,
│   │                        #   HTTP/1, HTTP/2 and HTTP/3 muxes, stats, CLI; the `alcyon` binary
│   ├── alcyon-proto/        # layer model: protocol / transport / mux interfaces, HTX, HTTP/1
│   │                        #   and HTTP/2 framing
│   ├── alcyon-config/       # HAProxy configuration parser and AST
│   ├── alcyon-sample/       # sample fetches, converters and matchers
│   ├── alcyon-sched/        # HAProxy-style task scheduler (ebtree run queue, timers)
│   ├── alcyon-stick-table/  # stick tables: tracked keys, counters, rate limiters
│   ├── alcyon-tls/          # TLS transport over rustls and SNI certificate selection
│   ├── alcyon-quic/         # QUIC transport over quinn-proto
│   ├── alcyon-mmsg/         # recvmmsg / sendmmsg batching for UDP
│   ├── alcyon-dns/          # sans-IO DNS resolver, after HAProxy's resolvers.c
│   ├── alcyon-regex/        # regular expressions (regex, with fancy-regex for PCRE-only syntax)
│   ├── alcyon-crypt/        # crypt(3) password hashes for userlists, in safe Rust
│   ├── alcyon-alloc/        # memory pools and arenas, allocation counting for tests
│   ├── alcyon-h1-sys/       # FFI to HAProxy's C HTTP/1 parser, a test oracle
│   ├── ebtree/              # port of Willy Tarreau's elastic binary trees
│   └── slz/                 # port of libslz, a stateless deflate compressor
├── vendor/
│   ├── quinn-proto/         # QUIC protocol library, patched (vendor/README.md)
│   ├── ringalcyon/          # ring with zeroizing patches (opt-in crypto provider)
│   └── rustls-ringalcyon/   # rustls provider for that fork
├── fuzz/                    # differential fuzzer and libFuzzer targets
├── harness/                 # differential tests, VTC runner, coverage and suite drivers
├── tools/                   # check-in gate, measurement, load and battery scripts
├── docs/  design/           # design documents and research notes
├── data/                    # findings and verification ledgers, baselines, measurements
├── examples/                # sample configurations and certificates
└── contrib/  admin/         # systemd units
```

[ARCHITECTURE.md](ARCHITECTURE.md) describes how the pieces fit together, and
[tradeoff.md](tradeoff.md) records the places where Alcyon deliberately does something other than
HAProxy, and why.

## Building and running

Alcyon builds with stable Rust and Cargo (Linux only). The `Makefile` wraps the common tasks;
`make help` lists them.

```bash
make build          # release build: target/release/alcyon
make debug          # debug build: target/debug/alcyon
make run            # run with examples/canonical_haproxy_35.cfg
make run-stats      # run with the stats page on http://127.0.0.1:8404/stats
make test           # the workspace tests
make lint           # clippy with warnings as errors
make fmt-check      # formatting check
make vtc            # one HAProxy .vtc case through harness/vtc_runner.py (vtc-all: the compatible ones)
make difftest       # differential tests; DIFFTEST_REF must point at a reference haproxy binary
sudo make install   # installs the binary (PREFIX, DESTDIR as usual)
```

The binary takes HAProxy's command line: `alcyon -f haproxy.cfg`, `alcyon -c -f haproxy.cfg` to
check a configuration. [docs/operating.md](docs/operating.md) covers running it as a service.

## Licence

Alcyon is a derivative of HAProxy and carries its licence: GPL-2.0-or-later
([LICENSE](LICENSE), [LICENSE.GPL-2.0](LICENSE.GPL-2.0)). `crates/ebtree` is LGPL-2.1-only
([LICENSE.LGPL-2.1](LICENSE.LGPL-2.1)), as Willy Tarreau's ebtree is, and `crates/slz` is MIT, as
libslz is. The vendored crates keep their own licences.
