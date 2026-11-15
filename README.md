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
make difftest       # differential tests against HAProxy 1.0.2 (needs ALCYON_REFERENCE, below)
sudo make install   # installs the binary (PREFIX, DESTDIR as usual)
```

The binary takes HAProxy's command line: `alcyon -f haproxy.cfg`, `alcyon -c -f haproxy.cfg` to
check a configuration. [docs/operating.md](docs/operating.md) covers running it as a service.

`cargo build` and `cargo test` need no HAProxy. They leave out `alcyon-h1-sys`, which compiles
HAProxy's own HTTP/1 parser for the `haproxy-ffi` oracle; `--workspace` includes it.

## Running the oracle tests

HAProxy is the oracle: many tests run the same configuration or bytes through a reference
HAProxy and through Alcyon and compare the answers. They find the reference builds through one
variable, `ALCYON_REFERENCE`, a directory laid out like this:

```
$ALCYON_REFERENCE/
  haproxy/                   HAProxy 3.5-dev8 (885761, 2026/10/02), a git checkout built in place:
    haproxy                    the binary: USE_OPENSSL=1 USE_ZLIB=1 USE_PCRE2=1
    src/ include/              alcyon-h1-sys compiles src/h1.c and src/http.c
    reg-tests/                 HAProxy's regression tests (the smoke board, harness/vtc_runner.py)
  haproxy-quic/haproxy       HAProxy 3.5-dev10 (38e65c, 2026/10/30) with QUIC
  haproxy-1.0.2/haproxy102   HAProxy 1.0.2 (curl_parity, make difftest)
```

To build them (OpenSSL 3.5 or later, whose QUIC API needs no quictls):

```bash
export ALCYON_REFERENCE=$HOME/reference        # anywhere; put it in your shell profile
git clone https://github.com/haproxy/haproxy.git "$ALCYON_REFERENCE/haproxy"
cd "$ALCYON_REFERENCE/haproxy" && git checkout 88576119c   # 3.5-dev8-885761-29
make -j"$(nproc)" TARGET=linux-glibc USE_OPENSSL=1 USE_ZLIB=1 USE_PCRE2=1
git clone https://github.com/haproxy/haproxy.git "$ALCYON_REFERENCE/haproxy-quic"
cd "$ALCYON_REFERENCE/haproxy-quic" && git checkout 38e65c812   # 3.5-dev10-38e65c-10
make -j"$(nproc)" TARGET=linux-glibc USE_THREAD=1 USE_OPENSSL=1 USE_ZLIB=1 USE_QUIC=1 USE_PROMEX=1 USE_PCRE2=1
# HAProxy 1.0.2: the release tarball from https://www.haproxy.org/download/1.0/src/, built with
# its own Makefile into $ALCYON_REFERENCE/haproxy-1.0.2, binary renamed haproxy102.
```

With the variable unset, a test that needs an oracle prints `skipped: ALCYON_REFERENCE is not
set` and passes; the check-in gate (`tools/checkin.sh`) instead fails the stage and names the
variable (`harness/reference.py --require`), so a gate cannot pass by skipping its oracles.
Variables that name one binary still win where they exist: `HAPROXY_REF` (the source tree for
`alcyon-h1-sys`), `CHECK_BIN`, `ALCYON_TXN_BIN`, `HAPROXY` (tools/measure), `HQ`,
`VTC_QUIC_CLIENT_BINARY`, `--haproxy` on the fuzz scripts.

Build and report directories default to `${XDG_CACHE_HOME:-~/.cache}/alcyon/` (`targets/`,
`boards/`, `reports/`), each with its own variable: `ALCYON_TARGETS` (all target directories),
`ALCYON_GATE_TARGET_BASE`, `ALCYON_PERFBASE_DIR`, `ALCYON_PERFBASE_BOARDS`, `DIFFFUZZ_TARGET`,
`DIFFFUZZ_OUT`, `ALCYON_WORKTREES`.

## Who wrote the code

Most of Alcyon is written by Claude models (Anthropic) under one maintainer. Some code was written by
other models while they were being evaluated: run locally, Qwen3.6-35B-A3B, Qwen3.8-Flash-Next and
Muse Glimmer 30B; and since 2026-11-15, through Antigravity, Gemini 4 Hydrogen and Gemini 4 Argon.
Every such commit, and how much of it is still in the tree, is listed in
[docs/provenance/LOCAL-MODELS.md](docs/provenance/LOCAL-MODELS.md), generated from git by
`tools/model_provenance.py`. A model's output is committed unmodified as its own commit, with a
`Model-Authored-By:` trailer, so `git show` on it is exactly what the model wrote. Review fixes and
tests are separate commits on top.

The early work (2026-09-21 to 2026-10-12) was done with Google's Antigravity agent, running Gemini
models (Gemini 3.1 Pro among them). It wrote the first versions of much of the tree, including the
TLS, HTTP/1 and HTTP/2, HPACK, stats, health-check and stick-table code, and many of the `agy/T*`
tasks merged in that period. That code came in mixed with the maintainers' review fixes, so it is
credited here rather than itemised in the ledger.

## Licence

Alcyon is a derivative of HAProxy and carries its licence: GPL-2.0-or-later
([LICENSE](LICENSE), [LICENSE.GPL-2.0](LICENSE.GPL-2.0)). `crates/ebtree` is LGPL-2.1-only
([LICENSE.LGPL-2.1](LICENSE.LGPL-2.1)), as Willy Tarreau's ebtree is, and `crates/slz` is MIT, as
libslz is. The vendored crates keep their own licences.

## Thanks to the HAProxy developers

Alcyon would not exist without HAProxy, and almost everything good in it is theirs.

**Willy Tarreau** started HAProxy in 2000 and has led it ever since. **Everyone who has contributed
to it** made it what it is today: the maintainers, the patch authors, the reviewers, the people who
report bugs and test the development branches, and the people at HAProxy Technologies who fund
and do much of the work. Their names are in HAProxy's history and in its `CONTRIBUTING` and
`MAINTAINERS` files, and they deserve the credit for the ideas this project reimplements.

What Alcyon takes from their work:

- **The design.** The configuration language, the stream and connection model, the muxes, the
  HTX representation, the schedulers, the load-balancing algorithms, stick tables, the sample
  fetch and converter system, the CLI, the stats page and the logging formats were all
  designed by the HAProxy developers. Alcyon follows their design rather than inventing its own,
  and the source comments point to the HAProxy file and line each piece follows.
- **The code.** Alcyon is a derivative work: much of it is a Rust translation of HAProxy's C,
  which is why every file carries HAProxy's licence and copyright line.
- **The oracle.** The HAProxy binary is the specification Alcyon is tested against. Most tests
  here run the same configuration and traffic through both and compare the results. That is
  only possible because HAProxy behaves so precisely and consistently.
- **The tests and the documentation.** HAProxy's reg-tests (run with VTest, which descends from
  Varnish's varnishtest) and its `configuration.txt` and `management.txt` are the best
  specification a reimplementation could ask for. Many of Alcyon's tests are ports of them.
- **The libraries.** Willy Tarreau's ebtree and libslz are ported here as `crates/ebtree` and
  `crates/slz`.
- **The engineering.** Where Alcyon is fast, it is usually because it copied a decision HAProxy
  made first: buffer and memory pools, zero-copy forwarding, and careful attention to the cost of
  each request.

Any mistakes in Alcyon are its own, not HAProxy's.
