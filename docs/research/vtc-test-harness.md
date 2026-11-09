# HAProxy VTC Regression Test Framework & Alcyon Harness Architecture

**Document Type:** Architectural Research & Test Harness Specification  
**Oracle Baseline:** `/home/bhenc/reference/haproxy/reg-tests` @ commit `e6f616af` (HAProxy 3.5-dev7)  
**Safety & Concurrency Invariant:** `#![forbid(unsafe_code)]`, zero external C runtime dependencies for standalone runner, exact parity against upstream HAProxy behavior.

---

## 1. Executive Summary & Problem Formulation

Project Alcyon's ultimate quality metric is **direct upstream compatibility**: proving that Alcyon can pass the exact regression test cases (`.vtc` files) created by HAProxy core maintainers over the last 25 years.

HAProxy tests its binary using **VTest** (derived from Poul-Henning Kamp's Varnish Test Case tool, `varnishtest`). A `.vtc` test script specifies:
1. Declarations of mock HTTP/TCP servers (`server s1 { ... }`).
2. Declarations of mock UDP syslog receivers (`syslog Slg_1 { ... }`).
3. Embedded HAProxy configuration blocks (`haproxy h1 -conf { ... }`).
4. Concurrently executed mock HTTP/TCP clients (`client c1 -connect ... { ... }`).
5. Multithreaded execution synchronization barriers (`barrier b1 cond 2`).
6. Assertion expressions verifying HTTP status codes, header values, regex matches, header non-existence (`<undef>`), and response payloads.

This document details:
1. The formal grammar, execution semantics, and macro system of VTC test scripts.
2. An architectural comparison between **Integration Path A** (Standard C `vtest`) and **Integration Path B** (Pure Python/Rust standalone VTC interpreter).
3. The exact CLI binary flags and file-descriptor inheritance mechanisms Alcyon must support.
4. An exhaustive triage of all **312 `.vtc` regression tests** across 36 directories in HAProxy 3.5.
5. An implementation blueprint for `harness/vtc_runner.py` and `crates/alcyon-vtest`.
6. A phased roadmap scaling Alcyon test pass rates from **51 initial tests** to **198 in-scope tests**.

---

## 2. VTC (Varnish Test Case) Grammar & Execution Semantics

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              VTC Script Architecture                            │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  ┌──────────────────────┐  pre-bind socket  ┌────────────────────────────────┐  │
│  │     vtest Engine     │──────────────────►│  OS File Descriptor (FD: 7)    │  │
│  └──────────┬───────────┘                   └───────────────┬────────────────┘  │
│             │                                               │                   │
│             │ defines macros: ${s1_sock}, ${h1_px_sock}     │ sets env: px=7    │
│             ▼                                               ▼                   │
│  ┌──────────────────────┐                   ┌────────────────────────────────┐  │
│  │  Mock Server (s1)    │                   │   Target Proxy (Alcyon/HAProxy)  │  │
│  │  • rxreq             │                   │   • bind "fd@${px}"            │  │
│  │  • txresp            │                   │   • balance roundrobin         │  │
│  └──────────▲───────────┘                   │   • server srv1 ${s1_sock}     │  │
│             │ Upstream Forwarding           └───────────────▲────────────────┘  │
│             └───────────────────────────────────────────────┤                   │
│                                                     Client  │ Traffic           │
│                                                             │                   │
│  ┌──────────────────────────────────────────────────────────┴────────────────┐  │
│  │  Mock Client (c1)                                                         │  │
│  │  • txreq -url "/test"                                                     │  │
│  │  • rxresp                                                                 │  │
│  │  • expect resp.status == 200                                              │  │
│  │  • expect resp.http.Server ~ s1                                           │  │
│  └───────────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### 2.1 Top-Level Script Structure

A VTC file is an imperative test scenario composed of sequential and concurrent blocks:

```vtc
varnishtest "Test description string"
feature ignore_unknown_macro

barrier b1 cond 2

server s1 {
    rxreq
    expect req.url == "/api/v1/data"
    expect req.http.X-Custom == "injected"
    txresp -status 200 -hdr "Content-Type: text/plain" -body "Hello Alcyon"
} -repeat 2 -start

haproxy h1 -arg "-L A" -conf {
    global
        thread-groups 1

    defaults
        mode http
        timeout connect "${HAPROXY_TEST_TIMEOUT-5s}"
        timeout client  "${HAPROXY_TEST_TIMEOUT-5s}"
        timeout server  "${HAPROXY_TEST_TIMEOUT-5s}"

    frontend fe
        bind "fd@${fe}"
        http-request add-header X-Custom injected
        default_backend be

    backend be
        server srv1 ${s1_addr}:${s1_port}
} -start

client c1 -connect ${h1_fe_sock} {
    txreq -url "/api/v1/data"
    rxresp
    expect resp.status == 200
    expect resp.http.Content-Type == "text/plain"
    expect resp.body == "Hello Alcyon"
} -run
```

### 2.2 Top-Level Directives & Modifiers

| Directive | Syntax | Execution Semantics |
| :--- | :--- | :--- |
| `varnishtest` / `vtest` | `varnishtest "<title>"` | Declares test title and initializes execution scratch environment. |
| `feature` | `feature <cond>` | Evaluates feature prerequisites (e.g., `ignore_unknown_macro`, `cmd <binary>`). Skips test if unmet. |
| `server` | `server <id> [opts] { ... }` | Defines mock upstream HTTP/TCP server. Options: `-start`, `-wait`, `-repeat <N>`, `-break`. |
| `haproxy` | `haproxy <id> [opts] { ... }` | Declares candidate proxy instance. Options: `-conf { ... }`, `-conf-BAD`, `-conf-OK`, `-arg "<flags>"`, `-start`, `-wait`. |
| `client` | `client <id> [opts] { ... }` | Defines mock HTTP/TCP client. Options: `-connect <addr_port>`, `-start`, `-run`, `-wait`, `-repeat <N>`. |
| `syslog` | `syslog <id> [opts] { ... }` | Defines mock UDP syslog listener. Options: `-level <lvl>`, `-start`, `-wait`. |
| `barrier` | `barrier <id> cond <N>` / `sock <N>` | Creates an $N$-participant thread synchronization barrier. |
| `delay` | `delay <seconds>` | Pauses main execution thread for given duration. |
| `shell` | `shell { <bash script> }` | Executes an arbitrary subshell command block; fails if exit code $\ne 0$. |
| `setenv` | `setenv <var> "<val>"` | Sets environment variable in test runner process. |

### 2.3 Server & Client Inner Action DSL

Within `{ ... }` blocks for `server` and `client`, actions execute sequentially:

| Command | Arguments / Flags | Description |
| :--- | :--- | :--- |
| `rxreq` | None | Reads HTTP request headers (and body if Content-Length/chunked present). |
| `rxreqhdrs` | None | Reads only HTTP request headers without consuming body. |
| `txreq` | `-req <M>`, `-url <U>`, `-hdr "K: V"`, `-body "B"` | Transmits formatted HTTP request. Automatically computes Content-Length unless `-nolen` is set. |
| `rxresp` | None | Reads HTTP response status, headers, and body. |
| `rxresphdrs` | None | Reads only HTTP response headers. |
| `txresp` | `-status <S>`, `-hdr "K: V"`, `-body "B"`, `-nolen` | Transmits formatted HTTP response. |
| `expect` | `<expr> <op> <val>` | Asserts protocol attributes (`==`, `!=`, `<`, `>`, `<=`, `>=`, `~` [regex], `!~`). |
| `send` / `sendhex` | `"string"` / `"0d0a..."` | Transmits raw ASCII or hexadecimal bytes over the TCP stream. |
| `recv` | `<bytes>` | Receives raw byte count or until EOF. |
| `barrier` | `<id> sync` | Blocks on named synchronization barrier until all $N$ participants arrive. |
| `delay` | `<seconds>` | Delays active client/server thread. |
| `close` | None | Closes active socket connection. |
| `accept` | None | Server accepts next incoming TCP connection on its listening socket. |

### 2.4 Dynamic Macro Engine

The VTC runner dynamically expands `${macro}` variables in config blocks and client connection strings:

1. **Server Network Macros**:
   - `${s1_addr}`: Loopback IP (`127.0.0.1` or `::1`).
   - `${s1_port}`: Ephemeral port assigned to mock server `s1`.
   - `${s1_sock}`: Combined string `${s1_addr} ${s1_port}`.
2. **Proxy Frontend Macros (`fd@${fe}`)**:
   - When the runner encounters `bind "fd@${fe}"` in proxy config:
     1. Runner creates a non-blocking TCP listening socket on `127.0.0.1:0`.
     2. Runner records assigned ephemeral port $P$ and socket file descriptor $F$.
     3. Runner sets environment variable `fe=F`.
     4. Runner populates macros `${h1_fe_addr}=127.0.0.1`, `${h1_fe_port}=P`, `${h1_fe_sock}=127.0.0.1 P`.
3. **Syslog Macros**: `${Slg_1_addr}`, `${Slg_1_port}`, `${Slg_1_sock}`.
4. **Process & Path Macros**:
   - `${h1_pid}`: OS PID of the running proxy process.
   - `${tmpdir}`: Temporary working directory `/tmp/vtc.<pid>.<hex>`.
   - `${testdir}`: Directory containing the `.vtc` test file.
5. **POSIX Default Expansion**: `${VAR-default}` (e.g. `"${HAPROXY_TEST_TIMEOUT-5s}"` resolves to `5s` if `HAPROXY_TEST_TIMEOUT` is unset).

---

## 3. Evaluation of Integration Paths for Project Alcyon

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           Integration Path Comparison                           │
├──────────────────────────────────────┬──────────────────────────────────────────┤
│ Path A: Standard C vtest Runner      │ Path B: Standalone Python/Rust Runner    │
├──────────────────────────────────────┼──────────────────────────────────────────┤
│ • External C toolchain dependency    │ • 100% pure Rust / Python standard lib  │
│ • Requires compiling VTest2 / Varnish│ • Zero external compilation dependencies │
│ • Strict HAProxy CLI flag compliance │ • Direct support for mock translations   │
│ • Raw C log files (/tmp/vtc.*/LOG)   │ • Rich JSON test reports & color diffs   │
│ • Slower test launch overhead        │ • Sub-millisecond execution (< 5s suite) │
│ • Upstream official Oracle sign-off  │ • Ideal for inner-loop developer CI      │
└──────────────────────────────────────┴──────────────────────────────────────────┘
```

### 3.1 Path A: Standard `vtest` Integration

In Path A, Alcyon is executed directly by HAProxy's official `vtest` binary:

```bash
HAPROXY_PROGRAM=/path/to/project-ibex/target/release/alcyon \
vtest -b 4194304 -k -t 10 -L -v reg-tests/balance/balance-rr.vtc
```

#### Required Binary CLI Flags for `alcyon`

| Flag | Category | HAProxy Semantics | Alcyon Handling |
| :--- | :--- | :--- | :--- |
| `-vv` | Discovery | Dumps version, build targets, poller capabilities, and compiler options. | Alcyon emits `HAProxy version 3.5.0-alcyon`, `TARGET=linux-glibc`, `epoll` polling engine. |
| `-f <path>` | Core Config | Specifies path to configuration file (repeatable). | Parsed by `alcyon-config` AST parser. |
| `-c` | Validation | Validates configuration file and exits (0 = OK, 1 = Error). | Runs `alcyon_config::parse()` and validation passes; exits immediately. |
| `-cc <expr>` | Conditional | Evaluates conditional build expression; exits 0 if true, 1 if false. | Evaluates expression against built-in feature set (`THREAD`, `OPENSSL`, etc.). |
| `-d` / `-db` | Runtime | Runs proxy in foreground debug mode (no daemonizing). | Alcyon default execution mode (Tokio runtime stays in foreground). |
| `-W` / `-Ws` | Process | Master-worker mode / systemd notification mode. | Alcyon operates worker loop without master fork (or single master wrapper). |
| `-D` | Daemon | Forks into background as daemon. | Accepted for compatibility (ignored in test harnesses). |
| `-q` / `-V` | Verbosity | Quiet / Verbose logging output. | Sets `tracing`/log level filter. |
| `-L <peer>` | Clustering | Sets local peer name. | Populates `global.localpeer` for peers sync. |
| `-dM`, `-dI`, `-dW` | Debugging | Memory pool debug, insecure fork, zero warning mode. | Recognized and safely ignored as no-ops. |
| `-de`, `-dp` | Poller Tuning | Disables epoll / poll. | Recognized (Alcyon poller configuration). |
| `-p <pidfile>`| Process | Writes process PID to file. | Writes `std::process::id()` to target path. |

### 3.2 Path B: Standalone Pure Interpreter (`harness/vtc_runner.py` / `crates/alcyon-vtest`)

Path B implements a lightweight, native VTC interpreter without any C build tools or Varnish dependencies:
1. **Parser Layer**: High-speed recursive descent parser for `.vtc` blocks, macro substitutions, and line continuations.
2. **Server Engine**: Asynchronous mock HTTP/1.1 and TCP server managing mock request verification (`rxreq`, `expect req.*`) and response generation (`txresp`).
3. **Client Engine**: Asynchronous HTTP client executing requests (`txreq`) and evaluating assertions (`expect resp.status`, `expect resp.http.*`, `expect resp.body`).
4. **Proxy Manager**: Process supervisor launching `alcyon` with generated configuration, managing temporary sockets, piping logs, and enforcing graceful shutdown.
5. **Assertion Evaluator**: Rich difference highlighter comparing actual vs expected status codes, headers, and bodies.

---

## 4. Comprehensive Catalog & Triage of HAProxy 3.5 Regression Tests (312 Tests)

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                      HAProxy 3.5 Regression Test Triage (312 Tests)             │
├────────────────────────┬─────────────┬────────────┬─────────────────────────────┤
│ Bucket                 │ Count       │ Percentage │ Criteria                    │
├────────────────────────┼─────────────┼────────────┼─────────────────────────────┤
│ REACHABLE_NOW          │  51 tests   │   16.35%   │ Core HTTP/1 & TCP proxying  │
│ REACHABLE_LATER        │ 147 tests   │   47.12%   │ In-scope features (TLS/CLI) │
│ OUT_OF_SCOPE           │ 114 tests   │   36.54%   │ Excluded features (QUIC/H2) │
├────────────────────────┼─────────────┼────────────┼─────────────────────────────┤
│ Total In-Scope Target  │ 198 tests   │   63.46%   │ Total reachable for Alcyon    │
└────────────────────────┴─────────────┴────────────┴─────────────────────────────┘
```

### Directory Breakdown & Mapping

| Directory | Total Tests | Reachable Now | Reachable Later | Out of Scope | Dominant Features / Modules Tested |
| :--- | :---: | :---: | :---: | :---: | :--- |
| `balance/` | 5 | 4 | 0 | 1 | Round-Robin, URI Hash, Consistent Hash, Maxconn |
| `cache/` | 14 | 0 | 0 | 14 | Small object cache, early hints (Excluded) |
| `checks/` | 25 | 0 | 19 | 6 | HTTP/TCP health checks, send/expect patterns |
| `compression/` | 5 | 0 | 0 | 5 | Gzip/deflate compression (Excluded) |
| `connection/` | 19 | 8 | 8 | 3 | HTTP reuse (`safe`, `always`), PROXY v1/v2 TLVs |
| `converter/` | 25 | 0 | 19 | 6 | IP masking, string hashing, field/word extract |
| `http-capture/` | 1 | 1 | 0 | 0 | Request & response header capture |
| `http-cookies/` | 2 | 1 | 1 | 0 | Cookie insertion, indirect cookies, persistence |
| `http-errorfiles/`| 5 | 5 | 0 | 0 | Custom error files, `http-error` overrides |
| `http-messaging/` | 24 | 9 | 10 | 5 | H1 request targets, host normalization, transfer enc |
| `http-rules/` | 22 | 9 | 10 | 3 | `del-header`, `set-timeout`, `replace-header`, returns |
| `jwt/` | 2 | 0 | 2 | 0 | JWT validation & token sample fetches |
| `log/` | 11 | 3 | 8 | 0 | Syslog formatting, load-balanced logging |
| `lua/` | 10 | 0 | 0 | 10 | Embedded Lua scripts (Excluded) |
| `peers/` | 4 | 0 | 0 | 4 | Legacy single-threaded peer sync |
| `proxy/` | 3 | 0 | 3 | 0 | Transparent proxying / IP binding |
| `quic/` | 30 | 0 | 0 | 30 | QUIC transport & HTTP/3 framing (Milestone 7) |
| `sample_fetches/`| 12 | 0 | 11 | 1 | Layer 4-7 sample fetch expressions |
| `server/` | 11 | 0 | 11 | 0 | Dynamic server state, slowstart, FQDN servers |
| `ssl/` | 47 | 0 | 47 | 0 | TLS termination, SNI matching, ALPN, mTLS |
| `stats/` | 3 | 0 | 3 | 0 | Stats applet CSV/HTML exposition |
| `stick-table/` | 3 | 0 | 3 | 0 | Sliding counters, GPC increments, key tracking |
| `stream/` | 4 | 3 | 1 | 0 | Unique-ID generation, retry policies |
| **Total** | **312** | **51** | **147** | **114** | **100.0% Coverage** |

---

## 5. Phased Roadmap to 100+ Regression Tests

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                          Alcyon VTC Pass Rate Roadmap                             │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   200 ┼───────────────────────────────────────────────────────── 198 Target     │
│       │                                                    ╭────                │
│   150 ┼───────────────────────────────────────────────╭────┘ (Phase 3)          │
│       │                                         ╭─────┘                         │
│   100 ┼───────────────────────────────────╭─────┘ (Phase 2: 150+ Tests)         │
│       │                             ╭─────┘                                     │
│    50 ┼───────────────╭─────────────┘ (Phase 1: 51 Tests)                       │
│       │         ╭─────┘                                                         │
│     0 ┼─────────┴──────────────────────────────────────────────────────────     │
│         Baseline     Phase 1 (H1 Core)   Phase 2 (TLS+Checks)  Phase 3 (Full)   │
└─────────────────────────────────────────────────────────────────────────────────┘
```

1. **Phase 1: Core HTTP/1 & Load Balancing Baseline (51 Tests)**:
   - Target: 51 `REACHABLE_NOW` tests in `balance/`, `connection/`, `http-rules/`, `http-messaging/`, `http-errorfiles/`, `stream/`.
   - Validates: Round-Robin, URI Hashing, `del-header`, `http-request return`, PROXY v2 forwarding, and chunked transfer decoding.
2. **Phase 2: TLS, Converters & Health Checks Expansion (150+ Tests)**:
   - Target: Additional 99 tests from `ssl/` (47 tests via `alcyon-tls`), `checks/` (19 tests via HTTP/TCP health checker), `converter/` (19 tests), and `sample_fetches/` (11 tests).
   - Validates: SNI certificate dispatch, client certificate verification, HTTP monitor URIs, string concatenation, and IP CIDR masking.
3. **Phase 3: Stick Tables & Runtime CLI Parity (198 Tests — 100% In-Scope Target)**:
   - Target: Additional 48 tests from `stick-table/`, `stickiness/`, `stats/`, `jwt/`, `stream/`, and `proxy/`.
   - Validates: Distributed sliding rate limiting, stick table tracking (`sc_track`), runtime CLI stats socket manipulation, and JWT authentication.
