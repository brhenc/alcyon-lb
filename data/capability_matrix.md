# Alcyon Capability Matrix

Audit conducted: 2026-09-22  
Oracle: HAProxy reference binary (`haproxy` 3.5-dev7 @ `e6f616a`) and Project Alcyon codebase.  
Governing specification: `nudge-agy-4.md` (Item 4).

---

## 1. Overview & Evaluation Methodology

This capability matrix records what Project Alcyon can actually perform end to end. As identified in `nudge-agy-4.md`, static line counts and isolated unit tests can be deceptive: thousands of lines of protocol implementation may exist in library crates without being reachable from the runtime data path.

### Evaluation Criteria

- **Implemented**: The code exists in the repository, compiles, and passes unit/module-level tests.
- **Reachable from the daemon**: A client connecting to a configured listener (or an operator interacting with the configured CLI / admin endpoints) can exercise the capability through the live runtime engine (`alcyon-rt`). Code that exists solely as an internal library or is unwired from `alcyon-rt` is marked **No**.
- **Tested end to end**: Automated integration tests exercise the full path from listener accept through protocol handling/routing to backend response or administrative completion.
- **Declined (out of scope)**: Features explicitly excluded by architectural decision (`tradeoff.md` §4.2) to maintain project focus and tractability, rather than being missing or incomplete.

---

## 2. Capability Matrix

| Capability | Implemented | Reachable from the daemon | Tested end to end | Notes |
|---|---|---|---|---|
| **HTTP/2 Core & Multiplexing** (`h2.rs`, `mux_h2.rs`) | Yes | Yes | Yes | Fully wired into `alcyon-rt` data path over TLS ALPN (`h2`) and cleartext connection preface. Supports preface exchange, initial SETTINGS negotiation, HPACK header compression, stream multiplexing, and response generation from HTX. Verified end to end over TLS in `tls_e2e.rs` (`h2_is_served_over_tls_end_to_end`) and loopback socket conformance suite in `http2_conformance.rs`. Restored `+H2` in `-vv` banner. |
| **HTX Stream Representation** (`htx.rs`) | Yes | Yes (Stage 0) | Yes | Unified flat borrowed representation (`HtxSlice<'a>` / `HtxSliceRef<'a>`). `HtxBuffer` is ownership-only wrapper. Zero-allocation parser verified (`parsing_a_request_into_htx_allocates_nothing` passes with 0 allocs). Data path uses pooled `Buf` backing for HTX; `HtxBuffer::with_capacity` and `to_h1_wire` eliminated to 0 allocs on the data path. |
| **HAProxy C FFI Differential Oracle (T16)** | Yes (feature `haproxy-ffi`) | Off by default | Yes | Differential parser testing between `alcyon-proto` H1 parser and reference HAProxy C parser (`h1.c` + `http.c` compiled via `alcyon-h1-sys` with safe C wrapper and C stub). Normalized differential suite in `haproxy_ffi_differential.rs` normalises 3 structural artifacts (header-block length, pseudo-headers, Eom), verifies framing agreement, matches obs-fold whitespace runs, and pins genuine Content-Length deduplication/normalization behaviors. |
| **HTTP/1.1 Reverse Proxying** | Yes | Yes | Yes | Keep-alive reuse (50+ sequential requests), pipelining, chunked transfer encoding, method dispatch, and RFC 9112 framing conflict enforcement. Verified in `http1_conformance.rs` and `http_proxy.rs`. |
| **Backend Connection Reuse (`http-reuse`)** | Yes | Yes | Yes | Shared idle connection pool across sessions (`http-reuse never|safe|aggressive|always`). Idle sockets are verified via non-blocking zero-copy socket peek (`raw::is_idle_conn_alive`) before reuse. Tested in `http_proxy.rs` (`http_reuse_shares_backend_connection_across_sessions` and `http_reuse_never_does_not_share_backend_connection`). |
| **HTTP/1.0 Fallback** | Yes | Yes | Yes | Close-delimited framing and HTTP/1.0 connection header defaults. Tested in `http1_conformance.rs`. |
| **L4 TCP Proxying (Non-splice)** | Yes | Yes | Yes | Safe user-space buffer proxying (`Buf`). Half-close propagation (`shutdown(Write)`), backpressure signalling via epoll interests, inspect-delay, connect retries, and timeouts. Tested in `tcp_proxy.rs`. |
| **L4 TCP Zero-Copy Splicing (`splice`)** | No | No | No | Linux `splice(2)` pipe zero-copy proxying is not implemented; proxying operates via user-space ring buffers under `#![forbid(unsafe_code)]`. Spliced byte counters exist for CSV schema parity only. |
| **TCP Request Rules (`tcp-request`)** | Yes | Yes | Yes | Connection, session, and content-level inspection rules with `inspect-delay`. Distinct handling of `reject` (active TCP RST via `SO_LINGER 0`) versus `silent-drop` (quiet drop via `IP_TTL = 1` / `SO_LINGER 0`). Verified in `tcp_request_rules.rs`, `tcp_request_tracking.rs`, and `tcp_proxy.rs`. |
| **Content Switching (`use_backend`, `default_backend`)** | Yes | Yes | Yes | Dynamic backend routing based on ACL condition evaluation (`if` / `unless`) and default fallbacks. Tested in `content_switching.rs` and `canonical_haproxy_35_e2e.rs`. |
| **Load Balancing: Round-Robin** | Yes | Yes | Yes | Cyclic distribution across active, healthy servers. Respects server state and backup failover. Tested in `content_switching.rs` and `canonical_haproxy_35_e2e.rs`. |
| **Load Balancing: Source IP Hash** | Yes | Yes | Yes | Consistent IPv4/IPv6 hashing (`balance source`). Integrates with PROXY protocol parsed client address (`src`). Tested in `content_switching.rs` and `proxy_protocol.rs`. |
| **Load Balancing: URI Hash** | Partial | Yes | No | Parsed by `alcyon-config`, but `engine.rs:select_server_with_key` falls through to round-robin (`_ => self.select_server()`). No sticky URI hashing test exists. |
| **Load Balancing: `static-rr`, `first`, `leastconn`** | No | No | No | Unimplemented algorithms are rejected at configuration parse time (`unknown balance algorithm <algo>` in `alcyon-config/src/parser.rs:1228`) adhering to Rule 5. |
| **Backup Server Failover (`backup`)** | Yes | Yes | Yes | Primary servers prioritized when available; automatic failover to `backup` servers when all active primaries are down or in maintenance. Tested in `canonical_haproxy_35_e2e.rs`. |
| **Stick Table Engine** (`alcyon-stick-table`) | Yes | Yes | Yes | `EbMbTree`-indexed memory tables supporting IPv4/IPv6 (`ip`), integer (`integer`), string (`string`), and binary (`binary`) keys with TTL expiration. Tested in `stick_table.rs`. |
| **Stick Table Counters & Metrics** | Yes | Yes | Yes | Tracks `conn_cnt`, `conn_cur`, `conn_rate`, `sess_cnt`, `sess_rate`, `http_req_cnt`, `http_req_rate`, `http_err_cnt`, `http_err_rate`, `bytes_in/out_cnt/rate`, `gpc0`, `gpc1`, `gpt0`, `server_id`. |
| **Stick Actions (`track-sc*`, `sc-inc-gpc*`, `sc-set-gpt0`)** | Yes | Yes | Yes | Rule actions evaluated across connection, session, content, and HTTP scopes. Verified in `canonical_haproxy_35_e2e.rs`, `tcp_proxy.rs`, and `tcp_request_tracking.rs`. |
| **Stick Table CLI Dumps (`show table`)** | Yes | Yes | Yes | UNIX socket CLI inspection with table name arguments and data filters (`data.gpc0 gt 0`, `data.conn_cnt`, etc.). Tested in `stick_table.rs` and `tcp_proxy.rs`. |
| **ACL Evaluation & Matchers** | Yes | Yes | Yes | Path matchers (`path`, `path_beg`, `path_end`, `path_sub`, `path_reg`, `path_dir`), IP matchers (`src`, `dst`, `fc_src`, `fc_dst`), headers (`hdr(...)`), payload byte inspection (`req.payload`). Tested in `sample_semantics.rs` and `tcp_request_rules.rs`. |
| **Sample Fetches & Converters** | Yes | Yes | Yes | Over 570 sample fetches registered (`alcyon-sample`). String, hex, base64, and arithmetic converters. `match_map` caching (`CachedMapTable`) implemented to eliminate per-request disk I/O and heap re-parsing (`tradeoff.md` §6.6). Tested in `sample_semantics.rs`, `proptest_expr.rs`, and `logfmt.rs`. |
| **TLS Termination via Rustls** | Yes | Yes | Yes | Modern TLS 1.2 and TLS 1.3 server-side termination using Rustls under `#![forbid(unsafe_code)]`. SNI resolution, ALPN (`http/1.1`), PEM bundle loading. Tested in `tls_e2e.rs` and `tls_xprt.rs`. Fails closed if certificates are invalid or missing. |
| **Backend Outbound TLS** | Partial | No | No | Inbound termination is complete; outbound client TLS to backend servers (`server ... ssl`) is not wired in the runtime connection pool. |
| **PROXY Protocol v1 (Receive & Send)** | Yes | Yes | Yes | Parses inbound `PROXY TCP4/TCP6` lines (`accept-proxy`) and generates outbound v1 headers (`send-proxy`). Tested in `proxy_protocol.rs`. |
| **PROXY Protocol v2 (Receive & Send)** | Yes | Yes | Yes | 16-byte binary header parsing (`accept-proxy`) and generation (`send-proxy-v2`), IPv4/IPv6/UNIX addresses, CRC32c wire validation, and TLV forwarding. Tested in `proxy_protocol.rs` and `canonical_haproxy_35_e2e.rs`. |
| **Health Checking: TCP Check** | Yes | Yes | Yes | Non-blocking periodic TCP probes executed in scheduler. Rise/fall counter state machine (`0..=rise+fall-1`) matching HAProxy `src/check.c`. Tested in `health_check.rs` and `stats_admin_sessions.rs`. |
| **Health Checking: HTTP Check** | Partial | Yes | Yes | Client-facing synthetic health responder (`monitor-uri` / synthetic health responses returning HTTP 200 `OK\n`) tested in `canonical_haproxy_35_e2e.rs`. Outbound active HTTP probe (`option httpchk`) is not implemented. |
| **Server Admin States (READY, DRAIN, MAINT)** | Yes | Yes | Yes | Dynamic operational state transitions via CLI and Web UI. Tested in `stats_admin_sessions.rs` and `stats_web_admin.rs`. |
| **Dynamic Server Weight & Session Shutdown** | Yes | Yes | Yes | Live weight adjustment (`set server ... weight <N>`) and connection termination (`shutdown sessions server ...`). Tested in `stats_admin_sessions.rs` and `stats_web_admin.rs`. |
| **Stats CSV Engine (`/stats;csv`, `show stat`)** | Yes | Yes | Yes | Byte-for-byte structural parity with HAProxy 3.5 reference binary: exactly 146 positional CSV fields (including `h2_*`, `ssl_*`, `h1_*` columns). Tested in `hatop_compat.rs` and `stats_csv_schema.rs`. |
| **Web Admin UI (`/stats`)** | Yes | Yes | Yes | Embedded dark-mode HTML dashboard with live metrics, health status badges, and interactive admin control forms. Tested in `stats_web_admin.rs`. |
| **Runtime CLI Socket & Hatop Compatibility** | Yes | Yes | Yes | UNIX domain socket supporting interactive mode (`prompt`), `show info` (all 14 mandatory regex keys required by Hatop 0.8.3), `show stat`, `show table`, `set server ...`, `clear counters all`. Tested in `hatop_compat.rs` and `cli_applet.rs`. |
| **Syslog Logging & Log Formatting** | Yes | Yes | Yes | UDP and UNIX datagram emission. RFC 5424 and RFC 3164 (space-padded days, facility*8 + severity priority calculation). Unified `log-format` engine with `%[...]` sample expansion. Tested in `syslog.rs` and `logfmt.rs`. |
| **Pool Allocator & Size Classes** | Yes | Yes | Yes | Thread-local size-class pool (`tune.bufsize.small`: 1024, `tune.bufsize`: 16384, `tune.bufsize.large`: opt-in 3 preallocated/thread). Automatic small-to-standard buffer promotion on overflow without truncation. Unified architecture in `buf.rs` backed by decoupled `alcyon-alloc` registry with compile-time `&'static str` names. Data-path buffer reuse achieved: `buf::alloc_standard` achieves 0 allocations per steady-state request. Tested in `cli_applet.rs`, `buf.rs`, and `request_allocations.rs`. |
| **Allocation Oracle & Hot-Path Bounds** | Yes | Yes | Yes | Global `CountingAllocator` and snapshot diff API in `crates/alcyon-alloc` and `tools/allocprofile`. Pooled `Buf` lifecycle verified at **0 allocations, 0 deallocations**. Steady-state HTTP request allocations reduced from 16 allocs (25,038 bytes) to 5 allocs (124 bytes per `allocprofile`, 6 allocs / 186 bytes in test harness). `HtxBuffer::with_capacity` (was 16 KB) and `to_h1_wire` (was 8 KB) eliminated to 0 allocations. Bound pinned to <= 10 allocs, <= 500 bytes. 60,000 backends measured at 14.00 MB resident (vs HAProxy's 207 MB), pinned to <= 20 MB. Tested in `tcp_proxy.rs` and `request_allocations.rs`. |
| **QUIC / HTTP/3** | Declined (out of scope) | No | No | Explicitly excluded by design decision (`tradeoff.md` §4.2). Marked permanently `OUT_OF_SCOPE` in reg-test triage (`data/regtests.json`). |
| **Generic Filters (FLT)** | Declined (out of scope) | No | No | Explicitly excluded by design decision (`tradeoff.md` §4.2). |
| **Lua Scripting Engine (`hlua`)** | Declined (out of scope) | No | No | Explicitly excluded by design decision (`tradeoff.md` §4.2) to maintain a tractable, high-assurance codebase. |
| **Stream Processing Offload Engine (SPOE)** | Declined (out of scope) | No | No | Explicitly excluded by design decision (`tradeoff.md` §4.2). |
| **FastCGI (FCGI)** | Declined (out of scope) | No | No | Explicitly excluded by design decision (`tradeoff.md` §4.2). |
| **HTTP Cache Applet / Subsystem** | Declined (out of scope) | No | No | Explicitly excluded by design decision (`tradeoff.md` §4.2). |

---

## 3. Detailed Audit Findings & Citations

### 3.1 HTTP/2 & Multiplexing (`h2.rs` + `mux_h2.rs`)
- **Codebase Inventory**: `crates/alcyon-proto/src/h2.rs` (1,734 lines) and `crates/alcyon-proto/src/mux_h2.rs` (748 lines), totalling **2,482 lines**.
- **Implementation Scope**: Full connection preface detection (`H2_CONN_PREFACE`), SETTINGS frame negotiation, HPACK dynamic table encoder/decoder, frame parser for DATA, HEADERS, PRIORITY, RST_STREAM, SETTINGS, PING, GOAWAY, and WINDOW_UPDATE, plus stream-level and connection-level flow control.
- **Reachability & Integration**: Fully integrated into the `alcyon-rt` runtime data path. Cleartext and TLS ALPN negotiation (`h2`) dynamically initialize `H2MuxContext` in `TcpSession`. Decrypted TLS and TCP client streams are fed into `MuxH2.parse`, extracting request line/headers into HTX and wire buffers for backend routing, and encoding backend responses into HTTP/2 HEADERS and DATA frames.
- **Test Coverage**: Tested end to end over TLS in `crates/alcyon-rt/tests/tls_e2e.rs` (`h2_is_served_over_tls_end_to_end`) and loopback socket conformance suite in `crates/alcyon-rt/tests/http2_conformance.rs`. Extended version banner restored `+H2`.

### 3.2 HTX Intermediate Representation (`htx.rs`)
- **Codebase Inventory**: `crates/alcyon-proto/src/htx.rs` (2,300+ lines).
- **Implementation Scope**: Pure safe Rust implementation of HAProxy's flat circular HTX buffer with header/data block indexing, in-place compaction/defragmentation (`defrag`), and proptest-based differential fuzzing.
- **Stage 0 Unification & Zero-Allocation Buffer Pooling**:
  - Unified on the borrowed flat buffer representation: `HtxSlice<'a>` and `HtxSliceRef<'a>`.
  - `HtxBuffer` refactored to ownership-only wrapper (`Vec<u8>`), eliminating duplicate block logic and delegating all mutations via `with_slice_mut`.
  - Seam signature unified: `HttpStream::parse(&mut self, input: &[u8], htx: &mut HtxSlice<'_>) -> io::Result<usize>` and `finish(&mut self, htx: &mut HtxSlice<'_>)`.
  - Zero-allocation parsing verified by `crates/alcyon-proto/tests/htx_allocation.rs` (`parsing_a_request_into_htx_allocates_nothing` passes with **0 allocations and 0 bytes allocated**).
  - Runtime request validation in `crates/alcyon-rt/src/proxy.rs:388` (`validate_request_head`) runs over `HtxSlice` backed by pooled `Buf` (`Buf::standard()`), eliminating `HtxBuffer::with_capacity` (was 16,384 B) and `HtxBuffer::to_h1_wire` (was 8,192 B) to **0 allocations** on the data path.
  - Zero-copy header inspection: `HtxSliceRef::headers` provides borrowed `(&str, &str)` slices directly into the buffer, eliminating heap string recreation.
- **Architectural Status**: Stage 0 complete per `nudge-agy-htx.md` and `nudge-agy-7.md`. Ready for Stage 1 (`mux_h1` full HTX stream generation on ingress).

### 3.3 Memory Allocation, Size Classes & Soft-Realtime Discipline
- **Status**: Implemented, reachable, and tested under Nudge 4, Nudge 5, Nudge 6, and Nudge 7.
- **Current State**:
  - Global `CountingAllocator` and snapshot diff API implemented in `crates/alcyon-alloc` (isolated safe interface wrapping `System` under `#![allow(unsafe_code)]` solely for the `GlobalAlloc` trait).
  - Profiling crate `tools/allocprofile` captures and ranks allocations by call site for steady-state HTTP requests.
  - Data-path buffer reuse achieved: `buf::alloc_standard` allocations dropped from 2 allocs (32,768 bytes) to **0 allocations, 0 bytes** per request by timely session cleanup and buffer release before subsequent requests accept.
  - Poller event buffer reuse: `Poller::poll` per-call allocations dropped from 8 allocs (6,144 bytes) to **0 allocations, 0 bytes** per request by storing a reusable `epoll::EventVec` on `Poller`.
  - Backend connection dispatch optimization: `connect_http_backend` allocations dropped from 41 allocs (741 bytes) to **0 allocations, 0 bytes** through borrowed timeout slices (`&'static str`), borrowed rule slices, and avoiding empty rule cloning.
  - Response processing fast-path: `apply_http_response_rules` dropped from 22 allocs (610 bytes) to **0 allocations, 0 bytes** when no response rules are configured, using borrowed UTF-8 string scanning for `Connection: close`.
  - HTX buffer pooling optimization: `HtxBuffer::with_capacity` (was 16 KB) and `HtxBuffer::to_h1_wire` (was 8 KB) dropped to **0 allocations, 0 bytes**.
  - Overall steady-state request allocation profile dropped to **5 allocations (124 bytes)** in `tools/allocprofile` (6 allocations, 186 bytes in test harness).
  - Pinned allocation ceiling tests updated in `crates/alcyon-rt/tests/request_allocations.rs`:
    - Steady-state TCP connection: measured **0 allocs, 0 bytes**; bound pinned to `<= 5`.
    - Steady-state HTTP request: measured **6 allocs, 186 bytes**; bound lowered from 25 to `<= 10` allocs, `<= 500` bytes.
    - ACL + log-format request: measured **6 allocs, 186 bytes**; bound lowered from 25 to `<= 10` allocs, `<= 500` bytes.
    - 60,000 backends without checks: measured **14.00 MB** (14,684,947 cumulative allocated bytes, ~245 bytes/server vs HAProxy's 207 MB / 3,456 bytes/server), pinned to `<= 20 MB`.
    - 60,000 backends with active health checks: measured **29.75 MB** (31,196,612 cumulative allocated bytes, 120,035 allocations, ~520 bytes/server), pinned to `<= 35 MB`.
  - Zero-allocation pooled buffer lifecycle: `alloc_count` and `dealloc_count` verified at **0** for warm `Buf::with_capacity(BUFSIZE)`.
  - Lock-free, zero-contention data path: freelists backed by `thread_local!` caches per thread rather than global mutex locks.
  - Decoupled `PoolRegistry`: `PoolHead.name: &'static str`, registry accessed only when querying statistics via `show pools` or diagnostics rather than on stream buffer acquisition or release.
  - Three configurable size classes implemented per HAProxy 3.5:
    - `tune.bufsize` (default 16384): rounded up to multiple of 16, must be >= 16384 if HTTP/2 configured, < 256MB.
    - `tune.bufsize.small` (default 1024): automatic promotion path to standard buffer on overflow without truncation.
    - `tune.bufsize.large` (off by default): preallocates 3 large buffers per thread when configured.
  - Boundary enforcement: HTTP header block exceeding `tune.bufsize - tune.maxrewrite` produces HTTP 400 on request and HTTP 502 on response. Tested below, at, and above threshold in `crates/alcyon-rt/tests/tcp_proxy.rs`.
  - Single unified pool architecture: dead `Pool<T>` index arena removed from `alcyon-alloc`, single implementation in `crates/alcyon-rt/src/buf.rs`.
  - Scratch-buffer string formatting implemented in `logfmt.rs` (`render_into`, `write_alias`) eliminating per-log heap churn.
  - `match_map` caching (`CachedMapTable`) implemented in `alcyon-sample/src/registry.rs`, completely eliminating per-request file reads and string re-parsing.
  - `show pools` CLI command wired to `dump_pools_info()` in `crates/alcyon-rt/src/applet.rs` for live HAProxy-compatible memory pool inspection with configured size classes.

### 3.4 HAProxy C FFI Differential Oracle (T16)
- **Status**: Implemented behind default-off Cargo feature `haproxy-ffi`.
- **Implementation Scope**:
  - `crates/alcyon-h1-sys`: compiles HAProxy 3.5 `h1.c` and `http.c` from reference tree with a ~50-line C stub (`stub.c`) for missing engine symbols.
  - Safe Rust FFI wrapper (`alcyon_h1_sys::parse_h1`) encapsulates all unsafe raw pointer arithmetic.
  - `alcyon-proto/src/ffi_h1.rs`: implements `HaproxyFfiParser` and `HaproxyFfiStream` conforming to `HttpParser` and `HttpStream` over `HtxSlice`.
  - Comprehensive differential test suite in `crates/alcyon-proto/tests/haproxy_ffi_differential.rs` comparing parsing results across 20 test vectors.
  - Structural normalisation implemented and documented: header-block length comparison (ignoring body/chunk framing), pseudo-header filtering (`:method`, `:path`, etc.), and `Eom` block equivalence.
  - `obs-fold` whitespace run preservation verified matching HAProxy 3.5 (`"foo\r\n bar"` -> `"foo   bar"`).
  - Pinned exact surviving Content-Length deduplication/normalization behaviors (`duplicate_cl_agreeing`, `comma_cl_agreeing`).
- **Reachability**: Reachable when compiled with `--features haproxy-ffi`. Verified framing agreement and cataloged differential nuances.


### 3.5 Explicitly Declined Subsystems (`tradeoff.md` §4.2)
Per project architectural records, the following HAProxy subsystems have been formally declined:
1. **QUIC / HTTP/3**: Excluded due to kernel UDP scaling requirements and complexity.
2. **Filters (FLT)**: Excluded to eliminate indirect function pointer loops (NASA JPL Rule 1).
3. **Lua Scripting (`hlua`)**: Excluded (~14,000 lines of C runtime) to avoid non-deterministic garbage collection and unbounded execution times.
4. **SPOE**: Excluded in favor of direct proxy pipelines.
5. **FCGI**: Excluded; backend communication standardized on HTTP and TCP.
6. **HTTP Cache**: Excluded to maintain stateless soft-realtime proxying invariants.

In `data/regtests.json`, all HAProxy regression tests targeting these subsystems are categorized as `OUT_OF_SCOPE`.

### 3.6 Audited Production Capabilities
1. **L4 TCP Proxying**: Buffer-based user-space copy. Splice is not implemented. Half-close, inspect-delay deadlines, early wakeups, and poller backpressure are verified in `crates/alcyon-rt/tests/tcp_proxy.rs`.
2. **HTTP/1.1 Reverse Proxying**: RFC 9112 conformance, chunked streaming, keep-alive reuse, and pipelining verified in `crates/alcyon-rt/tests/http1_conformance.rs` and `canonical_haproxy_35_e2e.rs`.
3. **Content Switching**: `use_backend` with ACL conditions (`if`/`unless`) and `default_backend` verified in `crates/alcyon-rt/tests/content_switching.rs`.
4. **Load Balancing**: `roundrobin` and `source` hash algorithms fully implemented and verified in `crates/alcyon-rt/tests/content_switching.rs`. `uri` is accepted by parser but falls back to round-robin. Other algorithms (`static-rr`, `first`, `leastconn`) are safely rejected by the parser adhering to Rule 5.
5. **Stick Tables & Metrics**: Full metric suite (`conn_*`, `http_req_*`, `gpc0`, `gpt0`) with sliding-window rate tracking and `show table` CLI filters verified in `crates/alcyon-rt/tests/stick_table.rs` and `tcp_request_tracking.rs`.
6. **ACL Evaluation**: Matchers (`path_beg/end/sub/reg`, `src`, `fc_src`, `hdr`, `req.payload`) and 570+ fetches verified in `crates/alcyon-rt/tests/tcp_request_rules.rs` and `crates/alcyon-sample/tests/sample_semantics.rs`.
7. **TLS Termination**: Rustls-backed server termination with fail-closed certificate verification and ALPN negotiation verified in `crates/alcyon-rt/tests/tls_e2e.rs` and `tls_xprt.rs`.
8. **PROXY Protocol**: Text v1 and binary v2 reception and outbound generation, with CRC32c checksum validation, verified in `crates/alcyon-rt/tests/proxy_protocol.rs`.
9. **Health Checking**: TCP connect health checking with rise/fall counter state machine matching HAProxy `src/check.c` verified in `crates/alcyon-rt/tests/health_check.rs`. Synthetic HTTP health responder verified in `canonical_haproxy_35_e2e.rs`. Outbound `option httpchk` is not implemented.
10. **Server Admin States**: READY, DRAIN, MAINT states, dynamic weight changes, and session shutdown verified in `crates/alcyon-rt/tests/stats_admin_sessions.rs`.
11. **Web Admin UI & Stats CSV**: Embedded HTML dashboard and exact 146-field CSV output matching live HAProxy binary verified in `crates/alcyon-rt/tests/stats_web_admin.rs` and `hatop_compat.rs`.
12. **CLI Socket & Hatop Compatibility**: Interactive UNIX socket CLI matching all Hatop 0.8.3 required regexes verified in `crates/alcyon-rt/tests/hatop_compat.rs` and `cli_applet.rs`.
13. **Syslog Engine**: RFC 5424 / RFC 3164 datagram formatting with unified sample-based `log-format` verified in `crates/alcyon-rt/tests/syslog.rs` and `logfmt.rs`.

---

## 4. Maintenance Rule

Per `nudge-agy-4.md`: **A row in this matrix must change in the same commit as the behaviour it describes.**  
Any capability marked "Reachable from the daemon: Yes" must be accompanied by an end-to-end integration test exercising the feature through a configured listener or control endpoint.
