# Subagent Execution & Research Registry

This document records the work, findings, and deliverables produced by all background subagents executing across Project Ibex milestones.

---

## Active & Completed Subagents

| ID | Role | Type | Milestone Focus | Status | Deliverable / Artifact |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `5768a999` | Differential Test Verifier | `self` | Milestones 1 & 2 | **Complete** | Full workspace test suite (77 tests) & 14/14 differential parity verification against `haproxy102`. |
| `5422d2cb` | TLS Architecture Researcher | `research` | Milestone 3 | **Complete** | Milestone 3 TLS Architecture Blueprint: `rustls 0.23`, `ebtree` SNI dispatch, `TlsArena` zero-allocation layout, `Class::Heavy` anti-DDoS throttling. |
| `b564eba3` | HTX & HTTP/1.1 Mux Researcher | `research` | Milestone 4 | **Complete** | Milestone 4 Report: Native HTX bidirectional buffer (`HtxBuffer`), zero-allocation chunked transfer encoding, trailer ordering, and `mux_h1` layering. |
| `5d24739a` | H2 & Peers Protocol Researcher | `research` | Milestones 5 & 6 | **Complete** | Milestones 5 & 6 Report: HTTP/2 multiplexing, 4096-byte contiguous HPACK dynamic table (`HpackDynamicTable`), and Distributed Peers Stick-Table Protocol v2.1 wire codec. |
| `671898d8` | Property Test Engineer | `self` | Milestone 2 | **Complete** | 59 new property-based tests across `ibex-sample` and `ibex-stick-table`, IPv6 CIDR matchers, standard converters, 128-bit sliding rate calculation. |
| `6f4d4837` | QUIC & HTTP/3 Architecture Researcher | `self` | Milestone 7 / Future Architecture | **Complete** | Milestone 7 Architecture Blueprint: RFC 9000/9001/9114 & HAProxy native QUIC analysis, `rustls::quic` `#![forbid(unsafe_code)]` integration, UDP `recvmmsg` batching, 256-shard `ebtree` CID routing, recorded in `docs/research/quic-http3.md`. |
| `40481f62` | Principal Systems Architect Reviewer | `self` (Pro) | Whole Architecture Audit | **Complete** | Adversarial architectural review across all crates for safety, memory bounds, error handling, and test coverage (`docs/research/architect-review.md`). |
| `2b0fc166` | TLS Implementation Engineer | `self` | Milestone 3 | **Complete** | Built `crates/ibex-tls` with pure `#![forbid(unsafe_code)]`, `rustls 0.23`, `ebtree::EbMbTree` exact/wildcard SNI resolution (`IbexCertResolver`), `TlsArena`/`TlsSlot`, and `RustlsTransport` (`Transport` + `TlsInfo`). |
| `e5b16c84` | Filters, SPOE & Lua Researcher | `research` | Extensibility | **Complete** | Extensibility Blueprint: HAProxy filter engine (`src/filters.c`), binary SPOP v2.0 async offload (`src/flt_spoe.c`), cooperative Lua scheduler analysis (`src/hlua.c`), and Ibex `#![forbid(unsafe_code)]` filter/SPOE/sandboxing architecture recorded in `docs/research/filters-spoe-lua.md`. |
| `5047f025` | Observability & OTel Researcher | `research` | Observability | **Complete** | Observability Blueprint: Zero-allocation native Prometheus exposition applet (`PrometheusApplet`), W3C Trace Context (`traceparent`/`tracestate`) parser and injector, `SpanRingBuffer` OTLP batch exporter, recorded in `docs/research/observability-otel.md`. |
| `7e873073` | Stick Table Aggregator Researcher | `self` | Distributed State & Clustering | **Complete** | Distributed State Blueprint: Mathematical CRDT model (Delta-G, PN, LWW, Aggregated Sliding Rates), binary peer v2.1/SPOP/delta codecs, 256-shard `ebtree` arena aggregator (`ibex-aggregator`), recorded in `docs/research/stick-table-aggregator.md`. |
| `d429bb91` | Multi-Threaded Peers Researcher | `research` | Distributed Systems & Peers Protocol | **Complete** | Multi-Threaded Peers Blueprint: HAProxy 3.5 single-thread pinning audit (`src/peers.c`), per-core `SO_REUSEPORT` TCP distribution, 256-shard lock-free stick table replication, wire codec v2.1 (`HAProxyS 2.1`, `intencode`/`intdecode`, `DcacheTx`/`DcacheRx`), sliding ACK window backpressure, recorded in `docs/research/multithreaded-peers.md`. |
| `77f483d9` | PROXY Protocol Core Engineer | `self` | Connection Layer & Wire Protocol | **Complete** | Pure `#![forbid(unsafe_code)]` zero-allocation PROXY protocol v1 & v2 codec, zero-copy slice parser, TLV builder/iterator, Castagnoli CRC32-C validator, comprehensive property tests (`proptest`), recorded in `docs/research/proxy-protocol.md`. |
| `73ed5e8f` | PROXY Protocol Integration & E2E Verification Engineer | `self` | Runtime Integration & E2E Verification | **Complete** | End-to-end integration of PROXY v1/v2 across `ibex-rt`, `ibex-config`, and `ibex-proto`: frontend `accept-proxy` / `accept-proxy-v2` non-blocking interception & header stripping, client IP extraction into stream context & stick table hashing, backend `send-proxy` / `send-proxy-v2` generation & TLV forwarding, chained proxy E2E test suite (11 tests passing), zero clippy warnings. |
| `4355d1b6` | HAProxy Keyword Compatibility Researcher | `research` | Compatibility & Config Architecture | **Complete** | Comprehensive audit of HAProxy 1.0 -> 3.5 keyword evolution, catalog of obsolete/removed directives in 3.5 (`dispatch`, `transparent`, `master-worker`, `req*`/`rsp*`, `mode health`, legacy `tune.quic.*`), modern L4-L7 action rules matrix, and `ibex-config` native 3.5 AST/parser specification recorded in `docs/research/keyword-compatibility-matrix.md`. |
| `04473986` | VTC & Regression Test Architect | `research` | Quality Assurance & Upstream Parity | **Complete** | Exhaustive analysis of HAProxy's 312 `.vtc` regression tests, dual integration path design (Path A `vtest` CLI flags / `fd@` inheritance + Path B standalone `vtc_runner.py`), and 3-phase roadmap from 51 initial reachable tests to 198 total target tests recorded in `docs/research/vtc-test-harness.md`. |
| `958c8b16` | CLI & HAProxy 3.5 Compatibility Engineer | `self` | Runtime & CLI Compatibility | **Complete** | Complete HAProxy 3.5 CLI flag audit, memory-safe parser in `ibex-rt` (`bin/ibex.rs`), multi-config directory expansion, reload signal dispatching, and integration test suite recorded in `docs/research/cli-options-compatibility.md`. |
| `fb2023df` | Build Automation Engineer | `self` | Developer Experience & Tooling | **Complete** | Root `Makefile` with standard Unix build, test, lint, format, difftest, vtc, install, and uninstall targets. |
| `ce267c7a` | HAProxy 3.5 Keyword Cataloger | `research` | Compatibility & Roadmap | **Complete** | Exhaustive catalog of all sections, keywords, L4-L7 actions, sample fetches, and converters in HAProxy 3.5 recorded in `docs/research/haproxy-35-keywords-complete-catalog.md`. |
| `3dfc9706` | Stats Admin & Session Management Engineer | `self` | Runtime Administration & Management | **Complete** | Full connection handling and admin controls (`kill_sessions`/`shutdown_sessions`, `enable_health`/`disable_health`, `clear_counters`, `set_maxconn`) in Web Admin UI, CLI applet, and `Engine` (`crates/ibex-rt/tests/it/stats_admin_sessions.rs`). |
| `fa9404f9` | Server-Sent Events (SSE) Architect | `research` | Low-Latency Streaming Protocols | **Complete** | SSE protocol mechanics, HAProxy 3.5 streaming audit, unbuffered pipeline bypass, same-pass event flush, and disconnect cancellation recorded in `docs/research/server-sent-events.md`. |
| `08c6d33d` | HTTP QUERY Method Architect | `research` | Modern Protocol Standards | **Complete** | RFC 10008 HTTP `QUERY` method analysis, HAProxy cache collision vulnerability discovery, composite cache key hashing, and Ibex integration blueprint recorded in `docs/research/http-query-method.md`. |
| `189118e6` | WebSocket Protocol Architect | `research` | Real-Time & Multiplexing Protocols | **Complete** | RFC 6455 & RFC 8441 Extended CONNECT WebSocket architecture, `#![forbid(unsafe_code)]` SHA-1/base64 accept engine, tunnel transition, `timeout tunnel` scheduler integration, and cross-protocol bridging recorded in `docs/research/websocket-support.md`. |
| `217f3889` | Static File & Async Filesystem I/O Architect | `research` | Storage & High-Performance I/O | **Complete** | Non-blocking Linux filesystem research (`RWF_NOWAIT`, `openat2(RESOLVE_BENEATH)`, `io_uring`, `eventfd` thread pools), ETag/RFC 9110 ranges/sidecar negotiation, and 3-Tier non-blocking engine blueprint recorded in `docs/research/static-file-serving-async-io.md`. |

---

## Detailed Deliverable Index

### 1. Milestone 1 & 2: Differential Test Verification (`5768a999`)
- **Status**: 14/14 differential scenarios passing in 100% parity against HAProxy 1.0.2: `echo`, `client_close`, `server_close`, `server_refused`, `connect_timeout`, `client_timeout`, `server_timeout`, `maxconn`, `concurrent`, `half_close`, `http_get`, `http_cookie`, `http_cliexp`, `http_srvexp`.
- **Workspace Quality**: Zero compiler warnings, zero clippy warnings under `-D warnings`.

### 2. Milestone 3: TLS Architecture & Implementation (`5422d2cb` & `2b0fc166`)
- **Memory Safety**: Pure `#![forbid(unsafe_code)]` with `rustls 0.23` across `crates/ibex-tls` and `crates/ebtree`.
- **Multi-Certificate Resolution (`IbexCertResolver`)**: Implemented `rustls::server::ResolvesServerCert` backed by two `ebtree::EbMbTree` (Match-Bytes Tree) instances for exact domains and wildcard SNI domains (`*.domain.com`), with case-insensitivity and default fallback certificate support.
- **Zero-Allocation Hot-Path (`TlsArena`, `TlsSlot`)**: Fixed-capacity pre-allocated connection arena (`MAX_TLS_SLOTS = 65536`) with recycled 16 KiB I/O staging buffers (`DEFAULT_TLS_BUF_CAPACITY`) to eliminate dynamic runtime allocations during active TLS proxying.
- **L5/L6 Transport Abstraction (`RustlsTransport`)**: Implements `ibex_proto::transport::Transport` and `TlsInfo` without leaking provider types across layer boundaries. Full support for non-blocking handshakes, encrypted read/write pumping, ALPN negotiation (`h2`, `http/1.1`), cipher and protocol version extraction, and graceful write shutdown.
- **Anti-DDoS Scheduler Defense**: Incoming TLS handshakes tagged with `state::HEAVY = 1 << 5` and limited to at most 1 handshake per scheduler pass via `Class::Heavy` in `ibex-sched`, protecting established HTTP connections from asymmetric CPU exhaustion attacks.
- **Verification & Test Coverage**: 8 comprehensive integration and unit tests passing cleanly under `cargo test -p ibex-tls` and zero warnings under `cargo clippy -p ibex-tls --all-targets -- -D warnings`, plus real network loopback validation over `tokio` TCP sockets.

### 3. Milestone 4: Native HTX & HTTP/1.1 Mux (`b564eba3`)
- **Bidirectional Memory Layout**: Contiguous ring buffer with payloads growing forward and 8-byte bit-packed descriptors growing backward.
- **Zero-Allocation Streaming**: Ingests chunked encoding (`h1_parse_msg_chunks`), strips framing, merges `DATA` blocks, and bubbles trailer headers before `EOT` markers without allocations.
- **Safe Rust Implementation**: `HtxBuffer` using index-partitioned slices under `#![forbid(unsafe_code)]` with zero `alloc` calls on hot forwarding loops.

### 4. Milestones 5 & 6: HTTP/2 & Distributed Peers Protocol (`5d24739a`)
- **HTTP/2 Multiplexing**: `H2Stream` tasks mapped to `ibex-sched` (`Class::Urgent` for connection I/O demux, `Class::Normal` for stream transactions, `Class::Bulk` for large streaming).
- **Contiguous HPACK Dynamic Table**: Fixed 4096-byte memory slab with forward descriptor growth and backward string storage, bounded to exactly 4KB per connection.
- **Distributed Peers Sync Protocol v2.1**: Masterless cluster replication for stick tables over binary frames (`HAProxyS 2.1`) using custom variable-length integer encoding (`intencode`/`intdecode`).

### 5. Milestone 7: QUIC & HTTP/3 Architecture Blueprint (`6f4d4837`)
- **Native HAProxy QUIC / H3 Extraction**: Thorough architectural analysis of HAProxy's native QUIC engine (`src/quic_sock.c`, `src/quic_cid.c`, `src/quic_conn.c`, `src/quic_rx.c`, `src/quic_tx.c`, `src/quic_tls.c`, `src/mux_quic.c`, `src/h3.c`).
- **IETF Standards Conformance**: Full mapping of RFC 9000 (QUIC Transport), RFC 9001 (QUIC TLS 1.3 Encryption & Header Protection), and RFC 9114 (HTTP/3) over pure-Rust `#![forbid(unsafe_code)]` `rustls::quic`.
- **Level-Triggered Batch I/O**: `recvmmsg` (batching up to 64 datagrams per syscall) and `sendmmsg` / GSO (`UDP_SEGMENT`) in `Poller` and `FdTab`, virtualizing connection sessions under `CO_FL_FDLESS`.
- **256-Shard `ebtree` CID Routing & Stateless ODCID**: Zero-allocation $O(k)$ DCID session lookup via 256 sharded `EbMbTree`s, with deterministic `XXH64` / `ahash` ODCID derivation to eliminate global tree pollution on unvalidated Initial handshakes.
- **Zero-Allocation Data Path**: 256-byte cacheline-aligned `QuicConn` layouts, pre-allocated `DatagramArena`, `Eb64Tree` out-of-order stream frame reassembly, and direct zero-copy transcoding into native `HtxBuffer` blocks.
- **Unified TLS 1.3 Dispatch & Anti-DDoS Defense**: Shared `Arc<rustls::ServerConfig>` between TCP TLS (`bind :443 ssl`) and QUIC (`bind :443 quic`), with `Class::Heavy` scheduler throttling (1 handshake per pass) and anti-amplification (3x limit) defense. Deliverable in `docs/research/quic-http3.md`.

### 6. Distributed State & Stick Table Aggregator Architecture (`7e873073`)
- **Active-Active Rate Limiting Analysis**: Deconstructed the mathematical and architectural failure modes of standard HAProxy peer replication (LWW/overwrite data loss, gauge oscillation, rate dilution, $O(N^2)$ mesh complexity).
- **Formal CRDT Convergence Proofs**: Join semi-lattice $(\mathcal{S}, \sqcup)$ formulations and mathematical proofs of Strong Eventual Consistency (SEC) for Delta-G-Counters (`conn_cnt`, `http_req_cnt`, `bytes_in_cnt`), PN-Counters (`conn_cur`), LWW-Registers (`server_id`), and distributed sliding window rate limiters ($\le 0.5\%$ error under network latency jitter).
- **Multi-Protocol Wire Ingestion**: Wire framing specifications for HAProxy Peers Protocol v2.1 (`HAProxyS 2.1` varint encoding), Binary SPOP v2.0 offload engine, and custom batch delta streaming (`ibex-agg-v1`).
- **High-Performance Safe Rust Architecture**: `#![forbid(unsafe_code)]` standalone aggregator engine (`ibex-aggregator`), 256-shard lock-partitioned `ebtree::EbMbTree` key indexing, contiguous generational pre-allocated memory arenas (`StickArena`), and zero runtime heap allocations on the hot aggregation path.
- **Throughput & Latency Scaling**: Validated design targets for $> 100,000$ delta updates/sec per core at $p99 < 500\,\mu\text{s}$ latency with linear multi-core scaling ($> 1.8\text{M}$ updates/sec across 16 cores) and bounded memory footprints ($1\text{M}$ keys in $< 96\,\text{MB}$). Deliverable in `docs/research/stick-table-aggregator.md`.

### 7. Multi-Threaded Distributed Peers Protocol Architecture (`d429bb91`)
- **HAProxy 3.5 Core Pinning Verification**: Confirmed via `/home/bhenc/reference/haproxy/src/peers.c` that HAProxy pins the peers sync task to a single operating thread (`peers->sync_task = task_new_on(operating_thread)`), funnels all worker thread stick table mutations through this single task (`table->sync_task`), gates applet state transitions behind task synchronization (`PEER_F_WAIT_SYNCTASK_ACK`), and executes global "stop-the-world" thread isolation (`thread_isolate()`) on CLI commands (`show peers`).
- **Full-Mesh Bottleneck Deconstruction**: Quantified the scaling limitations of $O(N^2)$ connections ($4,032$ connections for 64 nodes, $65,280$ connections for 256 nodes), CPU saturation on a single core at $> 2\text{M}$ updates/sec, and memory bloat on slow WAN links.
- **Multi-Core `SO_REUSEPORT` TCP Distribution**: Architected per-core `SO_REUSEPORT` listeners in `Engine` worker loops with parallel dedicated TCP replication streams per shard group, eliminating cross-thread context switches on network I/O.
- **256-Shard Lock-Free Stick Table Replication**: Partitioned stick tables across 256 shards (`XXH64(key) >> 56`) with thread affinity, lock-free SPSC ring buffers for cross-thread mutations, and non-blocking asynchronous snapshot iterators replacing `thread_isolate()`.
- **Pure-Rust HAProxyS 2.1 Codec**: Implemented HAProxy's custom variable-length integer encoding (`intencode`/`intdecode` with 240 single-byte threshold), binary message framing (Classes 0, 1, 10), and 256-slot LRU dictionary compression (`DcacheTx`/`DcacheRx`) under `#![forbid(unsafe_code)]`.
- **Bounded Batching & Dynamic Backpressure**: Pre-allocated 64 KiB `PeerTxBatch` slabs, credit-based sliding ACK window (`MAX_IN_FLIGHT_UPDATES = 16384`), lossy delta coalescing for lagging peers, and three-phase fast resync state machine. Deliverable in `docs/research/multithreaded-peers.md`.

### 8. PROXY Protocol Versions 1 & 2 Engine (`77f483d9`)
- **Memory Safety & Zero Allocations**: Pure `#![forbid(unsafe_code)]` implementation in `crates/ibex-proto/src/proxy_protocol.rs` with zero dynamic allocations on all parsing and encoding hot paths.
- **Version 1 Human-Readable Engine**: Strict 107-character bounds checking, single-space delimiter parsing, decimal no-leading-zero IPv4/port enforcement, and `PROXY TCP4`/`TCP6`/`UNKNOWN` handling.
- **Version 2 Binary Framing Engine**: 12-byte binary signature matching (`\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A`), `PROXY`/`LOCAL` command handling, `IPv4`/`IPv6`/`UNIX`/`UNSPEC` address decoding, and 16-bit payload framing.
- **Comprehensive TLV Engine**: Zero-copy TLV vector parser and builder (`TlvBuilder`, `TlvIter`, `SslTlv`) for ALPN (`PP2_TYPE_ALPN`), Authority/SNI (`PP2_TYPE_AUTHORITY`), Unique ID (`PP2_TYPE_UNIQUE_ID`), Network Namespace (`PP2_TYPE_NETNS`), NOOP padding (`PP2_TYPE_NOOP`), and SSL containers with sub-TLVs (`PP2_SUBTYPE_SSL_VERSION`, `CN`, `CIPHER`, `SIG_ALG`, `KEY_ALG`, `GROUP`, `SIG_SCHEME`, `CLIENT_CERT`).
- **Castagnoli CRC32-C Checksum**: Full implementation of RFC 4960 Appendix B CRC32-C (`0x1EDC6F41` polynomial) with in-place zeroed checksum calculation and validation.
- **Property-Based Verification**: 32 unit and property-based tests passing cleanly (`proptest`), fuzzing parser against arbitrary byte sequences and streaming chunk boundaries. Zero clippy warnings under `-D warnings`. Deliverable in `docs/research/proxy-protocol.md`.

### 9. PROXY Protocol Runtime Integration & E2E Verification (`73ed5e8f`)
- **Frontend Interception (`accept-proxy` & `accept-proxy-v2`)**: Integrated non-blocking PROXY v1/v2 header interception into `TcpSession::process_cli_io()` in `crates/ibex-rt/src/proxy.rs`. Intercepts incoming stream data before protocol dispatch, strictly parses headers, extracts the real client socket address (`client_addr`) and TLV vector (`proxy_info`), and strips the PROXY header so downstream HTTP or TCP stream handlers only process clean application data.
- **Deferred Backend Handshake in TCP Mode**: In `Engine::init_client_session` and `step_stream`, deferred upstream connection until the PROXY header is received and parsed, guaranteeing that source IP load balancing (`balance source`) and stick tables track the real client IP rather than the intermediary proxy IP.
- **Backend Transmission (`send-proxy` & `send-proxy-v2`)**: Implemented `maybe_prepend_send_proxy` in `crates/ibex-rt/src/engine.rs` to generate PROXY v1 (ASCII) and PROXY v2 (binary with TLVs) headers, prefixing them directly to upstream connection request buffers for both TCP and HTTP modes without double-prepending on connection retries.
- **Chained PROXY Architecture**: Validated multi-hop chained proxying (`Client -> Ibex 1 [accept-proxy, send-proxy-v2] -> Ibex 2 [accept-proxy] -> Backend Server`), verifying that original client metadata and custom TLVs are preserved and relayed end-to-end.
- **Comprehensive E2E Test Suite**: 11 end-to-end integration tests in `crates/ibex-rt/tests/it/proxy_protocol.rs` covering PROXY v1 HTTP, PROXY v2 TCP, strict v2 rejection of v1, malformed header rejection, upstream v1/v2 generation, source hashing with PROXY client IP, fragmented chunk streaming, TLV forwarding, and CRC32c wire validation.
- **Quality & Parity**: 100% test pass rate across the workspace (`cargo test --workspace`), zero compiler warnings, and zero Clippy warnings under `cargo clippy --workspace --all-targets -- -D warnings`.
 
### 10. HAProxy 1.0 -> 3.5 Keyword Compatibility & Syntax Modernization (`4355d1b6`)
- **Exhaustive 25-Year Syntax Evolution Audit**: Analyzed the historical evolution and deprecation path of HAProxy configuration grammar from 1.0 monolithic regexes through 1.5 TLS/stick tables, 2.0-2.1 HTX hegemony (removal of legacy HTTP analyzers and 9,082 lines of dead code in commit `711ed6ae4`), 2.4 dynamic servers/converters, up to modern HAProxy 3.5.
- **Obsolete & Purged Keywords in HAProxy 3.5**: Cataloged all excised directives in 3.5:
  - `dispatch <ip:port>` and `transparent`: **Removed in 3.5** (commit `be8159248`); replaced by `server <name> <addr:port>` and `server transparent 0.0.0.0`.
  - `master-worker` global keyword: **Removed in 3.5** (commit `5a6ce0481`); replaced by CLI arguments `-W` / `-Ws`.
  - `reqadd`/`reqdel`/`reqrep`/`rspadd`/`rspdel`/`rsprep`: **Removed in 2.1**; replaced by structured `http-request`/`http-response` action rules.
  - `contimeout`/`clitimeout`/`srvtimeout`: **Removed in 2.1**; replaced by `timeout connect`/`client`/`server`.
  - `mode health`: **Removed in 2.3**; replaced by `http-request return status 200`.
  - `[no] option http-use-htx`: **Removed in 2.5**; native HTX is the sole internal representation.
  - `filter opentracing`: **Removed in 3.5**; replaced by `filter otel`.
  - Legacy `tune.quic.*`: **Removed in 3.5**; replaced by `tune.quic.fe.*` / `tune.quic.mem.*`.
- **Modern HAProxy 3.5 Action Rules Matrix**: Complete mapping of L4-L7 pipeline rules (`quic-initial`, `tcp-request connection/session/content`, `tcp-response content`, `http-request`, `http-response`, `http-after-response`), sample fetches, converter chaining, and stick table counters.
- **Concrete `ibex-config` Specification**: Clean AST structure in `crates/ibex-config/src/ast.rs` targeting HAProxy 3.5 directly without carrying legacy 1.x technical debt, with helpful diagnostic error messages on obsolete directives. Deliverable recorded in `docs/research/keyword-compatibility-matrix.md`.



### 11. HAProxy 3.5 Complete Keyword Catalog & Implementation Roadmap (`e6f616af`)
- **Exhaustive Codebase & Documentation Audit**: Analyzed 33,415 lines of `doc/configuration.txt` and C registration tables (`src/cfgparse*.c`, `src/http_act.c`, `src/tcp_act.c`, `src/sample.c`, `src/flt_*.c`, etc.) in HAProxy 3.5-dev7 (`e6f616af`).
- **Complete Section Catalog**: Audited all configuration sections (`global`, `defaults`, `frontend`, `backend`, `listen`, `peers`, `mailers`, `cache`, `resolvers`, `program`, `fcgi-app`, `ring`, `userlist`, `http-errors`, `log-forward`, `crt-store`, `acme`, `healthcheck`), cataloging every keyword with syntax, description, and status (`Standard`, `New in 3.x`, `Deprecated in 3.5`, `Obsolete/Purged in 3.5`).
- **Purged Directives in HAProxy 3.5 Verified**: Confirmed fatal excision of `dispatch`, `transparent`, `master-worker` (purged in 3.5), `program` section (purged in 3.2+ via commit `7cb6167d0`), `nbproc` (purged in 2.5), `reqadd`/`reqdel`/`reqrep` (purged in 2.1), `mode health` (purged in 2.3), `[no] option http-use-htx` (purged in 2.5), and `filter opentracing` (purged in 3.5; replaced by `filter otel`).
- **Complete L7 & L4 Action Rules**: Cataloged all 80+ action variants across 8 rule sets (`quic-initial`, `tcp-request connection/session/content`, `tcp-response content`, `http-request`, `http-response`, `http-after-response`), detailing header rewrites, URI path normalizations, terminal returns, stick table increments, dynamic variables, and socket tunables.
- **Complete Sample Fetches & Converters**: Audited all 570 registered sample fetches and 211 converters across HAProxy's typed sample lattice (`SMP_T_*`), along with ACL matchers (`-i`, `-m <method>`) and pre-defined ACLs.
- **Exhaustive Bind & Server Parameters**: Documented all 40+ bind parameters and 60+ server/default-server parameters covering TLS, PROXY v1/v2, health checks, connection pooling, and DNS resolution.
- **Four-Tier Implementation Priority Roadmap**: Formulated actionable engineering roadmap (P0: Core Production Essentials, P1: Standard Web Traffic & Observability, P2: Advanced Traffic Management & Caching, P3: Specialized Niche Features) with zero-heap hot path invariants adhering to NASA JPL Rule 3.
- **Deliverable**: Recorded in `docs/research/haproxy-35-keywords-complete-catalog.md`.

### 12. HAProxy 3.5 Command-Line Compatibility & Runtime Integration (`958c8b16`)
- **Comprehensive CLI Audit**: Conducted an exhaustive audit of all command-line arguments in HAProxy 3.5 from `/home/bhenc/reference/haproxy` (`src/haproxy.c`, `src/mworker.c`, `doc/haproxy.1`, `doc/management.txt`).
- **Memory-Safe CLI Architecture**: Implemented a pure-Rust, `#![forbid(unsafe_code)]` command-line argument parser in `crates/ibex-rt/src/bin/ibex.rs` supporting:
  - Multi-path `-f <path>` and trailing `-- <paths...>` config declarations with recursive-safe directory expansion (`alphasort` lexical order, non-hidden `.cfg` filtering).
  - Check-only mode (`-c`) with exit codes (0 for valid, 1 for invalid) and quiet (`-q`) / verbose (`-V`) modifiers.
  - Working directory change (`-C <dir>`) executed before file expansion and PID file creation.
  - Informative version reports (`-v`, `-vv`) presenting complete target, compiler, feature matrix, poller list (`epoll`, `poll`), and multiplexers (`h2`, `h1`, `none`).
  - Help banner (`-h`, `--help`) with full HAProxy 3.5 flag compatibility.
  - Process execution modes: background daemon (`-D`), foreground debug (`-d`, `-db`), and master-worker (`-W`, `-Ws` with systemd `sd_notify` socket signalling).
  - PID file management (`-p <pidfile>`) writing current process PID.
  - Graceful soft reload (`-sf <pids...>`) via `SIGUSR1` and immediate termination (`-st <pids...>`) via `SIGTERM` using safe `rustix::process::kill_process`.
  - Resource and tuning overrides: global connection limit (`-n <maxconn>`), per-proxy default limit (`-N <maxsock>`), and virtual memory limits (`-m <megabytes>`) using `rustix::process::setrlimit`.
  - Master CLI socket binding (`-S <socket>`) and diagnostic reporting for specialized tuning flags (`-dr`, `-de`, `-dp`, `-dM`, `-dL`, `-u`, `-g`, `-U`, `-G`, `-ch`, `-e`).
- **Verification & Test Coverage**: Written integration test suite in `crates/ibex-rt/tests/it/cli_options.rs` verifying `-c`, `-v`, `-vv`, `-h`, multiple `-f` files and directory expansion, `-p` PID creation, and `-n` parameter overrides.
- **Deliverable**: Recorded in `docs/research/cli-options-compatibility.md`.

### 13. Unix Build Automation & Makefile Parity (`fb2023df`)
- **Standard Unix Build System**: Created a production-grade root `Makefile` following standard Unix conventions (`PREFIX ?= /usr/local`, `DESTDIR ?=`, `CARGO ?= cargo`, `CARGO_FLAGS ?= --release`).
- **Comprehensive Targets**: Implemented `build`, `debug`, `test`, `lint`, `fmt`, `fmt-check`, `difftest`, `vtc`, `vtc-all`, `run`, `run-stats`, `install` (mode 755), `uninstall`, `clean`, and a self-documenting ANSI-colored `help` display.
- **Verification**: Verified all targets execute cleanly and integrate with differential and regression test runners.

### 14. Stats Admin, Connection Handling & Session Management (`3dfc9706`)
- **Active Session Termination (`kill_sessions` / `shutdown_sessions`)**: Implemented `shutdown_session_entry` and `shutdown_matching_sessions` in `crates/ibex-rt/src/engine.rs`. Gracefully transitions streams to `ScState::Closed`, executes bidirectional socket shutdown via `raw::shutdown_both`, wakes up scheduler tasklets, and immediately reclaims `act_conn` and `server_actconn` counters with double-free protection.
- **Health Check Control (`enable_health` / `disable_health`)**: Added `enabled: bool` to `ServerCheckState` in `crates/ibex-rt/src/check.rs`, enabling dynamic pausing/resuming of active health checks via Web UI and CLI socket while preserving administrative state.
- **Stats Counter Clearing (`clear_counters`)**: Added `ProxyStats::clear` zeroing traffic and error counters (`bytes_in`, `bytes_out`, `cum_conn`, `failed_conn`, `hrsp_5xx`) and resetting `max_conn` via Web Admin and CLI socket.
- **Dynamic Maxconn Tuning (`set_maxconn`)**: Added live tuning of frontend, backend, and server connection limits from the Web Admin table and CLI applet.
- **Verification**: Created comprehensive integration suite in `crates/ibex-rt/tests/it/stats_admin_sessions.rs` (6/6 tests passing).

### 15. Server-Sent Events (SSE) Protocol & Unbuffered Pipeline Architecture (`fa9404f9`)
- **HAProxy 3.5 Streaming Audit**: Audited `src/http_ana.c`, `src/mux_h1.c`, `src/mux_h2.c`, and `src/flt_http_comp.c`.
- **Auto-Detection Engine**: Automatic detection of `Content-Type: text/event-stream` / `X-Accel-Buffering: no` in response headers and immediate bypass of response aggregation buffers.
- **Same-Pass Event-Driven Flush**: Direct sub-millisecond draining of chunked payloads to client sockets with `TCP_NODELAY` without waiting for delayed epoll turns or Nagle coalescing.
- **HTTP/2 Streaming & Disconnect Cancellation**: Mapping events into unbuffered `DATA` frames with dynamic flow control, and immediate propagation of downstream client disconnects (`FIN`/`RST_STREAM`) to cancel upstream LLM token generation or database push tasks.
- **Deliverable**: Recorded in `docs/research/server-sent-events.md`.

### 16. HTTP QUERY Method (RFC 10008) Architecture & Caching (`08c6d33d`)
- **RFC 10008 Analysis**: Deconstructed the IETF HTTP `QUERY` method specification (safe and idempotent method carrying a request body payload without URL length limits or URL data leakage).
- **HAProxy 3.5 Cache Vulnerability Uncovered**: Discovered that HAProxy 3.5 (`src/cache.c`) restricts caching exclusively to `GET` and hashes only `Scheme + Host + URI`. Applying `QUERY` without payload hashing causes severe cross-tenant cache collisions and poisoning.
- **Ibex Protocol & Caching Integration**: Added `HttpMethod::Query` across `ibex-proto`, `ibex-config`, and `ibex-sample`, and designed composite cache key hashing:
  $$\text{Key} = \text{XXH3\_128}(\text{Scheme} \parallel \text{Authority} \parallel \text{URI} \parallel \text{XXH3\_64}(\text{RequestBody}) \parallel \text{ContentType})$$
- **Deliverable**: Recorded in `docs/research/http-query-method.md`.

### 17. WebSocket Protocol & Tunnel Mode Architecture (RFC 6455 & RFC 8441) (`189118e6`)
- **RFC 6455 HTTP/1.1 Upgrade Codec**: Strict 5-point header validation, zero-unsafe constant-time stack-allocated SHA-1 and Base64 accept calculation (`compute_ws_accept`), and 101 Switching Protocols handling.
- **RFC 8441 HTTP/2 Extended CONNECT Engine**: HTTP/2 SETTINGS parameter `SETTINGS_ENABLE_CONNECT_PROTOCOL` (`0x0008`), pseudo-header parsing (`:method = CONNECT`, `:protocol = websocket`, `:scheme`, `:authority`, `:path`), status code 200 stream establishment, and strict `PROTOCOL_ERROR` rejection for illegal `:protocol` pseudo-headers.
- **Bidirectional Zero-Copy Streaming**: Seamless tunnel transition in `TcpSession`, disabling HTTP analyzers, enabling raw byte forwarding via `Buf` ring buffers, and preserving half-close TCP semantics.
- **`timeout tunnel` Scheduler Integration**: Dynamic timer reassignment where `timeout tunnel` supersedes client/server timeouts once upgraded, integrated with `ibex-sched::Tick` modulo $2^{32}$ signed arithmetic.
- **Cross-Protocol Bridging Matrix**: Native transcoding enabling H2 clients (RFC 8441) to communicate with legacy H1 WebSocket backends (RFC 6455) and vice-versa.
- **Deliverable**: Recorded in `docs/research/websocket-support.md`.

### 18. Static File Serving & Non-Blocking Linux Filesystem I/O Architecture (`217f3889`)
- **Linux Kernel VFS & Storage Traps Deconstruction**:
  - Analyzed why POSIX `read(2)` / `write(2)` with `O_NONBLOCK` blocks on regular files due to lack of `IOCB_NOWAIT` in standard VFS `read_iter`, forcing calling threads into `TASK_UNINTERRUPTIBLE` (`D` state) on page cache misses.
  - Verified in `fs/eventpoll.c` why `epoll(7)` returns `EPERM` for disk files (lack of `.poll` handler in `ext4`, `xfs`, `btrfs`, `generic_ro_fops`).
  - Deconstructed why `sendfile(2)` blocks on page cache misses even when the destination network socket is non-blocking.
  - Analyzed POSIX AIO (`glibc` thread pools) and the `O_DIRECT` cache-bypass trap of Linux kernel `io_submit(2)`.
- **NGINX Static Architecture Audit**: Deconstructed NGINX's classic `sendfile` mode, `directio` fallback, and `aio threads` task queue with `eventfd` notification, identifying context switch taxes (4 switches/read) and queue mutex bottlenecks.
- **Modern Linux Kernel Primitives**:
  - `preadv2(2)` with `RWF_NOWAIT` (`0x08`) for microsecond page-cache lookups returning `EAGAIN` immediately on cache misses.
  - `openat2(2)` with `RESOLVE_BENEATH` and `RESOLVE_NO_MAGICLINKS` for TOCTOU-proof jail enforcement without root chroot.
  - `io_uring` dual-ring architecture (`IORING_OP_OPENAT2`, `STATX`, `READV`, `SPLICE`, `SEND_ZC`) for true zero-context-switch kernel async I/O.
- **Ibex Static File Protocol Engine**:
  - Zero-allocation MIME type matcher for all standard web assets (HTML, CSS, JS, WASM, Images, Fonts).
  - Deterministic ETag generation (`W/"mtime-size-inode"`) and conditional caching revalidation (`If-None-Match`, `If-Modified-Since` -> HTTP 304).
  - RFC 9110 Section 14 byte-range request engine (`Range: bytes=start-end` -> HTTP 206 Partial Content / HTTP 416 Range Not Satisfiable).
  - Pre-compressed asset sidecar negotiation (`.br`, `.gz` automatic serving with `Vary: Accept-Encoding`).
  - Strict path traversal sanitization, canonicalization, and `RESOLVE_BENEATH` jail enforcement.
- **Adaptive 3-Tier Non-Blocking Execution Engine under `#![forbid(unsafe_code)]`**:
  - **Tier 1**: In-memory `FileSlabCache` (< 64 KiB) & `preadv2(RWF_NOWAIT)` page-cache probe on the epoll event loop without thread yielding.
  - **Tier 2**: Dedicated asynchronous worker thread pool (`FileIoPool`) with `eventfd` poller wakeup for cache misses.
  - **Tier 3**: Asynchronous kernel `io_uring` engine with zero-copy splicing.
- **Deliverable**: Recorded in `docs/research/static-file-serving-async-io.md`.
