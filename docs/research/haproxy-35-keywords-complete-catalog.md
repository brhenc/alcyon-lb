# HAProxy 3.5 Complete Keyword Catalog & Implementation Roadmap for Project Alcyon

**Target Baseline:** HAProxy 3.5-dev7 (commit `e6f616af`, 2026-09-21)  
**Document Type:** Exhaustive Architectural Syntax Catalog & Engineering Roadmap  
**Target Crates:** `alcyon-config`, `alcyon-proto`, `alcyon-rt`, `alcyon-stick-table`, `alcyon-tls`, `alcyon-sample`  
**Safety & Memory Invariant:** Pure Rust `#![forbid(unsafe_code)]`, zero heap allocation on event loops (NASA JPL Rule 3), bounded $O(1)$/$O(\log N)$ algorithmic complexity.

---

## Table of Contents
1. [Executive Summary & Audit Scope](#1-executive-summary--audit-scope)
2. [Section-by-Section Keyword Catalog](#2-section-by-section-keyword-catalog)
   - 2.1 [Global Section (`global`)](#21-global-section-global)
   - 2.2 [Proxy Sections (`defaults`, `frontend`, `backend`, `listen`)](#22-proxy-sections-defaults-frontend-backend-listen)
   - 2.3 [Peers Section (`peers`)](#23-peers-section-peers)
   - 2.4 [Mailers Section (`mailers`)](#24-mailers-section-mailers)
   - 2.5 [Cache Section (`cache`)](#25-cache-section-cache)
   - 2.6 [Resolvers Section (`resolvers`)](#26-resolvers-section-resolvers)
   - 2.7 [Program Section (`program`) - Status in 3.5](#27-program-section-program---status-in-35)
   - 2.8 [FastCGI Applications Section (`fcgi-app`)](#28-fastcgi-applications-section-fcgi-app)
   - 2.9 [Ring Buffers Section (`ring`)](#29-ring-buffers-section-ring)
   - 2.10 [Ancillary Sections (`userlist`, `http-errors`, `log-forward`, `crt-store`, `acme`)](#210-ancillary-sections-userlist-http-errors-log-forward-crt-store-acme)
3. [Exhaustive L7 Action Rules Catalog](#3-exhaustive-l7-action-rules-catalog)
   - 3.1 [`http-request <action>`](#31-http-request-action)
   - 3.2 [`http-response <action>`](#32-http-response-action)
   - 3.3 [`http-after-response <action>`](#33-http-after-response-action)
4. [Exhaustive L4 Action Rules Catalog](#4-exhaustive-l4-action-rules-catalog)
   - 4.1 [`tcp-request connection <action>`](#41-tcp-request-connection-action)
   - 4.2 [`tcp-request session <action>`](#42-tcp-request-session-action)
   - 4.3 [`tcp-request content <action>`](#43-tcp-request-content-action)
   - 4.4 [`tcp-response content <action>`](#44-tcp-response-content-action)
5. [Sample Fetches, Converters & ACL Matchers Catalog](#5-sample-fetches-converters--acl-matchers-catalog)
   - 5.1 [Sample Fetches Taxonomy & Inventory](#51-sample-fetches-taxonomy--inventory)
   - 5.2 [Sample Converters Taxonomy & Inventory](#52-sample-converters-taxonomy--inventory)
   - 5.3 [ACL Matchers, Flags & Pre-Defined ACLs](#53-acl-matchers-flags--pre-defined-acls)
6. [Bind and Server Parameters Catalog](#6-bind-and-server-parameters-catalog)
   - 6.1 [Bind Parameters (`bind`)](#61-bind-parameters-bind)
   - 6.2 [Server & Default-Server Parameters (`server`, `default-server`)](#62-server--default-server-parameters-server-default-server)
7. [Project Alcyon Implementation Priority Roadmap](#7-project-ibex-implementation-priority-roadmap)
   - 7.1 [Roadmap Summary Matrix](#71-roadmap-summary-matrix)
   - 7.2 [Tier P0: Core Production Essentials (Milestones 1–4)](#72-tier-p0-core-production-essentials-milestones-14)
   - 7.3 [Tier P1: Standard Web Traffic & Observability (Milestones 5–8)](#73-tier-p1-standard-web-traffic--observability-milestones-58)
   - 7.4 [Tier P2: Advanced Traffic Management & Caching (Milestones 9–11)](#74-tier-p2-advanced-traffic-management--caching-milestones-911)
   - 7.5 [Tier P3: Specialized Niche Features (Post-1.0 / Enterprise / Edge)](#75-tier-p3-specialized-niche-features-post-10--enterprise--edge)
   - 7.6 [Parser Architectural Blueprint for `alcyon-config`](#76-parser-architectural-blueprint-for-alcyon-config)

---

## 1. Executive Summary & Audit Scope

This document represents the definitive, exhaustive audit of the configuration syntax, action rules, sample extraction engines, converter pipelines, and server/listener parameter models implemented in **HAProxy 3.5-dev7** (specifically reference commit `e6f616af` dated September 2026).

Project Alcyon is an ultra-high-performance, memory-safe, asynchronous HTTP/1.1, HTTP/2, HTTP/3, and TCP reverse proxy written entirely in pure Rust under `#![forbid(unsafe_code)]`. Rather than emulating obsolete HAProxy 1.x configurations that relied on unmaintainable regex replacements (`reqrep`/`rsprep`) and monolithic architectures, Alcyon targets native **HAProxy 3.5 HTX (HTTP Tree eXpression)** grammar directly.

### 1.1 Codebase Audit Methodology
The audit was conducted by extracting and analyzing keyword definitions across both HAProxy 3.5's canonical documentation (`doc/configuration.txt`, 33,415 lines) and C source registration tables:
- **Global & Proxy Parsing**: `src/cfgparse.c`, `src/cfgparse-global.c`, `src/cfgparse-listen.c`, `src/proxy.c`, `src/server.c`, `src/listener.c`.
- **L4/L7 Action Engines**: `src/http_act.c`, `src/tcp_act.c`, `src/tcp_rules.c`, `src/http_rules.c`, `src/cache.c`, `src/flt_spoe.c`, `src/flt_bwlim.c`, `src/queue.c`, `src/stream.c`.
- **Sample Fetches & Converters**: `src/sample.c`, `src/http_fetch.c`, `src/http_conv.c`, `src/tcp_sample.c`, `src/ssl_sample.c`, `src/stick_table.c`, `src/vars.c`, `src/map.c`, `src/jwe.c`, `src/jwt.c`.
- **Ancillary Subsystems**: `src/resolvers.c`, `src/cache.c`, `src/fcgi-app.c`, `src/cfgparse-peers.c`, `src/sink.c`, `src/mworker.c`, `src/ssl_ckch.c`, `src/acme.c`.

### 1.2 Keyword Status Classification Taxonomy
Every keyword and action is categorized under one of four normative lifecycle statuses in HAProxy 3.5:
1. **`Standard`**: Core syntax in continuous production use across HAProxy 2.x and 3.x.
2. **`New in 3.x`**: Directives, options, or action variants introduced in HAProxy 3.0 through 3.5 (e.g., granular `tune.quic.fe.*`/`tune.quic.be.*`, HTTP 103 `early-hints` ratio caching, multi-queue listener tuning `tune.listener.multi-queue`, stick table shard replication `shards`).
3. **`Deprecated in 3.5`**: Directives accepted by HAProxy 3.5 with runtime configuration warnings and slated for complete excision in subsequent releases (e.g., `set-mark`, `set-tos`, `tune.ssl.capture-cipherlist-size`, `tune.ssl.ocsp-update.*`).
4. **`Obsolete / Purged in 3.5`**: Directives completely excised from the HAProxy 3.5 C grammar that trigger fatal configuration parser aborts (e.g., `dispatch`, `transparent`, `master-worker` global keyword, `program` section, `mode health`, `[no] option http-use-htx`, `reqadd`/`reqdel`/`reqrep`, `filter opentracing`).

---
## 2. Section-by-Section Keyword Catalog

### 2.1 Global Section (`global`)

The `global` section configures process-wide parameters, system security limits, thread topologies, OS integration, event loop polling mechanisms, SSL engine defaults, and performance tuning tunables. In HAProxy 3.5, `global` directives apply uniformly across all worker threads.

#### 2.1.1 Process Management & Security Directives

| Keyword | Syntax | Status (3.5) | Description & Alcyon Architecture |
|---|---|---|---|
| `chroot` | `chroot <jail dir>` | Standard | Changes the root directory of the process after binding sockets. In Alcyon, containerized deployments (cgroups/namespaces) or `systemd DynamicUser` provide superior isolation; supported for compatibility. |
| `daemon` | `daemon` | Standard | Forks the process into the background. Alcyon runs in foreground by default (`Type=notify` in systemd); ignored with informational log if present. |
| `user` | `user <username>` | Standard | Drops privileges to the specified user after socket binding. Alcyon drops Linux capabilities (`CAP_NET_BIND_SERVICE`). |
| `group` | `group <groupname>` | Standard | Drops privileges to the specified group. |
| `uid` | `uid <number>` | Standard | Numerical user ID to set. |
| `gid` | `gid <number>` | Standard | Numerical group ID to set. |
| `pidfile` | `pidfile <path>` | Standard | Writes the process PID to a file. |
| `node` | `node <name>` | Standard | Sets the node name for inventory and cluster identification. |
| `description` | `description <text>` | Standard | Sets an administrative description of the instance. |
| `hard-stop-after` | `hard-stop-after <time>` | Standard | Maximum time allowed to perform a soft reload before forcing shutdown. Crucial in Alcyon graceful draining. |
| `grace` | `grace <time>` | Standard | Duration of the graceful drain period upon receiving `SIGUSR1`. |
| `default-path` | `default-path { current | config | parent | origin }` | Standard | Sets default base directory resolution for relative configuration paths. |
| `ca-base` | `ca-base <dir>` | Standard | Default directory for CA certificates. |
| `crt-base` | `crt-base <dir>` | Standard | Default directory for server and client TLS certificates. |
| `key-base` | `key-base <dir>` | Standard | Default directory for TLS private keys. |
| `issuers-chain-path` | `issuers-chain-path <dir>` | Standard | Directory containing bundle certificates for OCSP and client certificate validation. |
| `cluster-secret` | `cluster-secret <secret>` | Standard | Shared secret across cluster nodes for distributed deterministic hashing (e.g. JWT / dynamic tokens). |
| `external-check` | `external-check` | Standard | Enables the execution of external health check helper binaries. |
| `fd-hard-limit` | `fd-hard-limit <number>` | Standard | Hard limit on maximum allowed file descriptors across the process. |
| `ulimit-n` | `ulimit-n <number>` | Standard | Adjusts OS `RLIMIT_NOFILE` automatically. |
| `prealloc-fd` | `prealloc-fd` | Standard | Pre-allocates file descriptor tracking tables to avoid runtime memory fragmentation. |
| `strict-limits` | `strict-limits` | Standard | Prevents HAProxy from automatically clamping down limits if `ulimit` cannot be adjusted. |
| `set-dumpable` | `set-dumpable` | Standard | Enables core dumps for debugging post-privilege drop. |
| `insecure-fork-wanted` | `insecure-fork-wanted` | Standard | Explicit opt-in allowing worker processes to fork child processes. |
| `insecure-setuid-wanted` | `insecure-setuid-wanted` | Standard | Explicit opt-in allowing setuid after initialization. |
| `expose-deprecated-directives` | `expose-deprecated-directives` | Standard | Suppresses configuration parser warnings for deprecated syntax. |
| `expose-experimental-directives`| `expose-experimental-directives`| Standard | Enables evaluation of experimental features and action rules. |
| `h1-case-adjust` | `h1-case-adjust <name> <capitalized>` | Standard | Preserves non-standard HTTP/1.1 header casing for legacy backends. |
| `h1-case-adjust-file` | `h1-case-adjust-file <path>` | Standard | Loads HTTP/1.1 header case mappings from an external dictionary. |
| `h1-accept-payload-with-any-method` | `h1-accept-payload-with-any-method` | Standard | Allows body payloads on GET/DELETE/HEAD requests without rejecting. |
| `h1-do-not-close-on-insecure-transfer-encoding` | `h1-do-not-close-on-insecure-transfer-encoding` | Standard | Disables strict smuggling closure on anomalous transfer encodings. |
| `h2-workaround-bogus-websocket-clients` | `h2-workaround-bogus-websocket-clients` | Standard | Accommodates clients that violate RFC 8441 extended CONNECT syntax. |
| `harden.reject-privileged-ports.tcp` | `harden.reject-privileged-ports.tcp` | New in 3.x | Rejects outbound TCP connections to ports < 1024 to mitigate SSRF. |
| `harden.reject-privileged-ports.quic`| `harden.reject-privileged-ports.quic`| New in 3.x | Rejects outbound QUIC connections to ports < 1024. |
| `setenv` | `setenv <name> <value>` | Standard | Sets an environment variable for process runtime and child processes. |
| `presetenv` | `presetenv <name> <value>` | Standard | Sets an environment variable only if not already present. |
| `unsetenv` | `unsetenv <name>` | Standard | Unsets an environment variable. |
| `resetenv` | `resetenv [<name> ...]` | Standard | Clears all environment variables except specified whitelist. |
| `localpeer` | `localpeer <name>` | Standard | Identifies the local instance name in distributed `peers` synchronization. |
| `stats socket` | `stats socket <addr:port\|path> [param*]` | Standard | Administrative CLI UNIX domain socket or TCP management endpoint. |
| `stats timeout` | `stats timeout <time>` | Standard | Inactivity timeout on the administrative CLI socket. |
| `stats maxconn` | `stats maxconn <number>` | Standard | Maximum concurrent connections allowed to the stats CLI socket. |
| `stats-file` | `stats-file <path>` | Standard | Periodically dumps runtime counters to an external file. |
| `worker-id` | `worker-id <number>` | Standard | Unique worker ID in master-worker topologies. |
| `limited-quic` | `limited-quic` | New in 3.x | Throttles QUIC operations if cryptographic acceleration is overloaded. |

#### 2.1.2 Multi-Threading & CPU Topology Directives

| Keyword | Syntax | Status (3.5) | Description & Alcyon Architecture |
|---|---|---|---|
| `nbthread` | `nbthread <number>` | Standard | Number of worker threads to spawn. Alcyon defaults to `std::thread::available_parallelism()` with hard thread affinity. |
| `thread-group` | `thread-group <num> <threads>` | Standard | Defines thread groupings for NUMA locality and partitioned worker pools. |
| `thread-groups` | `thread-groups <count>` | Standard | Sets the total count of thread groups. |
| `thread-hard-limit` | `thread-hard-limit <num>` | Standard | Enforces a hard ceiling on total worker threads. |
| `max-threads-per-group` | `max-threads-per-group <num>` | Standard | Restricts threads within any single NUMA thread group. |
| `cpu-map` | `cpu-map [auto:]<group>[/<set>] <cpus>` | Standard | Pins worker threads to designated physical CPU cores via `sched_setaffinity`. |
| `cpu-affinity` | `cpu-affinity <affinity>` | Standard | Global CPU affinity mask. |
| `cpu-policy` | `cpu-policy <policy>` | Standard | Scheduling policy for worker threads (`other`, `fifo`, `rr`). |
| `numa-cpu-mapping` | `numa-cpu-mapping { on \| off }` | Standard | Automatically aligns thread groups with system NUMA nodes. |

#### 2.1.3 Performance Tuning (`tune.*`) Directives

HAProxy 3.5 provides deep, low-level tuning knobs for memory buffers, socket queues, TLS pipelines, HTTP/2 flow control, and HTTP/3 QUIC state machines.

| Keyword | Syntax | Status (3.5) | Description & Alcyon Mapping |
|---|---|---|---|
| `tune.bufsize` | `tune.bufsize <bytes>` | Standard | Default buffer slab size for all session I/O (default 16,384 bytes). In Alcyon, maps to `PooledBuf` chunk size. |
| `tune.bufsize.small` | `tune.bufsize.small <bytes>` | New in 3.x | Smaller buffer slab size for idle or low-bandwidth streams. |
| `tune.bufsize.large` | `tune.bufsize.large <bytes>` | New in 3.x | Jumbo buffer slab size for heavy streaming responses. |
| `tune.maxrewrite` | `tune.maxrewrite <bytes>` | Standard | Reserved header rewrite buffer margin (default 1,024 bytes). Prevents body data from starving header injection. |
| `tune.buffers.limit` | `tune.buffers.limit <number>` | Standard | Maximum number of active buffer slabs before allocating backpressure kicks in. |
| `tune.buffers.reserve` | `tune.buffers.reserve <number>`| Standard | Number of reserved buffer slabs maintained to prevent deadlocks under extreme load. |
| `tune.rcvbuf.client` | `tune.rcvbuf.client <bytes>` | Standard | Sets `SO_RCVBUF` on downstream client sockets. |
| `tune.rcvbuf.server` | `tune.rcvbuf.server <bytes>` | Standard | Sets `SO_RCVBUF` on upstream backend sockets. |
| `tune.sndbuf.client` | `tune.sndbuf.client <bytes>` | Standard | Sets `SO_SNDBUF` on downstream client sockets. |
| `tune.sndbuf.server` | `tune.sndbuf.server <bytes>` | Standard | Sets `SO_SNDBUF` on upstream backend sockets. |
| `tune.rcvbuf.frontend` | `tune.rcvbuf.frontend <bytes>`| Standard | Default receive buffer for all frontend sockets. |
| `tune.rcvbuf.backend` | `tune.rcvbuf.backend <bytes>` | Standard | Default receive buffer for all backend sockets. |
| `tune.sndbuf.frontend` | `tune.sndbuf.frontend <bytes>`| Standard | Default send buffer for all frontend sockets. |
| `tune.sndbuf.backend` | `tune.sndbuf.backend <bytes>` | Standard | Default send buffer for all backend sockets. |
| `tune.pipesize` | `tune.pipesize <bytes>` | Standard | Sets kernel pipe buffer capacity for zero-copy Linux `splice()` proxying. |
| `tune.idle-pool.shared` | `tune.idle-pool.shared { on \| off }` | Standard | Permits sharing idle backend connections across threads in the same thread group. |
| `tune.idletimer` | `tune.idletimer <time>` | Standard | Maximum idle connection duration before scheduled health poll. |
| `tune.listener.default-shards` | `tune.listener.default-shards <num>` | New in 3.x | Default number of kernel socket shards (`SO_REUSEPORT`) per listener. |
| `tune.listener.multi-queue` | `tune.listener.multi-queue { on \| off }` | New in 3.x | Enables multi-queue distribution for listener accept queues. |
| `tune.h1.fe.glitches-threshold` | `tune.h1.fe.glitches-threshold <num>` | Standard | Maximum HTTP/1.1 protocol anomalies before closing frontend connection. |
| `tune.h1.be.glitches-threshold` | `tune.h1.be.glitches-threshold <num>` | Standard | Maximum HTTP/1.1 anomalies tolerated from upstream backends. |
| `tune.h1.zero-copy-fwd-recv` | `tune.h1.zero-copy-fwd-recv { on \| off }` | New in 3.x | Enables zero-copy receive forwarding for HTTP/1.1 large chunk payloads. |
| `tune.h1.zero-copy-fwd-send` | `tune.h1.zero-copy-fwd-send { on \| off }` | New in 3.x | Enables zero-copy transmit forwarding for HTTP/1.1 payloads. |
| `tune.h2.fe.max-concurrent-streams` | `tune.h2.fe.max-concurrent-streams <num>` | Standard | Max concurrent streams advertised to HTTP/2 clients via `SETTINGS`. |
| `tune.h2.be.max-concurrent-streams` | `tune.h2.be.max-concurrent-streams <num>` | Standard | Max concurrent HTTP/2 streams opened toward upstream servers. |
| `tune.h2.fe.initial-window-size` | `tune.h2.fe.initial-window-size <bytes>` | Standard | Initial stream flow-control window size for downstream clients. |
| `tune.h2.be.initial-window-size` | `tune.h2.be.initial-window-size <bytes>` | Standard | Initial stream flow-control window size for upstream servers. |
| `tune.h2.header-table-size` | `tune.h2.header-table-size <bytes>` | Standard | Maximum HPACK dynamic header decompression table size (default 4,096). |
| `tune.h2.max-frame-size` | `tune.h2.max-frame-size <bytes>` | Standard | Maximum HTTP/2 payload frame size (default 16,384). |
| `tune.h2.fe.max-rst-at-once` | `tune.h2.fe.max-rst-at-once <num>` | New in 3.x | Rate limit for RST_STREAM frames to mitigate Rapid Reset DoS attacks. |
| `tune.h2.fe.max-total-streams` | `tune.h2.fe.max-total-streams <num>` | New in 3.x | Cumulative stream budget before forcing client connection termination. |
| `tune.h2.zero-copy-fwd-send` | `tune.h2.zero-copy-fwd-send { on \| off }` | New in 3.x | Enables zero-copy transmit for HTTP/2 data frames. |
| `tune.quic.fe.max-idle-timeout` | `tune.quic.fe.max-idle-timeout <time>` | New in 3.x | QUIC idle connection timeout for frontend clients. |
| `tune.quic.be.max-idle-timeout` | `tune.quic.be.max-idle-timeout <time>` | New in 3.x | QUIC idle timeout for backend upstream connections. |
| `tune.quic.fe.stream.max-concurrent` | `tune.quic.fe.stream.max-concurrent <num>` | New in 3.x | Max concurrent QUIC streams per client session. |
| `tune.quic.be.stream.max-concurrent` | `tune.quic.be.stream.max-concurrent <num>` | New in 3.x | Max concurrent QUIC streams opened to upstream servers. |
| `tune.quic.fe.cc.cubic-min-losses` | `tune.quic.fe.cc.cubic-min-losses <num>` | New in 3.x | Minimum packet loss threshold for QUIC CUBIC congestion controller backoff. |
| `tune.quic.fe.cc.hystart` | `tune.quic.fe.cc.hystart { on \| off }` | New in 3.x | Enables Hybrid Slow Start for frontend QUIC sessions. |
| `tune.quic.fe.tx.udp-gso` | `tune.quic.fe.tx.udp-gso { on \| off }` | New in 3.x | Enables Linux UDP Generic Segmentation Offload (GSO) for high-speed QUIC packet output. |
| `tune.quic.fe.tx.pacing` | `tune.quic.fe.tx.pacing { on \| off }` | New in 3.x | Enables packet pacing for QUIC congestion avoidance. |
| `tune.quic.mem.tx-max` | `tune.quic.mem.tx-max <bytes>` | New in 3.x | Global memory allocation ceiling for QUIC retransmission buffers. |
| `tune.sched.low-latency` | `tune.sched.low-latency { on \| off }` | Standard | Instructs event scheduler to prioritize I/O completion over batching. Maps to `alcyon-sched`. |
| `tune.sched.remote-work-budget` | `tune.sched.remote-work-budget <num>` | New in 3.x | Number of task migrations processed per scheduler tick. |
| `tune.peers.max-updates-at-once` | `tune.peers.max-updates-at-once <num>` | Standard | Batch limit on stick-table synchronization updates sent across peers. |
| `tune.ring.queues` | `tune.ring.queues <num>` | New in 3.x | Number of multi-producer lock-free queues in ring sinks. |
| `tune.ssl.cachesize` | `tune.ssl.cachesize <number>` | Standard | Maximum entries in the shared SSL session cache. |
| `tune.ssl.lifetime` | `tune.ssl.lifetime <time>` | Standard | Maximum lifetime of SSL session tickets and cache entries. |
| `tune.ssl.maxrecord` | `tune.ssl.maxrecord <bytes>` | Standard | Maximum TLS record chunk size before transmission (default 16,384). |
| `tune.ssl.hard-maxrecord` | `tune.ssl.hard-maxrecord { on \| off }`| Standard | Prevents dynamic TLS record sizing and forces static records. |
| `tune.ssl.keylog` | `tune.ssl.keylog { on \| off }` | Standard | Enables `SSLKEYLOGFILE` dumping for Wireshark TLS decryption debugging. |
| `tune.ssl.capture-cipherlist-size` | `tune.ssl.capture-cipherlist-size <bytes>`| Deprecated | Buffer size for storing client TLS cipher list; deprecated in 3.5. |
| `tune.ssl.ocsp-update.maxdelay` | `tune.ssl.ocsp-update.maxdelay <time>` | Deprecated | Slated for removal; replaced by `ocsp-update.maxdelay`. |
| `tune.ssl.ocsp-update.mindelay` | `tune.ssl.ocsp-update.mindelay <time>` | Deprecated | Slated for removal; replaced by `ocsp-update.mindelay`. |
| `tune.vars.global-max-size` | `tune.vars.global-max-size <bytes>` | Standard | Global memory limit for process-wide variables. |
| `tune.vars.txn-max-size` | `tune.vars.txn-max-size <bytes>` | Standard | Memory limit for per-transaction variables (`txn.*`). |
| `tune.vars.reqres-max-size` | `tune.vars.reqres-max-size <bytes>` | Standard | Memory limit for request/response variables (`req.*`, `res.*`). |

#### 2.1.4 Obsolete & Purged Keywords in Global Section

| Keyword | Excised In | Reason for Purge | HAProxy 3.5 Diagnostic / Replacement |
|---|---|---|---|
| `master-worker` | HAProxy 3.5 (`5a6ce0481`) | Ambiguous configuration vs CLI flag collision; master process must know mode prior to reading config. | **Fatal parse error**. Replace with CLI argument `-W` (multi-process) or `-Ws` (systemd notify mode). |
| `nbproc` | HAProxy 2.5 (`3d1b647f1`) | Multi-process mode eliminated in favor of clean, scalable multi-threading (`nbthread`). | **Fatal parse error**. Replace with `nbthread <N>` and NUMA `thread-group`. |
| `tune.quic.*` (legacy flat) | HAProxy 3.5 (`e6f616af`) | Replaced by granular frontend/backend sub-hierarchies (`tune.quic.fe.*`, `tune.quic.be.*`, `tune.quic.mem.*`). | **Fatal parse error**. Replace with hierarchical `tune.quic.fe.*` directives. |

---
### 2.2 Proxy Sections (`defaults`, `frontend`, `backend`, `listen`)

Proxy sections define the core forwarding topology of HAProxy:
- `defaults`: Sets baseline defaults inherited by all subsequently declared `frontend`, `backend`, and `listen` blocks.
- `frontend`: Accepts downstream client connections, performs TLS termination, enforces L4/L7 rate limiting and routing rules, and dispatches traffic to backends.
- `backend`: Manages upstream server pools, load balancing algorithms, connection reuse, health check probes, and response filtering.
- `listen`: Combines a frontend and backend into a single cohesive configuration block (common for TCP services, administrative dashboards, and internal proxies).

#### 2.2.1 Proxy Keywords Applicability Matrix & Reference

| Keyword | Syntax | Defaults | Frontend | Backend | Listen | Status (3.5) | Description & Alcyon Architecture |
|---|---|:---:|:---:|:---:|:---:|:---:|---|
| `mode` | `mode { http \| tcp }` | Yes | Yes | Yes | Yes | Standard | Sets the operational layer. `http` activates the HTX state machine; `tcp` operates raw stream forwarding. |
| `bind` | `bind <addr>:<port> [param*]` | No | Yes | No | Yes | Standard | Binds listeners to network endpoints. Supports TLS, PROXY protocol, and socket options. |
| `backlog` | `backlog <conns>` | Yes | Yes | No | Yes | Standard | Sets the kernel TCP SYN listen backlog hint. |
| `maxconn` | `maxconn <conns>` | Yes | Yes | No | Yes | Standard | Sets concurrent connection ceiling on a frontend or listener. |
| `balance` | `balance <algorithm> [args]` | Yes | No | Yes | Yes | Standard | Selects load balancing algorithm: `roundrobin`, `leastconn`, `source`, `uri`, `url_param`, `hdr`, `random`. |
| `hash-type` | `hash-type <method> [function]` | Yes | No | Yes | Yes | Standard | Sets hash distribution: `map-based` ($O(1)$ array), `consistent` (Ketama consistent hashing tree). |
| `hash-balance-factor` | `hash-balance-factor <percent>` | Yes | No | Yes | Yes | Standard | Bounded load balancing factor mitigating consistent hash hotspotting. |
| `hash-preserve-affinity` | `hash-preserve-affinity` | Yes | No | Yes | Yes | New in 3.x | Preserves consistent hashing ring positions across server state flapping. |
| `server` | `server <name> <addr>:<port> [param*]`| No | No | Yes | Yes | Standard | Declares an upstream server endpoint with health check and SSL options. |
| `default-server` | `default-server [param*]` | Yes | No | Yes | Yes | Standard | Configures default parameters applied to all subsequent `server` lines. |
| `server-template` | `server-template <prefix> <num> <addr> [param*]`| No | No | Yes | Yes | Standard | Generates multiple dynamic server instances resolved via DNS SRV/A records. |
| `use_backend` | `use_backend <backend> [ { if \| unless } <condition> ]` | No | Yes | No | Yes | Standard | Switches request execution to the designated backend if the ACL condition is met. |
| `default_backend`| `default_backend <backend>` | Yes | Yes | No | No | Standard | Designates the fallback backend when no `use_backend` rule matched. |
| `force-be-switch` | `force-be-switch [ { if \| unless } <condition> ]` | No | Yes | No | Yes | New in 3.x | Forces immediate backend dispatch before full HTTP request body receipt. |
| `be-unpublished` | `be-unpublished` | No | No | Yes | Yes | New in 3.x | Prevents backend metadata from being exposed in public CLI/metrics outputs. |
| `timeout connect` | `timeout connect <time>` | Yes | No | Yes | Yes | Standard | Maximum time to wait for a successful TCP connection to an upstream server. |
| `timeout client` | `timeout client <time>` | Yes | Yes | No | Yes | Standard | Maximum inactivity time on the downstream client socket. |
| `timeout client-fin` | `timeout client-fin <time>` | Yes | Yes | No | Yes | Standard | Inactivity timeout for half-closed connections on downstream client side. |
| `timeout server` | `timeout server <time>` | Yes | No | Yes | Yes | Standard | Maximum inactivity time on the upstream server socket. |
| `timeout server-fin` | `timeout server-fin <time>` | Yes | No | Yes | Yes | Standard | Inactivity timeout for half-closed connections on upstream server side. |
| `timeout tunnel` | `timeout tunnel <time>` | Yes | Yes | Yes | Yes | Standard | Inactivity timeout for bidirectional tunnels (WebSockets, HTTP CONNECT). |
| `timeout http-request` | `timeout http-request <time>` | Yes | Yes | No | Yes | Standard | Anti-Slowloris timeout for receiving complete HTTP request headers. |
| `timeout http-keep-alive` | `timeout http-keep-alive <time>` | Yes | Yes | No | Yes | Standard | Inactivity timeout waiting for a subsequent HTTP request on an open keep-alive connection. |
| `timeout queue` | `timeout queue <time>` | Yes | No | Yes | Yes | Standard | Maximum time a request may sit waiting in a backend connection pool queue. |
| `timeout check` | `timeout check <time>` | Yes | No | Yes | Yes | Standard | Additional timeout applied to active health check probes. |
| `timeout tarpit` | `timeout tarpit <time>` | Yes | Yes | Yes | Yes | Standard | Delay duration applied to tarpitted malicious requests before connection termination. |
| `option httpchk` | `option httpchk [<method>] [<uri>] [<version>]` | Yes | No | Yes | Yes | Standard | Activates HTTP-based active health check probing. |
| `http-check` | `http-check <send\|expect\|connect\|comment>` | Yes | No | Yes | Yes | Standard | Modern multi-stage active HTTP health checking pipeline. |
| `option tcp-check` | `option tcp-check` | Yes | No | Yes | Yes | Standard | Activates multi-step TCP send/expect health checking. |
| `tcp-check` | `tcp-check <send\|expect\|connect\|comment>` | Yes | No | Yes | Yes | Standard | Configures raw L4 health checking state machine. |
| `external-check command` | `external-check command <path>` | Yes | No | Yes | Yes | Standard | Path to external health check script binary. |
| `external-check path` | `external-check path <path>` | Yes | No | Yes | Yes | Standard | `PATH` environment variable for executing external check commands. |
| `stick-table` | `stick-table type <type> size <size> [param*]` | No | Yes | Yes | Yes | Standard | Allocates an in-memory tracking table for real-time sliding counters and sticky sessions. |
| `stick on` | `stick on <sample> [ { if \| unless } <condition> ]` | No | No | Yes | Yes | Standard | Selects stick table key used to associate incoming request with cached server mapping. |
| `stick match` | `stick match <sample> [ { if \| unless } <condition> ]` | No | No | Yes | Yes | Standard | Matches client against stick table without updating access timestamps. |
| `stick store-request` | `stick store-request <sample> [ { if \| unless } <cond> ]` | No | No | Yes | Yes | Standard | Stores key and server mapping into stick table upon request receipt. |
| `stick store-response`| `stick store-response <sample> [ { if \| unless } <cond> ]`| No | No | Yes | Yes | Standard | Stores key and server mapping upon upstream response receipt (e.g. Set-Cookie). |
| `cookie` | `cookie <name> [param*]` | Yes | No | Yes | Yes | Standard | Enables cookie-based session persistence (insert, prefix, rewrite). |
| `force-persist` | `force-persist { if \| unless } <condition>` | No | No | Yes | Yes | Standard | Forces routing to a down or maintenance server if persistent cookie matches. |
| `ignore-persist` | `ignore-persist { if \| unless } <condition>` | No | No | Yes | Yes | Standard | Ignores session cookie and performs fresh load balancing when condition matches. |
| `log` | `log <addr> [len <len>] [format <fmt>] <facility> [<level>]` | Yes | Yes | Yes | Yes | Standard | Configures syslog, UDP, UNIX socket, or ring buffer logging destinations. |
| `log-format` | `log-format <string>` | Yes | Yes | No | Yes | Standard | Custom log string format using log variables and sample fetches. |
| `log-format-sd` | `log-format-sd <string>` | Yes | Yes | No | Yes | Standard | Structured Data (RFC 5424) log format string. |
| `log-tag` | `log-tag <string>` | Yes | Yes | Yes | Yes | Standard | Tag prepended to all syslog lines emitted by this proxy. |
| `log-steps` | `log-steps <steps>` | Yes | Yes | No | Yes | New in 3.x | Controls intermediate transaction state logging for detailed latency debugging. |
| `error-log-format` | `error-log-format <string>` | Yes | Yes | No | Yes | Standard | Specific custom log format string emitted on aborted or errored transactions. |
| `option httplog` | `option httplog [clf]` | Yes | Yes | Yes | Yes | Standard | Emits rich standard HTTP log format with timers, statuses, and headers. |
| `option tcplog` | `option tcplog` | Yes | Yes | Yes | Yes | Standard | Emits standard TCP log format with connection timers and byte counters. |
| `option dontlognull` | `option dontlognull` | Yes | Yes | No | Yes | Standard | Suppresses logging of probe connections that disconnect without sending any data. |
| `option dontlog-normal` | `option dontlog-normal` | Yes | Yes | No | Yes | Standard | Suppresses logging of successful HTTP 2xx/3xx requests, logging only errors. |
| `option log-separate-errors` | `option log-separate-errors` | Yes | Yes | No | Yes | Standard | Directs error logs to a separate syslog facility/server. |
| `option log-health-checks` | `option log-health-checks` | Yes | No | Yes | Yes | Standard | Emits syslog entries on every server health transition. |
| `monitor-uri` | `monitor-uri <uri>` | Yes | Yes | No | Yes | Standard | Intercepts HTTP requests to <uri> and returns immediate 200 OK without forwarding. |
| `monitor fail` | `monitor fail { if \| unless } <condition>` | No | Yes | No | Yes | Standard | Returns HTTP 503 Service Unavailable on `monitor-uri` when condition triggers. |
| `option forwardfor` | `option forwardfor [param*]` | Yes | Yes | Yes | Yes | Standard | Appends or inserts client IP into `X-Forwarded-For` HTTP header. |
| `option http-server-close` | `option http-server-close` | Yes | Yes | Yes | Yes | Standard | Closes upstream server connection after each transaction while keeping client keep-alive open. |
| `option http-keep-alive` | `option http-keep-alive` | Yes | Yes | Yes | Yes | Standard | Full bidirectional keep-alive on both client and upstream server sides. |
| `option httpclose` | `option httpclose` | Yes | Yes | Yes | Yes | Standard | Injects `Connection: close` on both sides, closing sockets after each request. |
| `option redispatch` | `option redispatch [<retries>]` | Yes | No | Yes | Yes | Standard | Redispatches request to another backend server if selected server fails to connect. |
| `option splice-auto` | `option splice-auto` | Yes | Yes | Yes | Yes | Standard | Automatically uses Linux kernel `splice()` zero-copy forwarding when possible. |
| `option tcp-smart-accept` | `option tcp-smart-accept` | Yes | Yes | No | Yes | Standard | Optimizes TCP ACK timing on client accepts using `TCP_DEFER_ACCEPT`. |
| `option tcp-smart-connect`| `option tcp-smart-connect`| Yes | No | Yes | Yes | Standard | Delays outbound SYN ACK until initial data is ready to send (`TCP_NODELAY`). |
| `option disable-h2-upgrade`| `option disable-h2-upgrade`| Yes | Yes | No | Yes | Standard | Disables HTTP/1.1 `Upgrade: h2c` cleartext protocol escalation. |
| `http-reuse` | `http-reuse { never \| safe \| aggressive \| always }` | Yes | No | Yes | Yes | Standard | Governs connection pool reuse strategy for upstream HTTP connections. |
| `http-send-name-header` | `http-send-name-header [<header>]` | Yes | No | Yes | Yes | Standard | Injects server identification name into an HTTP request header toward backend. |
| `compression algo` | `compression algo <algorithm> ...` | Yes | Yes | Yes | Yes | Standard | Enables dynamic HTTP compression: `identity`, `gzip`, `deflate`. |
| `compression type` | `compression type <mime-type> ...` | Yes | Yes | Yes | Yes | Standard | Restricts dynamic compression to specified MIME content types. |
| `compression offload` | `compression offload` | Yes | Yes | Yes | Yes | Standard | Strips `Accept-Encoding` from upstream requests and compresses on proxy egress. |
| `errorfile` | `errorfile <code> <path>` | Yes | Yes | Yes | Yes | Standard | Loads custom static HTTP error payload from file for designated HTTP status code. |
| `errorfiles` | `errorfiles <name> [<code> ...]` | Yes | Yes | Yes | Yes | Standard | References pre-declared `http-errors` section for custom error responses. |
| `errorloc302` | `errorloc302 <code> <url>` | Yes | Yes | Yes | Yes | Standard | Emits HTTP 302 Found redirect to <url> on specified error status. |
| `errorloc303` | `errorloc303 <code> <url>` | Yes | Yes | Yes | Yes | Standard | Emits HTTP 303 See Other redirect to <url> on specified error status. |
| `http-error` | `http-error status <code> [param*]` | Yes | Yes | Yes | Yes | Standard | Inline modern error configuration with custom headers, content-type, and body. |
| `acl` | `acl <name> <criterion> [flags] <value>` | Yes(!) | Yes | Yes | Yes | Standard | Declares an Access Control List boolean expression. `Yes(!)`: named defaults only. |
| `http-request` | `http-request <action> [args] [ { if \| unless } <cond> ]` | Yes(!) | Yes | Yes | Yes | Standard | L7 request processing pipeline rule. |
| `http-response` | `http-response <action> [args] [ { if \| unless } <cond> ]`| Yes(!) | Yes | Yes | Yes | Standard | L7 response processing pipeline rule. |
| `http-after-response` | `http-after-response <action> [args] [cond]` | Yes(!) | Yes | Yes | Yes | Standard | Late L7 response pipeline rule executed after body buffering. |
| `tcp-request connection`| `tcp-request connection <action> [args] [cond]` | No | Yes | No | Yes | Standard | L4 client connection filter rule executed immediately upon `accept()`. |
| `tcp-request session` | `tcp-request session <action> [args] [cond]` | No | Yes | No | Yes | Standard | L5 session filter rule executed after TLS handshake completion. |
| `tcp-request content` | `tcp-request content <action> [args] [cond]` | No | Yes | Yes | Yes | Standard | L6/L7 payload inspection rule before protocol decoding. |
| `tcp-response content`| `tcp-response content <action> [args] [cond]` | No | No | Yes | Yes | Standard | L6/L7 response payload inspection rule before forwarding to client. |
| `filter` | `filter <name> [args]` | No | Yes | Yes | Yes | Standard | Attaches dynamic stream filter: `spoe`, `cache`, `fcgi-app`, `bwlim`, `trace`, `otel`. |

#### 2.2.2 Obsolete Directives Purged in HAProxy 3.5

| Excised Keyword | Excised In | Historical Purpose | Modern HAProxy 3.5 & Alcyon Replacement |
|---|---|---|---|
| `dispatch <addr:port>` | HAProxy 3.5 (`be8159248`) | Fixed unconditional IP:port forwarding fallback. | **Fatal parse error**. Replace with `server default <addr:port>`. |
| `transparent` | HAProxy 3.5 (`be8159248`) | Intercepted destination address preservation. | **Fatal parse error**. Replace with `server transparent 0.0.0.0` or `usesrc clientip`. |
| `contimeout` / `clitimeout` / `srvtimeout` | HAProxy 2.1 | Pre-1.5 legacy timeout keywords. | **Fatal parse error**. Replace with `timeout connect`, `timeout client`, `timeout server`. |
| `reqadd` / `reqdel` / `reqrep` / `reqirep` | HAProxy 2.1 | Pre-HTX regex header manipulation. | **Fatal parse error**. Replace with `http-request add-header`, `del-header`, `replace-header`. |
| `rspadd` / `rspdel` / `rsprep` / `rspirep` | HAProxy 2.1 | Pre-HTX response regex manipulation. | **Fatal parse error**. Replace with `http-response add-header`, `del-header`, `replace-header`. |
| `mode health` | HAProxy 2.3 | Trivial HTTP 200 health check responder. | **Fatal parse error**. Replace with `http-request return status 200`. |
| `[no] option http-use-htx` | HAProxy 2.5 | Toggled between legacy HTTP parser and HTX. | **Fatal parse error**. Excised; HTX is the sole internal representation. |
| `filter opentracing` | HAProxy 3.5 | Legacy OpenTracing C wrapper filter. | **Fatal parse error**. Excised; replaced by native OpenTelemetry filter (`filter otel`). |

---
### 2.3 Peers Section (`peers`)

The `peers` section defines cluster membership for synchronizing stick-table contents across multiple HAProxy instances or across multi-core worker threads.

| Keyword | Syntax | Status (3.5) | Description & Alcyon Architecture |
|---|---|---|---|
| `peers` | `peers <name>` | Standard | Begins a peers cluster definition block. |
| `peer` | `peer <name> <addr>:<port>` | Standard | Defines a remote peer host address and synchronization TCP listener port. |
| `server` | `server <name> [<addr>:<port>] [param*]`| Standard | Alternative modern declaration treating peers as dynamic servers with health checks. |
| `bind` | `bind <addr>:<port> [param*]` | Standard | Defines the local incoming peer synchronization listening socket. |
| `default-bind` | `default-bind [param*]` | Standard | Sets default socket parameters for peer listeners. |
| `default-server`| `default-server [param*]`| Standard | Sets default server parameters for remote peer connections. |
| `shards` | `shards <num>` | New in 3.x | Partitions stick tables into $N$ parallel shards for multi-core peer synchronization. |
| `table` | `table <name> type <type> size <sz> [param*]`| Standard | Stick-table declared directly within the peers section for automatic cluster sync. |
| `log` | `log <addr> [param*]` | Standard | Configures syslog target for peer connection events and sync errors. |
| `disabled` | `disabled` | Standard | Disables synchronization for the designated peers section. |
| `enabled` | `enabled` | Standard | Enables the peers section (default state). |

---

### 2.4 Mailers Section (`mailers`)

The `mailers` section configures SMTP servers used by proxies to dispatch email notifications upon critical server health state transitions.

| Keyword | Syntax | Status (3.5) | Description & Alcyon Architecture |
|---|---|---|---|
| `mailers` | `mailers <name>` | Standard | Begins an SMTP mailer cluster definition block. |
| `mailer` | `mailer <name> <addr>:<port>` | Standard | Declares an outbound SMTP relay server endpoint. |
| `timeout mail` | `timeout mail <time>` | Standard | Maximum duration allowed for the SMTP handshake and transaction (default 10s). |

---

### 2.5 Cache Section (`cache`)

The `cache` section declares an in-memory HTTP cache instance adhering to RFC 9111 HTTP Caching semantics, referenced by `http-request cache-use` and `http-response cache-store`.

| Keyword | Syntax | Status (3.5) | Description & Alcyon Architecture |
|---|---|---|---|
| `cache` | `cache <name>` | Standard | Begins an in-memory RFC 9111 cache definition block. |
| `total-max-size` | `total-max-size <megabytes>` | Standard | Global RAM ceiling allocated to this cache instance in megabytes. |
| `max-object-size`| `max-object-size <bytes>` | Standard | Maximum single response body payload size eligible for caching (in bytes). |
| `max-age` | `max-age <seconds>` | Standard | Default cache retention TTL if no explicit `Cache-Control: max-age` header is present. |
| `process-vary` | `process-vary { on \| off }` | Standard | Enables secondary cache key hashing based on HTTP `Vary` request headers. |
| `early-hints` | `early-hints { on \| off \| only } [ratio <1-99>]` | New in 3.x | Caches and returns HTTP 103 Early Hints before serving cached 200 OK responses. |
| `max-secondary-entries` | `max-secondary-entries <num>`| Standard | Maximum distinct cached variants permitted per primary cache key URI. |

---

### 2.6 Resolvers Section (`resolvers`)

The `resolvers` section configures asynchronous DNS nameservers for runtime backend server IP address resolution, SRV service discovery, and dynamic hostname tracking.

| Keyword | Syntax | Status (3.5) | Description & Alcyon Architecture |
|---|---|---|---|
| `resolvers` | `resolvers <id>` | Standard | Begins a DNS resolution group definition block. |
| `nameserver` | `nameserver <id> <addr>:<port>` | Standard | Declares an upstream DNS nameserver (UDP/TCP fallback). |
| `parse-resolv-conf`| `parse-resolv-conf` | Standard | Imports nameservers and search domains directly from host `/etc/resolv.conf`. |
| `accepted_payload_size`| `accepted_payload_size <bytes>`| Standard | Maximum UDP payload size advertised in EDNS0 extension (512 to 8192, default 512). |
| `resolve_retries` | `resolve_retries <num>` | Standard | Number of query attempts before failing over to the next nameserver. |
| `timeout resolve` | `timeout resolve <time>` | Standard | Timeout for waiting for a DNS response. |
| `timeout retry` | `timeout retry <time>` | Standard | Inter-query delay before resending an unacknowledged DNS query. |
| `hold valid` | `hold valid <time>` | Standard | TTL override caching duration for successful DNS responses. |
| `hold nx` | `hold nx <time>` | Standard | Negative caching duration for non-existent domain (NXDOMAIN) responses. |
| `hold refused` | `hold refused <time>` | Standard | Backoff interval when nameserver returns REFUSED. |
| `hold timeout` | `hold timeout <time>` | Standard | Backoff interval when a query times out. |
| `hold obsolete` | `hold obsolete <time>` | Standard | Grace period to keep obsolete IP addresses active while switching servers. |
| `hold other` | `hold other <time>` | Standard | Backoff interval for other unclassified DNS error codes. |

---

### 2.7 Program Section (`program`) - Status in HAProxy 3.5

#### 2.7.1 Historical Context & Excision Audit
The `program` section was originally introduced in HAProxy 2.0 (commit `9a1ee7ac31c5`) to manage external sidecar processes (such as the Dataplane API) under the master-worker model:
```haproxy
program dataplane-api
    command /usr/local/bin/dataplaneapi -f /etc/dataplaneapi.yaml
    user haproxy
    group haproxy
```
However, managing child process lifecycles, signal propagation (`SIGUSR1`, `SIGTERM`), standard I/O redirection, and crash recovery inside a reverse proxy core proved brittle, prone to zombie processes, and fundamentally misaligned with modern service supervision.

**Complete Removal in HAProxy 3.2+ / 3.5**:
In HAProxy commit `7cb6167d046f1b37c19784fe99b9b6d37ea83c54` ("MAJOR: mworker: remove program section support"), William Lallemand completely excised the `program` section:
> *"This patch removes completely the support for the program section, the parsing of the section as well as the internals in the mworker does not support it anymore. The program section was considered dysfunctional and not fully compatible with the 'mworker V3' model. Users that want to run an external program must use their init system."*

#### 2.7.2 Alcyon Architectural Recommendation
- **Alcyon Parser Behavior**: The `alcyon-config` parser strictly rejects `program` blocks with a structured diagnostic error:
  ```
  error[E0350]: 'program' section is obsolete and was removed in HAProxy 3.2+
    --> haproxy.cfg:42:1
     |
  42 | program dataplane-api
     | ^^^^^^^ external process management is not supported in the dataplane.
     |
     = help: manage sidecar binaries using your system init daemon (systemd, runit) or container orchestrator (Kubernetes, Nomad).
  ```
- **Architectural Tenet**: Adhering to Unix philosophy, Alcyon focuses exclusively on high-performance packet and byte processing, delegating process lifecycle supervision to systemd / cgroups.

---

### 2.8 FastCGI Applications Section (`fcgi-app`)

The `fcgi-app` section configures an upstream FastCGI application gateway (e.g. PHP-FPM, Python FastCGI) for direct proxying without intermediary web servers.

| Keyword | Syntax | Status (3.5) | Description & Alcyon Architecture |
|---|---|---|---|
| `fcgi-app` | `fcgi-app <name>` | Standard | Begins a FastCGI application definition block. |
| `docroot` | `docroot <path>` | Standard | Base document root directory sent in `DOCUMENT_ROOT` FastCGI parameter. |
| `index` | `index <filename>` | Standard | Default script filename appended to directories (e.g. `index.php`). |
| `path-info` | `path-info <regex>` | Standard | Regular expression to extract `PATH_INFO` and `SCRIPT_NAME` from request URI. |
| `acl` | `acl <name> <criterion> ...` | Standard | ACL declaration scoped specifically to the FastCGI environment. |
| `set-param` | `set-param <name> <fmt> [cond]` | Standard | Injects or overrides FastCGI environment variable (e.g. `SCRIPT_FILENAME`). |
| `unset-param` | `unset-param <name> [cond]` | Standard | Removes FastCGI parameter from being transmitted to upstream backend. |
| `pass-header` | `pass-header <name> [cond]` | Standard | Explicitly forwards client HTTP header to FastCGI application. |
| `hide-header` | `hide-header <name> [cond]` | Standard | Strips client HTTP header before generating FastCGI params. |
| `option keep-conn` | `option keep-conn` | Standard | Keeps FastCGI connection open across requests (`FCGI_KEEP_CONN`). |
| `option get-values` | `option get-values` | Standard | Queries application capabilities via `FCGI_GET_VALUES` record on connection open. |
| `option mpxs-conns` | `option mpxs-conns` | Standard | Authorizes connection multiplexing across multiple concurrent FastCGI requests. |
| `option max-reqs` | `option max-reqs <num>` | Standard | Maximum concurrent requests multiplexed over a single FastCGI connection. |
| `log-stderr` | `log-stderr <target>` | Standard | Directs application `STDERR` log records to specified syslog or ring sink. |

---

### 2.9 Ring Buffers Section (`ring`)

The `ring` section configures a fixed-capacity, lock-free, zero-allocation circular memory buffer used for internal log aggregation, tracing, and CLI inspection.

| Keyword | Syntax | Status (3.5) | Description & Alcyon Architecture |
|---|---|---|---|
| `ring` | `ring <name>` | Standard | Begins a circular ring buffer definition block. |
| `size` | `size <bytes>` | Standard | Allocates fixed byte capacity for the circular buffer (power of 2 recommended). |
| `backing-file` | `backing-file <path>` | Standard | Backs the ring buffer with an `mmap()` file for persistence across reloads. |
| `format` | `format { local \| rfc3164 \| rfc5424 \| priority \| short \| raw }` | Standard | Selects framing format for messages written into the buffer. |
| `maxlen` | `maxlen <bytes>` | Standard | Truncates individual log lines exceeding this byte threshold. |
| `server` | `server <name> <addr>:<port> [param*]` | Standard | Upstream syslog forwarder server draining messages from the ring buffer. |
| `timeout connect`| `timeout connect <time>` | Standard | Connection timeout to upstream syslog forwarder server. |
| `timeout server` | `timeout server <time>` | Standard | Inactivity timeout on the upstream forwarder connection. |
| `description` | `description <text>` | Standard | Administrative description displayed in stats and CLI listings. |

---

### 2.10 Ancillary Sections (`userlist`, `http-errors`, `log-forward`, `crt-store`, `acme`)

| Section | Key Directives | Status (3.5) | Description & Alcyon Architecture |
|---|---|---|---|
| `userlist <name>` | `user <name> [password\|insecure-password <pwd>] [groups <g>]`, `group <name> [users <u>]` | Standard | In-memory authentication database for HTTP Basic Auth (`http-request auth`). |
| `http-errors <name>` | `errorfile <code> <path>`, `http-error status <code> [headers/body]` | Standard | Reusable dictionary of custom error pages shared across multiple proxies. |
| `log-forward <name>` | `bind`, `dgram-bind`, `log`, `log-format`, `log-profile` | Standard | High-performance syslog forwarding and fanout proxy pipeline. |
| `crt-store <name>` | `load-ca`, `load-crt`, `load-key`, `load-bundle` | Standard | Centralized dynamic TLS certificate catalog loaded and updated via CLI. |
| `acme <name>` | `account-key`, `directory`, `challenge-path`, `order` | New in 3.x | Automated ACME (Let's Encrypt) TLS certificate provisioning state machine. |
| `healthcheck <name>` | `tcp-check`, `http-check` | New in 3.x | Standalone reusable health check profiles shared across multiple backends. |

---
## 3. Exhaustive L7 Action Rules Catalog

HAProxy 3.5 executes HTTP actions across three discrete pipeline stages:
1. `http-request <action>`: Evaluated as soon as HTTP request headers are parsed, before forwarding upstream.
2. `http-response <action>`: Evaluated upon receiving HTTP response headers from the upstream backend, before buffering.
3. `http-after-response <action>`: Evaluated late in the response cycle, after caching, compression, and final response header finalization.

### 3.1 `http-request <action>` Reference

| Action | Syntax | Status (3.5) | Description & Technical Execution |
|---|---|---|---|
| `set-header` | `set-header <name> <fmt>` | Standard | Replaces all occurrences of header `<name>` with formatted string `<fmt>`. If not present, appends it. |
| `add-header` | `add-header <name> <fmt>` | Standard | Appends a new header `<name>` with value `<fmt>`, preserving existing headers with the same name. |
| `del-header` | `del-header [-m <meth>] <name>` | Standard | Deletes all headers matching `<name>`. Supports matching methods (`-m str`, `-m sub`, `-m reg`). |
| `replace-header`| `replace-header <name> <regex> <fmt>` | Standard | Matches regex against header value and replaces matching text with `<fmt>`. |
| `replace-value` | `replace-value <name> <regex> <fmt>` | Standard | Tokenizes delimited header values (e.g. `Cache-Control`, `Accept`) and replaces matching tokens. |
| `add-headers-bin`| `add-headers-bin <sample>` | New in 3.x | Decodes binary sample and injects structured binary headers into the HTTP transaction. |
| `del-headers-bin`| `del-headers-bin <sample>` | New in 3.x | Deletes headers identified by binary token expression. |
| `set-headers-bin`| `set-headers-bin <sample>` | New in 3.x | Replaces headers using binary serialized payload. |
| `early-hint` | `early-hint <name> <fmt>` | Standard | Sends an immediate HTTP 103 Early Hints response containing the specified Link header to client. |
| `set-path` | `set-path <fmt>` | Standard | Rewrites request URI path component while preserving query string. Updates HTX pseudo-headers. |
| `set-pathq` | `set-pathq <fmt>` | Standard | Rewrites request URI path and query string simultaneously. |
| `set-query` | `set-query <fmt>` | Standard | Rewrites request URI query string component (omitting leading `?`). |
| `set-uri` | `set-uri <fmt>` | Standard | Rewrites the entire HTTP request URI (scheme, host, path, query). |
| `set-method` | `set-method <fmt>` | Standard | Rewrites the HTTP request method verb (e.g. converting `POST` to `GET`). |
| `replace-path` | `replace-path <regex> <fmt>` | Standard | Applies regular expression replacement against the request URI path. |
| `replace-pathq`| `replace-pathq <regex> <fmt>` | Standard | Applies regex replacement against URI path and query together. |
| `replace-uri` | `replace-uri <regex> <fmt>` | Standard | Applies regex replacement across the full request URI. |
| `normalize-uri`| `normalize-uri <normalizer> [args]` | Standard | Normalizes URI paths to defeat path traversal attacks: `path-strip-dotdot`, `path-strip-dot`, `percent-decode-unreserved`, `percent-to-uppercase`, `query-sort-by-name`. |
| `allow` | `allow` | Standard | Halts further `http-request` rule evaluation and immediately approves request for forwarding. |
| `deny` | `deny [deny_status <status>] [hdr <name> <fmt>]` | Standard | Rejects request with an immediate HTTP error response (default 403 Forbidden). |
| `return` | `return status <status> [content-type <t>] [default-errorfiles] [errorfile <f>] [file <f>] [string <s>] [hdr <h> <v> ...]` | Standard | Emits an immediate synthetic HTTP response without touching backends. Zero backend connection overhead. |
| `redirect` | `redirect <scheme\|location\|prefix> <target> [code <301\|302\|303\|307\|308>]` | Standard | Emits an HTTP redirect response with designated target location and status code. |
| `tarpit` | `tarpit [deny_status <status>]` | Standard | Holds connection open for `timeout tarpit` before closing or returning error, exhausting attacker sockets. |
| `silent-drop` | `silent-drop` | Standard | Immediately drops the underlying TCP socket without sending FIN/RST packets. |
| `reject` | `reject` | Standard | Immediately closes connection by sending a TCP RST packet. |
| `pause` | `pause <time>` | Standard | Suspends request processing on the event loop for designated duration for traffic pacing. |
| `track-sc0` | `track-sc0 <key> [table <tab>]` | Standard | Tracks sticky session counter 0 for key `<key>` in the designated or current stick-table. |
| `track-sc1` | `track-sc1 <key> [table <tab>]` | Standard | Tracks sticky session counter 1. |
| `track-sc2` | `track-sc2 <key> [table <tab>]` | Standard | Tracks sticky session counter 2. |
| `track-sc*` | `track-sc<N> <key> [table <tab>]`| Standard | Modern extensible tracking counter for dynamic counter slots $N \ge 0$. |
| `sc-inc-gpc` | `sc-inc-gpc(<idx>) <sc-id>` | Standard | Increments General Purpose Counter at `<idx>` in the stick table tracked by `<sc-id>`. |
| `sc-inc-gpc0` | `sc-inc-gpc0 <sc-id>` | Standard | Increments GPC 0 in the stick table tracked by `<sc-id>`. |
| `sc-inc-gpc1` | `sc-inc-gpc1 <sc-id>` | Standard | Increments GPC 1 in the stick table tracked by `<sc-id>`. |
| `sc-add-gpc` | `sc-add-gpc(<idx>) <sc-id> <val>`| Standard | Adds `<val>` to General Purpose Counter `<idx>`. |
| `sc-set-gpt` | `sc-set-gpt(<idx>) <sc-id> <val>`| Standard | Sets General Purpose Tag `<idx>` in the stick table entry to `<val>`. |
| `sc-set-gpt0` | `sc-set-gpt0 <sc-id> <val>` | Standard | Sets General Purpose Tag 0. |
| `set-var` | `set-var(<var-name>) <expr>` | Standard | Evaluates sample expression and stores typed result into variable (`req.*`, `txn.*`, `sess.*`). |
| `set-var-fmt` | `set-var-fmt(<var-name>) <fmt>` | Standard | Evaluates custom log format string and stores string result into variable. |
| `unset-var` | `unset-var(<var-name>)` | Standard | Unbinds and deallocates the designated variable from memory. |
| `auth` | `auth [realm <realm>]` | Standard | Enforces HTTP Basic Authentication against the proxy's declared `userlist`. Returns 401 on failure. |
| `cache-use` | `cache-use <cache-name>` | Standard | Consults declared RFC 9111 cache; if cache hit occurs, serves response immediately and halts pipeline. |
| `capture` | `capture <sample> id <id>` | Standard | Evaluates `<sample>` and records result into pre-declared capture slot `<id>` for access logging. |
| `send-spoe-group`| `send-spoe-group <engine> <group>`| Standard | Triggers asynchronous Stream Processing Offload Engine (SPOE) notification frame to out-of-process agent. |
| `set-bandwidth-limit`| `set-bandwidth-limit <limit> [key <key>]`| Standard | Enforces dynamic bandwidth throttling filter on the current stream. |
| `do-resolve` | `do-resolve(<var-name>, <resolvers> [, <ipv>]) <expr>` | Standard | Performs asynchronous DNS query on hostname extracted from `<expr>` and stores IP in `<var>`. |
| `disable-l7-retry`| `disable-l7-retry` | Standard | Disables automatic backend connection retry if transaction fails midway through body streaming. |
| `do-log` | `do-log` | Standard | Forces logging of the current transaction even if `option dontlognull` or `dontlog-normal` matched. |
| `set-dst` | `set-dst <expr>` | Standard | Overrides upstream destination IP address dynamically using expression result. |
| `set-dst-port`| `set-dst-port <expr>` | Standard | Overrides upstream destination port dynamically. |
| `set-src` | `set-src <expr>` | Standard | Overrides client source IP address for subsequent rules and backend logging. |
| `set-src-port`| `set-src-port <expr>` | Standard | Overrides client source port. |
| `set-fc-mark` | `set-fc-mark <mark>` | Standard | Sets Linux kernel `SO_MARK` on the downstream client socket. |
| `set-fc-tos` | `set-fc-tos <tos>` | Standard | Sets IP Type of Service / DSCP byte on the downstream client socket. |
| `set-bc-mark` | `set-bc-mark <mark>` | Standard | Sets Linux `SO_MARK` on the upstream backend socket. |
| `set-bc-tos` | `set-bc-tos <tos>` | Standard | Sets IP ToS on the upstream backend socket. |
| `set-mark` | `set-mark <mark>` | Deprecated | Legacy socket mark setter; deprecated in 3.5 in favor of `set-fc-mark`. |
| `set-tos` | `set-tos <tos>` | Deprecated | Legacy socket ToS setter; deprecated in 3.5 in favor of `set-fc-tos`. |
| `set-log-level`| `set-log-level <level>` | Standard | Dynamically adjusts syslog severity level for this specific transaction. |
| `set-nice` | `set-nice <nice>` | Standard | Adjusts thread task priority nice value (-1024 to 1024) in `alcyon-sched`. |
| `set-priority-class`| `set-priority-class <expr>` | Standard | Assigns stream to a connection queue priority class. |
| `set-priority-offset`| `set-priority-offset <expr>`| Standard | Adjusts stream queue priority offset for aging acceleration. |
| `set-retries` | `set-retries <expr>` | Standard | Dynamically overrides backend retry limit. |
| `set-timeout` | `set-timeout <timeout-type> <time>` | Standard | Dynamically overrides session timeouts (`server`, `tunnel`, `http-request`, `queue`). |
| `strict-mode` | `strict-mode { on \| off }` | Standard | Toggles strict HTTP conformance checks on header syntax and chunk delimiters. |
| `use-service` | `use-service <service-name>` | Standard | Routes request directly into an internal service applet (e.g. Prometheus `prometheus-exporter`). |
| `wait-for-body`| `wait-for-body time <time> [at-least <bytes>]`| Standard | Buffers request body up to `<bytes>` or `<time>` before evaluating subsequent L7 rules. |
| `wait-for-handshake`| `wait-for-handshake` | Standard | Postpones request evaluation until downstream TLS handshake is fully finalized. |

---

### 3.2 `http-response <action>` Reference

| Action | Syntax | Status (3.5) | Description & Technical Execution |
|---|---|---|---|
| `set-header` | `set-header <name> <fmt>` | Standard | Replaces or injects HTTP header into the response sent to client. |
| `add-header` | `add-header <name> <fmt>` | Standard | Appends HTTP response header, preserving multi-value headers. |
| `del-header` | `del-header [-m <meth>] <name>` | Standard | Strips sensitive backend response headers (e.g. `Server`, `X-Powered-By`). |
| `replace-header`| `replace-header <name> <regex> <fmt>` | Standard | Regex replacement on response header value. |
| `replace-value` | `replace-value <name> <regex> <fmt>` | Standard | Tokenized delimiter regex replacement on response header values. |
| `set-status` | `set-status <status> [reason <str>]` | Standard | Rewrites HTTP response status code and optional reason phrase (e.g. masking 500 with 503). |
| `cache-store` | `cache-store <cache-name>` | Standard | Stores eligible HTTP response into the designated RFC 9111 cache instance. |
| `allow` | `allow` | Standard | Halts further `http-response` evaluation and transmits response downstream. |
| `deny` | `deny [deny_status <status>]` | Standard | Intercepts backend response and substitutes an immediate HTTP error response. |
| `return` | `return status <status> [param*]` | Standard | Substitutes response with synthetic response payload. |
| `redirect` | `redirect <target> [code <code>]` | Standard | Overrides backend response with an immediate redirect. |
| `silent-drop` | `silent-drop` | Standard | Kills client TCP connection without response. |
| `track-sc0..2`| `track-sc<N> <key> [table <tab>]` | Standard | Tracks session counters using samples extracted from response headers. |
| `set-var` | `set-var(<name>) <expr>` | Standard | Extracts response sample and records into variable. |
| `set-var-fmt` | `set-var-fmt(<name>) <fmt>` | Standard | Records formatted log string into variable. |
| `unset-var` | `unset-var(<name>)` | Standard | Unsets response variable. |
| `capture` | `capture <sample> id <id>` | Standard | Records response sample into capture slot for logging. |
| `send-spoe-group`| `send-spoe-group <engine> <group>`| Standard | Dispatches SPOE notification upon response receipt. |
| `set-bandwidth-limit`| `set-bandwidth-limit <limit>` | Standard | Throttles response egress bandwidth. |
| `set-fc-mark` | `set-fc-mark <mark>` | Standard | Sets socket mark on client connection upon response. |
| `set-fc-tos` | `set-fc-tos <tos>` | Standard | Sets ToS byte on client connection upon response. |
| `set-log-level`| `set-log-level <level>` | Standard | Dynamically overrides log level based on response criteria (e.g. log 5xx as alert). |
| `set-nice` | `set-nice <nice>` | Standard | Dynamically deprioritizes task priority for large streaming responses. |
| `set-timeout` | `set-timeout <timeout-type> <time>` | Standard | Modifies tunnel or client timeouts dynamically based on response headers. |
| `strict-mode` | `strict-mode { on \| off }` | Standard | Enforces strict response verification. |
| `wait-for-body`| `wait-for-body time <time> [at-least <bytes>]`| Standard | Buffers response payload before downstream transmission. |

---

### 3.3 `http-after-response <action>` Reference

`http-after-response` rules execute after response body filtering, caching, and compression, providing the definitive final opportunity to modify headers before wire serialization.

| Action | Syntax | Status (3.5) | Description & Technical Execution |
|---|---|---|---|
| `set-header` | `set-header <name> <fmt>` | Standard | Guarantees header injection even after caching or compression filters ran. |
| `add-header` | `add-header <name> <fmt>` | Standard | Appends header in the final serialization stage (e.g. `X-Cache-Status`, `Server-Timing`). |
| `del-header` | `del-header [-m <meth>] <name>` | Standard | Final stripped header removal. |
| `replace-header`| `replace-header <name> <regex> <fmt>` | Standard | Final header regex replacement. |
| `replace-value` | `replace-value <name> <regex> <fmt>` | Standard | Final tokenized value replacement. |
| `set-status` | `set-status <status> [reason <str>]` | Standard | Final status code rewrite. |
| `allow` | `allow` | Standard | Finalizes response processing and dispatches bytes to network. |
| `capture` | `capture <sample> id <id>` | Standard | Captures final post-compression response sizes and metrics. |
| `set-var` | `set-var(<name>) <expr>` | Standard | Saves final metrics into transaction variables. |
| `set-var-fmt` | `set-var-fmt(<name>) <fmt>` | Standard | Saves formatted string into variable. |
| `unset-var` | `unset-var(<name>)` | Standard | Cleans up variable. |
| `set-log-level`| `set-log-level <level>` | Standard | Overrides final log severity. |
| `strict-mode` | `strict-mode { on \| off }` | Standard | Enforces final strict validation. |
| `do-log` | `do-log` | Standard | Enforces logging at response termination. |

---
## 4. Exhaustive L4 Action Rules Catalog

HAProxy 3.5 provides four discrete L4 rule sets evaluated sequentially as a raw stream connection progresses:
1. `tcp-request connection`: Evaluated immediately upon socket `accept()`, before any handshake or data reception. Only L4 transport socket metadata (IP addresses, ports) is available.
2. `tcp-request session`: Evaluated after L5 handshakes (TLS negotiation, PROXY protocol reception) are completed.
3. `tcp-request content`: Evaluated after client payload data enters the receive buffer (gated by `tcp-request inspect-delay`). L6/L7 protocol inspection is possible.
4. `tcp-response content`: Evaluated on response payload data received from the upstream server before transmission to client.

---

### 4.1 `tcp-request connection <action>` Reference

| Action | Syntax | Status (3.5) | Description & Technical Execution |
|---|---|---|---|
| `accept` | `accept` | Standard | Halts connection rule evaluation and allows client socket to proceed to session setup. |
| `reject` | `reject` | Standard | Closes connection immediately with a TCP RST. Primary L4 DDoS mitigation tool. |
| `silent-drop` | `silent-drop` | Standard | Drops socket without RST or FIN packet, consuming attacker state table entries. |
| `track-sc0..2`| `track-sc<N> <key> [table <tab>]` | Standard | Initializes stick table tracking immediately on connection open (e.g. `src` IP connection rate limiting). |
| `expect-proxy` | `expect-proxy layer4` | Standard | Enforces PROXY protocol v1/v2 header requirement immediately upon connection. |
| `expect-netscaler-cip`| `expect-netscaler-cip layer4` | Standard | Enforces NetScaler Client IP insertion header. |
| `set-src` | `set-src <expr>` | Standard | Overrides client IP address before session initialization. |
| `set-src-port`| `set-src-port <expr>` | Standard | Overrides client source port. |
| `set-dst` | `set-dst <expr>` | Standard | Overrides destination address. |
| `set-dst-port`| `set-dst-port <expr>` | Standard | Overrides destination port. |
| `set-fc-mark` | `set-fc-mark <mark>` | Standard | Sets socket mark on incoming client connection. |
| `set-fc-tos` | `set-fc-tos <tos>` | Standard | Sets ToS byte on incoming client connection. |
| `set-var` | `set-var(<name>) <expr>` | Standard | Records connection-scoped sample into variable (`proc.*`, `sess.*`). |
| `set-var-fmt` | `set-var-fmt(<name>) <fmt>` | Standard | Records formatted string into variable. |
| `unset-var` | `unset-var(<name>)` | Standard | Clears connection variable. |
| `sc-inc-gpc` | `sc-inc-gpc(<idx>) <sc-id>` | Standard | Increments stick-table General Purpose Counter on connection. |
| `sc-set-gpt` | `sc-set-gpt(<idx>) <sc-id> <val>`| Standard | Sets General Purpose Tag on connection. |
| `do-log` | `do-log` | Standard | Forces emission of a connection log entry. |

---

### 4.2 `tcp-request session <action>` Reference

| Action | Syntax | Status (3.5) | Description & Technical Execution |
|---|---|---|---|
| `accept` | `accept` | Standard | Approves session and transitions connection to content evaluation phase. |
| `reject` | `reject` | Standard | Rejects session after TLS/PROXY handshake inspection (e.g. invalid SNI or cipher). |
| `silent-drop` | `silent-drop` | Standard | Silently discards connection without response. |
| `attach-srv` | `attach-srv <srv-name>` | Standard | Manually binds session directly to a designated server without running load balancing. |
| `track-sc0..2`| `track-sc<N> <key> [table <tab>]` | Standard | Tracks session counters with metadata available after TLS handshake (e.g. SNI, cipher). |
| `set-var` | `set-var(<name>) <expr>` | Standard | Records session variables. |
| `set-var-fmt` | `set-var-fmt(<name>) <fmt>` | Standard | Records formatted session variable. |
| `unset-var` | `unset-var(<name>)` | Standard | Cleans up session variable. |
| `set-fc-mark` | `set-fc-mark <mark>` | Standard | Sets client socket mark. |
| `set-fc-tos` | `set-fc-tos <tos>` | Standard | Sets client socket ToS. |
| `do-log` | `do-log` | Standard | Forces session log entry emission. |

---

### 4.3 `tcp-request content <action>` Reference

| Action | Syntax | Status (3.5) | Description & Technical Execution |
|---|---|---|---|
| `accept` | `accept` | Standard | Approves content payload and advances stream to backend forwarding or HTTP analysis. |
| `reject` | `reject` | Standard | Rejects connection based on initial payload byte inspection. |
| `silent-drop` | `silent-drop` | Standard | Silently drops connection upon inspection failure. |
| `track-sc0..2`| `track-sc<N> <key> [table <tab>]` | Standard | Tracks stick table counters using payload sample fetches (e.g. payload hex, RDP cookie). |
| `capture` | `capture <sample> [len <len>]` | Standard | Captures raw payload bytes into session capture buffer for L4 access logging. |
| `do-resolve` | `do-resolve(<var>, <resolvers> [, <ipv>]) <expr>` | Standard | Performs asynchronous DNS resolution for hostnames extracted from L4 payloads. |
| `send-spoe-group`| `send-spoe-group <engine> <group>`| Standard | Forwards raw L4 payload buffer to SPOE agent for external deep packet inspection. |
| `set-bandwidth-limit`| `set-bandwidth-limit <limit>` | Standard | Enforces bandwidth rate limiter on the TCP stream. |
| `switch-mode` | `switch-mode { proto <p> \| http }`| Standard | Dynamically switches stream analyzer mode based on initial payload sniffing. |
| `use-service` | `use-service <service>` | Standard | Directs stream into an internal service applet. |
| `set-priority-class`| `set-priority-class <expr>` | Standard | Assigns TCP stream to priority queuing class. |
| `set-priority-offset`| `set-priority-offset <expr>`| Standard | Adjusts queue aging priority offset. |
| `set-retries` | `set-retries <expr>` | Standard | Dynamically sets connection retry budget. |
| `set-dst` | `set-dst <expr>` | Standard | Dynamically routes stream to destination IP determined by payload bytes. |
| `set-dst-port`| `set-dst-port <expr>` | Standard | Dynamically overrides destination port. |
| `set-src` | `set-src <expr>` | Standard | Overrides client IP address. |
| `set-src-port`| `set-src-port <expr>` | Standard | Overrides client source port. |
| `set-fc-mark` | `set-fc-mark <mark>` | Standard | Sets socket mark on client socket. |
| `set-fc-tos` | `set-fc-tos <tos>` | Standard | Sets ToS on client socket. |
| `set-bc-mark` | `set-bc-mark <mark>` | Standard | Sets socket mark on upstream server socket. |
| `set-bc-tos` | `set-bc-tos <tos>` | Standard | Sets ToS on upstream server socket. |
| `set-log-level`| `set-log-level <level>` | Standard | Dynamically sets logging severity. |
| `set-nice` | `set-nice <nice>` | Standard | Sets task nice priority in event scheduler. |
| `set-var` | `set-var(<name>) <expr>` | Standard | Stores payload sample into variable. |
| `set-var-fmt` | `set-var-fmt(<name>) <fmt>` | Standard | Stores formatted log string into variable. |
| `unset-var` | `unset-var(<name>)` | Standard | Unsets variable. |
| `do-log` | `do-log` | Standard | Forces log emission on content inspection. |

---

### 4.4 `tcp-response content <action>` Reference

| Action | Syntax | Status (3.5) | Description & Technical Execution |
|---|---|---|---|
| `accept` | `accept` | Standard | Approves server response payload and begins forwarding downstream to client. |
| `reject` | `reject` | Standard | Rejects server response payload, terminating connection to protect client. |
| `close` | `close` | Standard | Sends a clean TCP FIN to both client and server upon inspecting response payload. |
| `silent-drop` | `silent-drop` | Standard | Silently drops connection. |
| `capture` | `capture <sample> [len <len>]` | Standard | Captures raw response payload bytes for logging. |
| `send-spoe-group`| `send-spoe-group <engine> <group>`| Standard | Sends response payload to SPOE filter agent. |
| `set-bandwidth-limit`| `set-bandwidth-limit <limit>` | Standard | Throttles egress bandwidth of server response data. |
| `set-fc-mark` | `set-fc-mark <mark>` | Standard | Sets client socket mark based on response payload criteria. |
| `set-fc-tos` | `set-fc-tos <tos>` | Standard | Sets client socket ToS. |
| `set-log-level`| `set-log-level <level>` | Standard | Dynamically overrides log severity based on response bytes. |
| `set-nice` | `set-nice <nice>` | Standard | Dynamically adjusts task scheduling priority. |
| `set-var` | `set-var(<name>) <expr>` | Standard | Records response payload sample into variable. |
| `set-var-fmt` | `set-var-fmt(<name>) <fmt>` | Standard | Stores formatted string into variable. |
| `unset-var` | `unset-var(<name>)` | Standard | Cleans up variable. |
| `do-log` | `do-log` | Standard | Forces emission of response log. |

---
## 5. Sample Fetches, Converters & ACL Matchers Catalog

Sample fetches extract runtime data from network sockets, TLS sessions, HTTP/1.x, HTTP/2, and HTTP/3 protocol structures, and internal rate counters. Converters transform samples through pipelines of string manipulation, hashing, mathematical evaluation, cryptographic verification, and map table lookups. ACLs match sample fetch and converter outputs against criteria to produce boolean branching decisions.

### 5.1 Sample Fetches Taxonomy & Core Inventory

HAProxy 3.5 registers **570 distinct sample fetch methods** across 24 active static registration tables.

#### 5.1.1 Fetch Output Type Lattice (`sample-t.h`)
Fetches return values typed according to HAProxy's internal type lattice:
- `SMP_T_BOOL` (Boolean 0/1, 37 fetches)
- `SMP_T_SINT` (Signed 64-bit integer, 325 fetches)
- `SMP_T_ADDR` / `SMP_T_IPV4` / `SMP_T_IPV6` (IP address structures, 13 fetches)
- `SMP_T_STR` (Character string pointer and length, 141 fetches)
- `SMP_T_BIN` (Raw binary buffer chunk, 47 fetches)
- `SMP_T_METH` (HTTP request method token, 2 fetches)
- `SMP_T_ANY` (Polymorphic generic pseudo-type, 5 fetches)

#### 5.1.2 Essential Sample Fetches Matrix

| Category | Sample Fetch | Output Type | Description & Alcyon Processing Engine |
|---|---|---|---|
| **Layer 4 Socket** | `src` | `SMP_T_ADDR` | Client socket source IP address (IPv4 or IPv6). |
| | `src_port` | `SMP_T_SINT` | Client socket source TCP/UDP port number. |
| | `dst` | `SMP_T_ADDR` | Local listening socket destination IP address. |
| | `dst_port` | `SMP_T_SINT` | Local listening socket destination port number. |
| | `so_id` | `SMP_T_SINT` | Socket ID assigned by the operating system. |
| | `fe_id` | `SMP_T_SINT` | Unique integer ID of the accepting frontend. |
| | `fe_name` | `SMP_T_STR` | String name of the accepting frontend. |
| | `be_id` | `SMP_T_SINT` | Unique integer ID of the assigned backend. |
| | `be_name` | `SMP_T_STR` | String name of the assigned backend. |
| | `srv_id` | `SMP_T_SINT` | Unique integer ID of the selected target server. |
| | `srv_name` | `SMP_T_STR` | String identifier of the selected target server. |
| **Layer 5 TLS / SSL** | `ssl_fc` | `SMP_T_BOOL` | Returns true if downstream frontend connection is over TLS. |
| | `ssl_fc_sni` | `SMP_T_STR` | Server Name Indication (SNI) string sent by client in ClientHello. |
| | `ssl_fc_alpn` | `SMP_T_STR` | Negotiated Application-Layer Protocol Negotiation (e.g. `h2`, `http/1.1`). |
| | `ssl_fc_cipher` | `SMP_T_STR` | Cipher suite name negotiated on downstream connection. |
| | `ssl_fc_protocol`| `SMP_T_STR` | TLS protocol version negotiated (e.g. `TLSv1.3`, `TLSv1.2`). |
| | `ssl_fc_is_resumed`| `SMP_T_BOOL` | True if connection resumed a previous TLS session ticket or ID. |
| | `ssl_c_verify` | `SMP_T_SINT` | Client certificate verification result code (0 = success). |
| | `ssl_c_s_dn` | `SMP_T_STR` | Subject Distinguished Name of client TLS certificate. |
| | `ssl_c_i_dn` | `SMP_T_STR` | Issuer Distinguished Name of client TLS certificate. |
| | `ssl_c_sha1` | `SMP_T_BIN` | SHA-1 fingerprint of client TLS certificate. |
| | `ssl_bc` | `SMP_T_BOOL` | Returns true if upstream backend connection is over TLS. |
| | `ssl_bc_alpn` | `SMP_T_STR` | ALPN negotiated with upstream backend server. |
| **Layer 7 HTTP Request**| `req.hdr([<name>[,<occ>]])`| `SMP_T_STR` | Extracts HTTP request header value. Supports occurrence indexing (`-1` = last). |
| | `req.hdr_cnt([<name>])` | `SMP_T_SINT` | Returns total number of occurrences of specified header name. |
| | `req.hdr_names([<delim>])`| `SMP_T_STR` | Returns delimited list of all header names present in request. |
| | `method` | `SMP_T_METH` | HTTP request method verb (`GET`, `POST`, `PUT`, `DELETE`, etc.). |
| | `path` | `SMP_T_STR` | HTTP request URI path (excluding query string, normalized). |
| | `query` | `SMP_T_STR` | HTTP request URI query string (excluding leading `?`). |
| | `url` | `SMP_T_STR` | Full HTTP request URI as transmitted on the wire. |
| | `url_param(<name>[,<delim>])`| `SMP_T_STR` | Extracts query parameter value matching `<name>`. |
| | `req.ver` | `SMP_T_STR` | HTTP protocol version string (`HTTP/1.1`, `HTTP/2.0`, `HTTP/3.0`). |
| | `req.body` | `SMP_T_BIN` | Raw buffered HTTP request body payload chunk. |
| | `req.body_len` | `SMP_T_SINT` | Length of buffered HTTP request body payload. |
| | `req.body_param(<name>)`| `SMP_T_STR` | Extracts parameter from `application/x-www-form-urlencoded` body. |
| | `capture.req.hdr(<idx>)` | `SMP_T_STR` | Extracts captured request header from slot `<idx>`. |
| | `capture.req.method` | `SMP_T_STR` | Captured HTTP request method string. |
| | `capture.req.uri` | `SMP_T_STR` | Captured HTTP request URI string. |
| **Layer 7 HTTP Response**| `res.hdr([<name>[,<occ>]])`| `SMP_T_STR` | Extracts HTTP response header value. |
| | `status` | `SMP_T_SINT` | HTTP response status code (e.g. 200, 404, 503). |
| | `res.ver` | `SMP_T_STR` | Upstream backend HTTP response protocol version. |
| | `res.body` | `SMP_T_BIN` | Raw buffered HTTP response body payload chunk. |
| | `res.body_len` | `SMP_T_SINT` | Length of buffered HTTP response body payload. |
| | `capture.res.hdr(<idx>)` | `SMP_T_STR` | Extracts captured response header from slot `<idx>`. |
| **Stick Table Counters**| `sc_conn_cnt(<sc-id>)` | `SMP_T_SINT` | Cumulative connection count for tracked stick table entry. |
| | `sc_conn_cur(<sc-id>)` | `SMP_T_SINT` | Current concurrent open connections for tracked entry. |
| | `sc_conn_rate(<sc-id>)` | `SMP_T_SINT` | Connection rate over configured period for tracked entry. |
| | `sc_sess_cnt(<sc-id>)` | `SMP_T_SINT` | Cumulative session count for tracked entry. |
| | `sc_sess_rate(<sc-id>)` | `SMP_T_SINT` | Session establishment rate over period. |
| | `sc_http_req_cnt(<sc-id>)`| `SMP_T_SINT` | Cumulative HTTP request count for tracked entry. |
| | `sc_http_req_rate(<sc-id>)`| `SMP_T_SINT`| HTTP request rate over sliding window period. Key for rate limiting. |
| | `sc_http_err_cnt(<sc-id>)`| `SMP_T_SINT` | Cumulative HTTP error count (4xx/5xx) for tracked entry. |
| | `sc_http_err_rate(<sc-id>)`| `SMP_T_SINT`| HTTP error rate over period. |
| | `sc_bytes_in_rate(<sc-id>)`| `SMP_T_SINT`| Incoming byte throughput rate for tracked entry. |
| | `sc_bytes_out_rate(<sc-id>)`| `SMP_T_SINT`| Outgoing byte throughput rate for tracked entry. |
| | `sc_get_gpc(<idx>,<sc-id>)`| `SMP_T_SINT`| Value of General Purpose Counter at `<idx>`. |
| | `sc_get_gpt(<idx>,<sc-id>)`| `SMP_T_SINT`| Value of General Purpose Tag at `<idx>`. |
| | `sc_tracked(<sc-id>)` | `SMP_T_BOOL` | Returns true if session counter `<sc-id>` is currently actively tracked. |
| **System & Internal** | `date([<offset>])` | `SMP_T_SINT` | Current system epoch timestamp in seconds (with optional offset). |
| | `rand([<range>])` | `SMP_T_SINT` | Pseudo-random integer between 0 and `<range>-1`. |
| | `env(<var-name>)` | `SMP_T_STR` | Environment variable value retrieved from the host process. |
| | `var(<var-name>)` | `SMP_T_ANY` | Value of custom stored dynamic variable (`proc.*`, `txn.*`, etc.). |
| | `res.cache_hit` | `SMP_T_BOOL` | True if the response was served directly from an RFC 9111 cache instance. |
| | `res.cache_name` | `SMP_T_STR` | Name of the cache instance that fulfilled the request. |

---

### 5.2 Sample Converters Taxonomy & Core Inventory

HAProxy 3.5 registers **211 distinct sample converter keywords**. Converters accept an input sample, evaluate parameterized arguments, and yield a transformed sample.

#### 5.2.1 Converters Categorized Inventory

| Category | Converter Keyword | Input Type | Output Type | Description & Argument Signature |
|---|---|---|---|---|
| **String & Text** | `lower` | `SMP_T_STR` | `SMP_T_STR` | Converts ASCII string characters to lowercase in-place. |
| | `upper` | `SMP_T_STR` | `SMP_T_STR` | Converts ASCII string characters to uppercase in-place. |
| | `concat(<str1>,...)` | `SMP_T_STR` | `SMP_T_STR` | Concatenates multiple strings or variables into a single string. |
| | `bytes(<offset>,<len>)`| `SMP_T_BIN` | `SMP_T_BIN` | Slices a byte buffer from `<offset>` for `<len>` bytes. |
| | `field(<idx>,<delim>)`| `SMP_T_STR` | `SMP_T_STR` | Extracts the $N$-th field from delimited string (1-indexed). |
| | `word(<idx>,<delim>)` | `SMP_T_STR` | `SMP_T_STR` | Extracts the $N$-th non-empty word from delimited string. |
| | `length` | `SMP_T_STR` | `SMP_T_SINT` | Computes string length in bytes. |
| | `trim([<char>])` | `SMP_T_STR` | `SMP_T_STR` | Strips leading and trailing whitespace or designated characters. |
| | `capture-req(<id>)` | `SMP_T_STR` | `SMP_T_STR` | Records converter input directly into request capture slot `<id>`. |
| | `capture-res(<id>)` | `SMP_T_STR` | `SMP_T_STR` | Records converter input directly into response capture slot `<id>`. |
| **Encoding & Serialization**| `base64` | `SMP_T_BIN` | `SMP_T_STR` | Encodes binary buffer into standard Base64 ASCII string. |
| | `base64_decode` | `SMP_T_STR` | `SMP_T_BIN` | Decodes Base64 string into raw binary bytes. |
| | `hex` | `SMP_T_BIN` | `SMP_T_STR` | Encodes binary buffer into hexadecimal character string. |
| | `hex_decode` | `SMP_T_STR` | `SMP_T_BIN` | Decodes hexadecimal character string into raw binary bytes. |
| | `url_dec` | `SMP_T_STR` | `SMP_T_STR` | Decodes URL percent-encoded characters (`%XX`). |
| | `url_enc` | `SMP_T_STR` | `SMP_T_STR` | Percent-encodes reserved URL characters. |
| | `json([<path>])` | `SMP_T_STR` | `SMP_T_STR` | Parses JSON payload and extracts field designated by JSON pointer. |
| | `protobuf(<field-id>)`| `SMP_T_BIN`| `SMP_T_ANY` | Decodes Protocol Buffers binary wire format and extracts tag. |
| **Hashing & Checksums** | `crc32` | `SMP_T_BIN` | `SMP_T_SINT` | Calculates 32-bit IEEE 802.3 CRC32 checksum. |
| | `crc32c` | `SMP_T_BIN` | `SMP_T_SINT` | Calculates 32-bit Castagnoli CRC32-C (hardware-accelerated SSE4.2/ARMv8). |
| | `djb2([<seed>])` | `SMP_T_BIN` | `SMP_T_SINT` | Computes Bernstein DJB2 hash. |
| | `sdbm([<seed>])` | `SMP_T_BIN` | `SMP_T_SINT` | Computes SDBM database hash. |
| | `xxh3([<seed>])` | `SMP_T_BIN` | `SMP_T_SINT` | Computes ultra-fast 64-bit XXH3 hash (introduced in HAProxy 2.4). |
| | `xxh64([<seed>])` | `SMP_T_BIN` | `SMP_T_SINT` | Computes XXHash64 checksum. |
| | `sha1` | `SMP_T_BIN` | `SMP_T_BIN` | Computes 160-bit SHA-1 cryptographic digest. |
| | `sha2([<bits>])` | `SMP_T_BIN` | `SMP_T_BIN` | Computes SHA-2 digest (224, 256, 384, or 512 bits). |
| | `digest(<algo>)` | `SMP_T_BIN` | `SMP_T_BIN` | Computes message digest using OpenSSL EVP engine (`md5`, `sha256`, etc.). |
| **IP & Network Masking**| `ipmask(<mask>)` | `SMP_T_ADDR` | `SMP_T_ADDR` | Applies IPv4 netmask (e.g. `255.255.255.0` or `24`) or IPv6 prefix CIDR. |
| | `in_table(<tab>)` | `SMP_T_ANY` | `SMP_T_BOOL` | Checks if sample key exists in stick table `<tab>`. |
| **Regular Expressions** | `regsub(<regex>,<fmt>[,<flags>])`| `SMP_T_STR`| `SMP_T_STR`| Regex string substitution with PCRE2 capture group references (`\1`, `\2`). |
| **Key-Value Map Lookups**| `map(<file>[,<def>])`| `SMP_T_STR` | `SMP_T_STR` | Exact string lookup in map file `<file>`, falling back to `<def>` if unmapped. |
| | `map_str(<file>[,<def>])`| `SMP_T_STR` | `SMP_T_STR` | Exact string map lookup. |
| | `map_beg(<file>[,<def>])`| `SMP_T_STR` | `SMP_T_STR` | Prefix matching string lookup in map file. |
| | `map_sub(<file>[,<def>])`| `SMP_T_STR` | `SMP_T_STR` | Substring matching lookup in map file. |
| | `map_dir(<file>[,<def>])`| `SMP_T_STR` | `SMP_T_STR` | Subdirectory path prefix map lookup. |
| | `map_dom(<file>[,<def>])`| `SMP_T_STR` | `SMP_T_STR` | Domain name suffix matching map lookup. |
| | `map_end(<file>[,<def>])`| `SMP_T_STR` | `SMP_T_STR` | Suffix string map lookup. |
| | `map_reg(<file>[,<def>])`| `SMP_T_STR` | `SMP_T_STR` | Regular expression map lookup. |
| | `map_int(<file>[,<def>])`| `SMP_T_SINT`| `SMP_T_STR` | Integer key map lookup. |
| | `map_ip(<file>[,<def>])` | `SMP_T_ADDR`| `SMP_T_STR` | CIDR IP network prefix map lookup. |
| **Arithmetic & Logic** | `add(<val>)` | `SMP_T_SINT` | `SMP_T_SINT` | Adds integer `<val>` to input sample. |
| | `sub(<val>)` | `SMP_T_SINT` | `SMP_T_SINT` | Subtracts integer `<val>` from input sample. |
| | `mul(<val>)` | `SMP_T_SINT` | `SMP_T_SINT` | Multiplies input sample by `<val>`. |
| | `div(<val>)` | `SMP_T_SINT` | `SMP_T_SINT` | Integer division of input sample by `<val>`. |
| | `mod(<val>)` | `SMP_T_SINT` | `SMP_T_SINT` | Modulo of input sample by `<val>`. |
| | `neg` | `SMP_T_SINT` | `SMP_T_SINT` | Negates input integer value ($x \to -x$). |
| | `and(<val>)` | `SMP_T_SINT` | `SMP_T_SINT` | Bitwise AND with `<val>`. |
| | `or(<val>)` | `SMP_T_SINT` | `SMP_T_SINT` | Bitwise OR with `<val>`. |
| | `xor(<val>)` | `SMP_T_SINT` | `SMP_T_SINT` | Bitwise XOR with `<val>`. |
| | `not` | `SMP_T_BOOL` | `SMP_T_BOOL` | Boolean inversion ($1 \to 0$, $0 \to 1$). |
| | `bool` | `SMP_T_ANY` | `SMP_T_BOOL` | Casts sample to boolean based on non-zero / non-empty truthiness. |
| **Crypto & JWT Security**| `aes_gcm_dec(<bits>,<key>,<ae>)`| `SMP_T_BIN`| `SMP_T_BIN`| Decrypts AES-GCM ciphertext buffer. |
| | `jwt_verify(<alg>,<key>)`| `SMP_T_STR` | `SMP_T_BOOL` | Validates JSON Web Token signature against algorithm and secret key. |

---

### 5.3 ACL Matchers, Flags & Pre-Defined ACLs

#### 5.3.1 ACL Syntax & Pattern Matching Methods
ACL declaration syntax:
```haproxy
acl <aclname> <criterion> [flags] [operator] <value> ...
```
Where `[flags]` customize pattern matching semantics:
- `-i`: Case-insensitive pattern matching.
- `-n`: Disables DNS resolution when matching domain names.
- `-m <method>`: Explicitly overrides the default matching method:
  - `-m bool`: Evaluates boolean truthiness of sample without values.
  - `-m int`: Exact integer equality or range matching (`min:max`).
  - `-m ip`: IPv4/IPv6 address or CIDR mask matching.
  - `-m bin`: Hexadecimal binary buffer matching.
  - `-m len`: String length matching.
  - `-m str`: Exact string comparison.
  - `-m sub`: Substring matching.
  - `-m beg`: Prefix matching (string begins with pattern).
  - `-m end`: Suffix matching (string ends with pattern).
  - `-m dir`: Subdirectory path matching (delimited by `/`).
  - `-m dom`: Domain name suffix matching (delimited by `.`).
  - `-m reg`: Regular expression matching via PCRE2.
  - `-m found`: Matches if the sample fetch succeeded, regardless of its value.
- `-f <file>`: Loads pattern values from an external file (one entry per line).
- `-u <unique-id>`: Forces unique identifier for runtime dynamic ACL updates via CLI.

#### 5.3.2 Pre-Defined Built-in ACLs
HAProxy 3.5 provides built-in pre-defined ACLs evaluated without explicit declaration:
- `TRUE`: Always evaluates to true.
- `FALSE`: Always evaluates to false.
- `LOCALHOST`: Matches source IP `127.0.0.1` or `::1`.
- `HTTP`: Matches when transaction protocol is HTTP.
- `HTTP_1.0`: Matches HTTP/1.0 protocol version.
- `HTTP_1.1`: Matches HTTP/1.1 protocol version.
- `HTTP_2.0`: Matches HTTP/2 protocol version.
- `METH_GET`, `METH_POST`, `METH_HEAD`, `METH_PUT`, `METH_DELETE`, `METH_OPTIONS`, `METH_TRACE`, `METH_CONNECT`: Matches standard HTTP method verbs.
- `WAIT_END`: Evaluates true when stream analysis is terminating.

---
## 6. Bind and Server Parameters Catalog

Listeners declared via `bind` and backend server destinations declared via `server` / `default-server` support extensive parameter sets tuning socket transport flags, hardware offloading, TLS handshakes, health checks, and PROXY protocol encapsulation.

---

### 6.1 Bind Parameters (`bind`)

| Bind Parameter | Syntax | Status (3.5) | Description & Alcyon Architecture |
|---|---|---|---|
| `accept-proxy` | `accept-proxy` | Standard | Enforces PROXY protocol v1 or v2 on all incoming client connections. Parsed via `alcyon-proto::proxy_protocol`. |
| `accept-netscaler-cip`| `accept-netscaler-cip <magic>`| Standard | Accepts Citrix NetScaler Client IP insertion header. |
| `allow-0rtt` | `allow-0rtt` | Standard | Enables TLS 1.3 Early Data (0-RTT). Gated against replay attacks in HTTP. |
| `alpn` | `alpn <proto1>,<proto2>...`| Standard | Sets ALPN protocols advertised in TLS handshake (e.g. `h2,http/1.1`). |
| `backlog` | `backlog <conns>` | Standard | Sets socket-specific SYN listen backlog size. |
| `ca-file` | `ca-file <path>` | Standard | Loads CA bundle certificate file for verifying client TLS certificates. |
| `ciphers` | `ciphers <cipher-suite>`| Standard | Sets acceptable TLS 1.2 and earlier cipher list string. |
| `ciphersuites` | `ciphersuites <ciphers>`| Standard | Sets acceptable TLS 1.3 cipher suites string. |
| `crt` | `crt <path>` | Standard | Path to PEM certificate and private key file, directory, or `crt-list`. |
| `defer-accept` | `defer-accept` | Standard | Uses Linux `TCP_DEFER_ACCEPT` to wake listener only when initial payload arrives. |
| `force-tlsv12` | `force-tlsv12` | Standard | Enforces TLS 1.2 as the exact and only accepted TLS version. |
| `force-tlsv13` | `force-tlsv13` | Standard | Enforces TLS 1.3 as the exact and only accepted TLS version. |
| `id` | `id <id>` | Standard | Assigns custom numerical ID to the listener. |
| `interface` | `interface <name>` | Standard | Binds socket strictly to network interface via `SO_BINDTODEVICE`. |
| `maxconn` | `maxconn <conns>` | Standard | Enforces connection limit specific to this listener socket. |
| `mode` | `mode { http \| tcp }` | Standard | Overrides proxy mode specifically for this listener endpoint. |
| `name` | `name <name>` | Standard | Assigns human-readable name to the listener for logging. |
| `namespace` | `namespace <netns>` | Standard | Binds socket inside designated Linux network namespace (`ip netns`). |
| `nice` | `nice <nice>` | Standard | Sets task priority nice value for connections accepted on this socket. |
| `no-tls-tickets` | `no-tls-tickets` | Standard | Disables stateless TLS session tickets (RFC 5077), forcing stateful session caching. |
| `process` | `process [auto:]<range>`| Standard | Binds listener socket processing to specified worker thread or thread group. |
| `proto` | `proto <protocol>` | Standard | Selects multiplexer protocol: `h1`, `h2`, `quic`, `spop`, `fcgi`. |
| `send-proxy` | `send-proxy` | Standard | Emits PROXY protocol v1 ASCII header downstream (transparent proxying). |
| `send-proxy-v2` | `send-proxy-v2` | Standard | Emits PROXY protocol v2 binary header with connection metadata. |
| `ssl` | `ssl` | Standard | Enables TLS/SSL decryption engine on this listener. |
| `ssl-min-ver` | `ssl-min-ver { TLSv1.2 \| TLSv1.3 }` | Standard | Enforces minimum accepted TLS protocol version. |
| `ssl-max-ver` | `ssl-max-ver { TLSv1.2 \| TLSv1.3 }` | Standard | Enforces maximum accepted TLS protocol version. |
| `strict-sni` | `strict-sni` | Standard | Refuses TLS connection if client does not present SNI or SNI has no matching certificate. |
| `tfo` | `tfo` | Standard | Enables TCP Fast Open (`TCP_FASTOPEN`) on the listener socket. |
| `transparent` | `transparent` | Standard | Enables `IP_TRANSPARENT` or `IP_FREEBIND` for non-local IP binding. |
| `v4v6` | `v4v6` | Standard | Allows socket bound to `::` to accept both IPv4 and IPv6 connections. |
| `v6only` | `v6only` | Standard | Disables IPv4-mapped IPv6 addresses (`IPV6_V6ONLY`). |
| `verify` | `verify { none \| optional \| required }` | Standard | Sets client TLS certificate verification policy. |

---

### 6.2 Server & Default-Server Parameters (`server`, `default-server`)

| Server Parameter | Syntax | Status (3.5) | Description & Alcyon Architecture |
|---|---|---|---|
| `check` | `check` | Standard | Enables active health check probing on the server endpoint. |
| `inter` | `inter <time>` | Standard | Regular health check probing interval (default 2,000 ms). |
| `fastinter` | `fastinter <time>` | Standard | Accelerated probing interval during state transitions (flapping). |
| `downinter` | `downinter <time>` | Standard | Probing interval applied while server is down, reducing network chatter. |
| `fall` | `fall <count>` | Standard | Consecutive failed checks before transitioning server to DOWN state (default 3). |
| `rise` | `rise <count>` | Standard | Consecutive successful checks before restoring server to UP state (default 2). |
| `weight` | `weight <1-256>` | Standard | Relative load balancing weight in round-robin and consistent hashing rings. |
| `backup` | `backup` | Standard | Designates server as a standby backup; receives traffic only if primary pool is down. |
| `maxconn` | `maxconn <conns>` | Standard | Maximum concurrent active connections allowed to this server; excess requests queue. |
| `minconn` | `minconn <conns>` | Standard | Dynamic minimum connection floor when dynamic queue sizing is active. |
| `maxqueue` | `maxqueue <conns>` | Standard | Maximum pending requests permitted in this server's connection queue. |
| `slowstart` | `slowstart <time>` | Standard | Gradually ramps up load balancing weight over `<time>` after a server comes UP. |
| `send-proxy` | `send-proxy` | Standard | Prefixes outbound backend connection with PROXY protocol v1 ASCII header. |
| `send-proxy-v2` | `send-proxy-v2` | Standard | Prefixes outbound backend connection with PROXY protocol v2 binary header. |
| `send-proxy-v2-ssl` | `send-proxy-v2-ssl` | Standard | Appends TLS metadata TLVs (`PP2_TYPE_SSL`) into outbound PROXY v2 header. |
| `send-proxy-v2-ssl-cn` | `send-proxy-v2-ssl-cn` | Standard | Appends client certificate Common Name TLV into outbound PROXY v2 header. |
| `ssl` | `ssl` | Standard | Enables TLS/SSL encryption for connections to this upstream server. |
| `verify` | `verify { none \| required }` | Standard | Enforces upstream server TLS certificate validation against CA bundle. |
| `ca-file` | `ca-file <path>` | Standard | CA bundle file used to authenticate upstream server certificate. |
| `crt` | `crt <path>` | Standard | Client TLS certificate presented to upstream server for mTLS authentication. |
| `crl-file` | `crl-file <path>` | Standard | Certificate Revocation List for upstream validation. |
| `sni` | `sni <expr>` | Standard | Sets Server Name Indication in TLS ClientHello (literal string or sample fetch). |
| `alpn` | `alpn <protos>` | Standard | ALPN protocols proposed to upstream server (e.g. `h2,http/1.1`). |
| `resolvers` | `resolvers <id>` | Standard | Associates server hostname with designated DNS `resolvers` section. |
| `resolve-prefer`| `resolve-prefer { ipv4 \| ipv6 }` | Standard | Prioritizes IPv4 or IPv6 DNS answers when server hostname resolves to both. |
| `resolve-net` | `resolve-net <network>,...` | Standard | Selects IP addresses matching designated CIDR subnets from DNS answers. |
| `init-addr` | `init-addr <methods>` | Standard | Fallback IP assignment sequence on startup (`last,libc,none`). |
| `cookie` | `cookie <value>` | Standard | Server identification value matched against persistence session cookies. |
| `redir` | `redir <prefix>` | Standard | Sends an immediate HTTP 302 redirect for all requests routed to this server. |
| `proto` | `proto <protocol>` | Standard | Explicitly selects upstream multiplexer: `h1`, `h2`, `fcgi`. |
| `track` | `track <proxy>/<server>` | Standard | Tracks health and administrative state of another server instance. |
| `port` | `port <port>` | Standard | Port number override used exclusively for active health checks. |
| `addr` | `addr <ip>` | Standard | IP address override used exclusively for active health checks. |
| `agent-check` | `agent-check` | Standard | Activates an out-of-band auxiliary TCP health check agent. |
| `agent-port` | `agent-port <port>` | Standard | Port number of the auxiliary agent check service. |
| `agent-inter` | `agent-inter <time>` | Standard | Frequency of auxiliary agent checks. |
| `agent-send` | `agent-send <string>` | Standard | String message transmitted to agent check service upon connection. |
| `allow-0rtt` | `allow-0rtt` | Standard | Enables early data transmission to upstream server in TLS 1.3. |
| `ciphers` | `ciphers <list>` | Standard | Upstream TLS 1.2 cipher suite preferences. |
| `ciphersuites` | `ciphersuites <list>` | Standard | Upstream TLS 1.3 cipher suite preferences. |
| `disabled` | `disabled` | Standard | Initializes server in administrative maintenance state (`MAINT`). |
| `enabled` | `enabled` | Standard | Initializes server in active ready state (`READY`). |
| `error-limit` | `error-limit <num>` | Standard | Consecutive error limit triggering server health mark-down. |
| `id` | `id <id>` | Standard | Unique integer identifier assigned to this server for stats and stick tables. |
| `observe` | `observe { layer4 \| layer7 }` | Standard | Passive health checking by monitoring real user traffic errors. |
| `on-error` | `on-error { fastinter \| fail-check \| mark-down }` | Standard | Action taken immediately upon a single failed health check probe. |
| `on-marked-down`| `on-marked-down { shutdown-sessions }`| Standard | Closes all active persistent connections immediately when server goes DOWN. |
| `on-marked-up` | `on-marked-up { shutdown-backup-sessions }`| Standard | Drains backup server sessions when a primary server recovers. |
| `pool-max-conn` | `pool-max-conn <num>` | Standard | Maximum idle keep-alive connections held open in server connection pool. |
| `pool-low-conn` | `pool-low-conn <num>` | Standard | Target idle connection floor below which connections are preserved. |
| `pool-purge-delay`| `pool-purge-delay <time>`| Standard | Idle timeout before cleaning up excess idle pooled connections. |
| `socks4` | `socks4 <addr>:<port>` | Standard | Tunnels outbound server connections through a SOCKS4 proxy. |
| `source` | `source <addr>[:<port>]` | Standard | Binds outbound server connections to a specific local source IP. |
| `tcp-ut` | `tcp-ut <time>` | Standard | Configures TCP user timeout (`TCP_USER_TIMEOUT`) on backend connections. |
| `tfo` | `tfo` | Standard | Uses TCP Fast Open for outbound connections to server. |
| `usesrc` | `usesrc { client \| clientip \| <addr> }` | Standard | Transparent proxying: spoofs client source IP on outbound connection. |
| `verifyhost` | `verifyhost <hostname>` | Standard | Expected Subject Alternative Name in upstream certificate validation. |

---
## 7. Project Alcyon Implementation Priority Roadmap

Project Alcyon prioritizes feature implementation using a rigorous four-tier taxonomy:
- **Tier P0: Core Production Essentials (Milestones 1–4, Immediate Production Baseline)**
- **Tier P1: Standard Web Traffic & Observability (Milestones 5–8, Modern TLS & HTTP/2)**
- **Tier P2: Advanced Traffic Management & Caching (Milestones 9–11, Enterprise Clustering)**
- **Tier P3: Specialized Niche Features (Post-1.0, Edge & Ecosystem Integrations)**

---

### 7.1 Roadmap Summary Matrix

| Tier | Subsystem / Focus | Core Directives & Keywords | Key Action Rules | Target Crates | Safety & Allocation Tenet |
|---|---|---|---|---|---|
| **P0** | Core TCP/HTTP Proxy, Basic Balancing, Probes, Logging | `global`, `defaults`, `frontend`, `backend`, `listen`, `bind`, `server`, `default-server`, `mode {tcp\|http}`, `balance {roundrobin\|leastconn\|source}`, `hash-type consistent`, `check`, `inter`, `fall`, `rise`, `weight`, `backup`, `maxconn`, `send-proxy`, `send-proxy-v2`, `accept-proxy`, `timeout connect\|client\|server\|http-request`, `option httplog\|tcplog\|dontlognull` | `http-request {set-header, add-header, del-header, redirect, deny, allow, return}`, `http-response {set-header, add-header, del-header, set-status, deny, allow}`, `tcp-request connection {accept, reject}` | `alcyon-config`, `alcyon-proto`, `alcyon-rt` | Zero runtime heap allocation on event loops (`NASA JPL Rule 3`). |
| **P1** | HTTP/2, TLS 1.3/SNI/ALPN, Stick Tables, DNS, CLI | `ssl`, `crt`, `ca-file`, `sni`, `alpn`, `strict-sni`, `verify required`, `stick-table`, `resolvers`, `nameserver`, `resolve-prefer`, `http-reuse safe`, `stats socket`, `stats admin`, `log-format`, `server-template` | `http-request {set-path, set-query, replace-header, replace-uri, track-sc0..2, sc-inc-gpc}`, `tcp-request content {accept, reject, track-sc0..2}` | `alcyon-tls`, `alcyon-stick-table`, `alcyon-proto`, `alcyon-sample` | Bounded $O(\log N)$ ebtree index lookups, hard thread affinity. |
| **P2** | RFC 9111 Caching, Multi-Threaded Peers, SPOE, Maps | `cache`, `total-max-size`, `max-age`, `process-vary`, `early-hints`, `peers`, `peer`, `shards`, `table`, `tune.peers.max-updates-at-once`, `filter spoe`, `http-check`, `tcp-check` | `http-request {cache-use, send-spoe-group, set-var, unset-var}`, `http-response {cache-store, send-spoe-group}`, `http-after-response {set-header, set-status}` | `alcyon-cache`, `alcyon-peers`, `alcyon-spoe`, `alcyon-rt` | Lock-free SPSC replication rings, pre-allocated memory slabs. |
| **P3** | FastCGI Gateway, Rings, ACME, Devices, Bandwidth | `fcgi-app`, `ring`, `acme`, `userlist`, `filter bwlim`, `filter otel`, `external-check`, `51degrees`, `deviceatlas`, `wurfl` | `tcp-request content switch-mode`, `http-request {set-bandwidth-limit, normalize-uri}`, `tcp-request connection silent-drop` | `alcyon-fcgi`, `alcyon-ring`, `alcyon-acme`, `alcyon-flt` | Bounded queue capacities, sandbox isolation for external processes. |

---

### 7.2 Tier P0: Core Production Essentials (Milestones 1–4)

#### 7.2.1 Scope & Mission
Provide the minimum viable, high-performance production proxy engine capable of replacing HAProxy in 80% of standard production reverse-proxy configurations (Kubernetes ingress, standard web load balancing, TCP stream routing).

#### 7.2.2 P0 Directives & Keyword Inventory
1. **Configuration Sections**:
   - `global`: `nbthread`, `cpu-map`, `maxconn`, `stats socket`, `log`, `chroot`, `user`, `group`.
   - `defaults`: Baseline proxy inheritance for timeouts, balance, and logging.
   - `frontend`: Downstream client connection termination, backlog management, mode selection.
   - `backend`: Upstream server pool management, load balancing algorithms, health check loops.
   - `listen`: Consolidated TCP/HTTP proxy blocks.
2. **Proxy Core Directives**:
   - `mode { http | tcp }`: Native HTTP HTX state machine vs raw TCP pass-through.
   - `bind <addr>:<port> [accept-proxy]`: Listening socket management with optional PROXY v1/v2 decoding.
   - `server <name> <addr>:<port> [weight] [maxconn] [backup] [check] [inter] [fall] [rise] [send-proxy] [send-proxy-v2]`: Upstream destination server declarations with active polling health checks.
   - `default-server`: Default options inheritance for upstream servers.
   - `balance { roundrobin | leastconn | source }`: Weighted round-robin, least-connections, and source IP hashing.
   - `hash-type consistent`: Ketama consistent hashing ring for consistent source IP distribution.
   - `use_backend <backend> [ { if | unless } <condition> ]`: Conditional routing.
   - `default_backend <backend>`: Fallback routing.
3. **Session Timeouts**:
   - `timeout connect <time>`: Upstream TCP connection timeout.
   - `timeout client <time>`: Downstream client socket inactivity timeout.
   - `timeout server <time>`: Upstream server socket inactivity timeout.
   - `timeout http-request <time>`: Anti-Slowloris request header timeout.
   - `timeout http-keep-alive <time>`: Inactivity timeout between keep-alive requests.
4. **Health Checking**:
   - Active TCP connect checks (`check`).
   - Active HTTP probes (`option httpchk <method> <uri>`).
   - Tunable parameters (`inter`, `fall`, `rise`, `fastinter`, `downinter`).
5. **Observability & Logging**:
   - `log <addr> <facility> [<level>]`: Syslog UDP/UNIX socket logging.
   - `option httplog`: Standard HTTP access log formatting.
   - `option tcplog`: Standard TCP connection log formatting.
   - `option dontlognull`: Suppression of empty health probes.
6. **P0 L7 & L4 Action Rules**:
   - `http-request set-header <name> <fmt>`: Header overwrite/insert.
   - `http-request add-header <name> <fmt>`: Header append.
   - `http-request del-header <name>`: Header removal.
   - `http-request redirect location <target> [code 301|302]`: Immediate redirect.
   - `http-request deny [deny_status 403]`: Immediate rejection.
   - `http-request allow`: Early pipeline termination.
   - `http-request return status <code> [content-type <t>] [string <s>]`: Synthetic response.
   - `http-response set-header <name> <fmt>`: Response header override.
   - `http-response add-header <name> <fmt>`: Response header append.
   - `http-response del-header <name>`: Response header strip.
   - `http-response set-status <code>`: Response status code rewrite.
   - `tcp-request connection accept`: L4 connection permit.
   - `tcp-request connection reject`: L4 connection RST.
7. **P0 Sample Fetches & Converters**:
   - Fetches: `src`, `src_port`, `dst`, `dst_port`, `req.hdr(<name>)`, `method`, `path`, `query`, `url`, `status`, `res.hdr(<name>)`.
   - Converters: `lower`, `upper`, `base64`, `hex`, `crc32`, `ipmask`.
   - ACL Matchers: `path_beg`, `path_end`, `hdr(<name>) -i`, `src <cidr>`.

---

### 7.3 Tier P1: Standard Web Traffic & Observability (Milestones 5–8)

#### 7.3.1 Scope & Mission
Bring Alcyon to full modern HTTPS web scale: HTTP/2 multiplexing, TLS 1.3 termination with SNI routing and client mTLS, stateful stick-table rate limiting, dynamic DNS service discovery, and CLI control.

#### 7.3.2 P1 Directives & Keyword Inventory
1. **HTTP/2 Multiplexing & HPACK (`alcyon-proto` M5)**:
   - Full HTTP/2 connection and stream state machines (`mux_h2`).
   - Static and dynamic HPACK table encoder/decoder (`hpack-dec`, `hpack-enc`).
   - Anti-DDoS mitigation: Rapid Reset RST flood throttling (`tune.h2.fe.max-rst-at-once`).
2. **TLS / SSL Modern Architecture (`alcyon-tls`)**:
   - `bind ... ssl crt <path> [alpn <protos>] [strict-sni] [ca-file <ca>] [verify required]`: TLS termination, ALPN negotiation (`h2`, `http/1.1`), and strict SNI certificate dispatch.
   - `server ... ssl [verify none|required] [sni <str>] [alpn <protos>]`: Upstream TLS re-encryption.
   - Sample fetches: `ssl_fc`, `ssl_fc_sni`, `ssl_fc_alpn`, `ssl_fc_cipher`, `ssl_fc_protocol`, `ssl_c_verify`, `ssl_c_s_dn`.
3. **Stick Tables & Sliding Rate Limiters (`alcyon-stick-table`)**:
   - `stick-table type {ip|string} size <size> expire <time> store {conn_rate,conn_cnt,http_req_rate,http_err_rate,gpc0,gpt0}`.
   - `http-request track-sc0 <sample> [table <tab>]`.
   - `http-request track-sc1 <sample>`, `track-sc2 <sample>`.
   - `http-request sc-inc-gpc0 <sc-id>`, `sc-set-gpt0 <sc-id> <val>`.
   - Rate limiting ACLs: `sc_http_req_rate(0) gt 100`, `sc_conn_cur(0) gt 50`.
4. **Dynamic DNS Resolution (`resolvers`)**:
   - `resolvers <id>` block with `nameserver <id> <addr:port>`.
   - `parse-resolv-conf` for system DNS auto-discovery.
   - Server options: `resolvers <id>`, `resolve-prefer { ipv4 | ipv6 }`, `resolve-net <cidr>`.
   - `server-template <prefix> <num> <addr> [param*]` for Kubernetes/Consul DNS SRV discovery.
5. **Advanced L7 Actions**:
   - `http-request set-path <fmt>`, `set-pathq <fmt>`, `set-query <fmt>`, `set-uri <fmt>`, `set-method <fmt>`.
   - `http-request replace-path <regex> <fmt>`, `replace-header <name> <regex> <fmt>`.
   - `http-request normalize-uri path-strip-dotdot`, `normalize-uri percent-decode-unreserved`.
   - `http-request tarpit`: Malicious client connection throttling.
6. **HTTP Connection Pooling & Keep-Alive**:
   - `http-reuse { never | safe | aggressive | always }`.
   - `option http-server-close`, `option http-keep-alive`, `option prefer-last-server`.
   - `pool-max-conn <num>`, `pool-low-conn <num>`, `pool-purge-delay <time>`.
7. **Observability & Management**:
   - `stats socket <path> [level admin]`: Interactive UNIX domain management socket (CLI parity with HAProxy CLI: `show info`, `show stat`, `show table`, `enable server`, `disable server`).
   - Built-in Web Admin UI and Prometheus Exporter (`stats enable`, `stats uri /admin`, `stats refresh`).
   - Custom `log-format` supporting all standard HAProxy log variable tokens (`%ci`, `%cp`, `%t`, `%ft`, `%b`, `%s`, `%TR`, `%Tt`, etc.).

---

### 7.4 Tier P2: Advanced Traffic Management & Caching (Milestones 9–11)

#### 7.4.1 Scope & Mission
Enterprise-grade clustering and performance features: native RFC 9111 HTTP caching, distributed stick-table peer synchronization, out-of-process deep packet inspection (SPOE), and dynamic variable manipulation.

#### 7.4.2 P2 Directives & Keyword Inventory
1. **RFC 9111 HTTP Caching Engine (`cache`)**:
   - `cache <name>` section with `total-max-size <mb>`, `max-age <sec>`, `max-object-size <bytes>`, `process-vary { on | off }`.
   - HTTP 103 Early Hints caching (`early-hints { on | off | only } [ratio <1-99>]`).
   - Actions: `http-request cache-use <name>`, `http-response cache-store <name>`.
   - Sample fetches: `res.cache_hit`, `res.cache_name`.
2. **Distributed Multi-Threaded Stick Table Replication (`peers`)**:
   - `peers <name>` section with `peer <name> <addr:port>`, `bind <addr:port>`, `shards <num>`.
   - Pure-Rust implementation of HAProxyS 2.1 binary protocol with 256-slot LRU dictionary compression.
   - Lock-free SPSC update queues between worker threads, eliminating HAProxy's single-thread sync bottleneck.
3. **Stream Processing Offload Engine (`filter spoe`)**:
   - Out-of-process WAF and auth offloading (e.g. ModSecurity, CrowdSec).
   - Directives: `filter spoe engine <eng> config <cfg>`.
   - Actions: `http-request send-spoe-group <engine> <group>`, `http-response send-spoe-group`.
4. **Dynamic Variables & Complex Converters**:
   - Actions: `http-request set-var(<name>) <expr>`, `set-var-fmt(<name>) <fmt>`, `unset-var(<name>)`.
   - Map lookups: `map(<file>)`, `map_beg`, `map_sub`, `map_reg`, `map_ip` with runtime reload via CLI.
   - PCRE2 regular expression substitution: `regsub(<regex>, <fmt>)`.
   - JSON pointer extraction: `json(<path>)`.
   - Cryptographic verification: `jwt_verify(<alg>, <key>)`, `aes_gcm_dec`.
5. **Multi-Step Advanced Health Checking**:
   - `http-check connect [param*]`.
   - `http-check send meth <m> uri <u> [hdr <h> <v> ...] [body <b>]`.
   - `http-check expect [!] { status <s> | string <s> | rstatus <r> | rstring <r> }`.
   - `tcp-check send`, `tcp-check expect`.
   - `agent-check`, `agent-port`, `agent-inter`.

---

### 7.5 Tier P3: Specialized Niche Features (Post-1.0 / Enterprise / Edge)

#### 7.5.1 Scope & Mission
Specialized protocol gateways, legacy hardware offloads, third-party proprietary engines, and edge platform features implemented on an as-needed enterprise basis.

#### 7.5.2 P3 Directives & Keyword Inventory
1. **FastCGI Application Gateway (`fcgi-app`)**:
   - `fcgi-app <name>` section: `docroot`, `path-info`, `index`, `set-param`, `pass-header`, `hide-header`, `option keep-conn`, `option mpxs-conns`.
   - Target use-case: Direct PHP-FPM / Python FastCGI proxying without Nginx or Apache.
2. **Circular Memory Ring Buffers (`ring`)**:
   - `ring <name>` section: `size`, `backing-file`, `server`, `format`, `maxlen`.
   - Internal circular ring buffer for zero-overhead in-memory log collection and inspection.
3. **Automated ACME Certificate Management (`acme`)**:
   - `acme <name>` section for automated Let's Encrypt TLS certificate issuing and renewal.
4. **Bandwidth Limitation Filter (`filter bwlim`)**:
   - `filter bwlim-in`, `filter bwlim-out`.
   - Actions: `http-request set-bandwidth-limit <limit> [key <key>]`.
5. **External Health Check Scripts (`external-check`)**:
   - Fork-exec model for running custom shell/Python health check scripts (`external-check command`).
6. **Proprietary Device Detection Subsystems**:
   - `51degrees-*`, `deviceatlas-*`, `wurfl-*`.
7. **OpenTelemetry Distributed Tracing (`filter otel`)**:
   - W3C Trace Context propagation (`traceparent`, `tracestate`) and native OTLP span export.

---

### 7.6 Parser Architectural Blueprint for `alcyon-config`

To achieve exact compatibility with HAProxy 3.5 without inheriting legacy technical debt, the `alcyon-config` crate adheres to the following parser architecture:

```
                            [HAProxy 3.5 Configuration File]
                                           │
                                           ▼
                                 [Logos/Lexer Tokenizer]
                                           │
                                           ▼
                                [Section-Aware Parser]
                 ┌─────────────────────────┼─────────────────────────┐
                 │                         │                         │
                 ▼                         ▼                         ▼
         [GlobalDirectives]         [ProxyDirectives]       [AncillaryDirectives]
         • Threading / NUMA         • defaults / frontend   • peers / cache / resolvers
         • Sockets / Limits         • backend / listen      • ring / fcgi-app / acme
         • tune.* Hierarchy         • HTTP / TCP pipelines  • userlist / http-errors
                 │                         │                         │
                 └─────────────────────────┼─────────────────────────┘
                                           │
                                           ▼
                            [AST Validation & Normalization]
                 ┌─────────────────────────┴─────────────────────────┐
                 │                                                   │
                 ▼                                                   ▼
     [Excised Directives Diagnostic]                     [Runtime Config Model]
     • 'dispatch' -> E0301                               • Zero-heap hot path structures
     • 'transparent' -> E0302                            • Pre-compiled PCRE2 regexes
     • 'master-worker' -> E0303                          • Pre-allocated ebtree indexes
     • 'program' -> E0350                                • Flat array lookup tables
```

#### 7.6.1 Strict Diagnostic Handling for Excised Keywords
The parser strictly rejects obsolete HAProxy keywords with informative, actionable error diagnostics:
```rust
match directive {
    "dispatch" => {
        return Err(ConfigError::ObsoleteKeyword {
            keyword: "dispatch",
            removed_in: "HAProxy 3.5 (commit be8159248)",
            replacement: "server <name> <addr:port>",
        });
    }
    "transparent" => {
        return Err(ConfigError::ObsoleteKeyword {
            keyword: "transparent",
            removed_in: "HAProxy 3.5 (commit be8159248)",
            replacement: "server transparent 0.0.0.0 or 'source ... usesrc clientip'",
        });
    }
    "master-worker" => {
        return Err(ConfigError::ObsoleteKeyword {
            keyword: "master-worker",
            removed_in: "HAProxy 3.5 (commit 5a6ce0481)",
            replacement: "CLI arguments -W (master-worker) or -Ws (systemd notify mode)",
        });
    }
    "program" => {
        return Err(ConfigError::ObsoleteSection {
            section: "program",
            removed_in: "HAProxy 3.2+ (commit 7cb6167d0)",
            guidance: "Manage background processes with systemd or container orchestrators.",
        });
    }
    "mode" if arg == "health" => {
        return Err(ConfigError::ObsoleteKeyword {
            keyword: "mode health",
            removed_in: "HAProxy 2.3",
            replacement: "http-request return status 200",
        });
    }
    _ => {}
}
```

#### 7.6.2 Zero-Allocation Hot-Path Invariant
All parsed rules (`http-request`, `tcp-request`, sample fetches, converters) compile directly into pre-allocated, flat enum representations in `alcyon-proto::actions`. During runtime request processing:
1. No dynamic heap allocations occur (`String`, `Vec`, `Box` are strictly forbidden on the event loop).
2. Header searches use zero-copy byte slice references against the HTX index arena.
3. String formatting (`set-var-fmt`, `set-header`) writes directly into pre-allocated thread-local scratch buffers (`PooledBuf`).
4. Algorithmic complexity is strictly bounded to $O(1)$ for array/slice indexing and $O(\log N)$ with maximum tree depth 32 for ebtree stick-table lookups.

---
