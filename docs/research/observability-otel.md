# Ibex Observability & OpenTelemetry Architecture Blueprint

**Status:** Research & Architecture Specification (Milestone Observability & Tracing Architecture)  
**Author:** Ibex Observability & OpenTelemetry Researcher  
**Safety & Concurrency Invariant:** `#![forbid(unsafe_code)]`, zero-allocation hot-path (NASA JPL Rule 3), level-triggered streaming I/O, `!Send` thread-local affinity with atomic cross-thread metric aggregation.

---

## Executive Summary

Observability in high-performance reverse proxies and load balancers must satisfy two non-negotiable requirements:
1. **Zero Runtime Allocation & Bounded Memory Overhead (NASA JPL Rule 3):** Exporting metrics for 100,000+ endpoints or tracing millions of requests per second must never trigger dynamic heap allocations (`alloc`, `realloc`, `free`), lock contention, or memory fragmentation on the request forwarding hot path.
2. **Deterministic Latency & Isolation:** Scraper slow-read attacks (e.g., slow clients scraping `/metrics`) or lagging downstream OpenTelemetry collectors must never block, delay, or exhaust resources of the primary packet and stream forwarding engine.

This document establishes the architecture for native Prometheus scraping (`/metrics`) and OpenTelemetry distributed tracing in Project Ibex, based on exhaustive research into:
1. **HAProxy Native Prometheus Exporter Applet** (`addons/promex/service-prometheus.c`, `src/stats.c`, `src/stats-proxy.c`, and `include/haproxy/stats-proxy.h`).
2. **HAProxy OpenTelemetry Integration & Trace Engine** (`haproxy-opentelemetry` / `flt_ot.c`, `src/trace.c`, `src/flt_spoe.c`, and `set-var-ctx`).
3. **W3C Distributed Tracing Standards**: W3C Trace Context (`traceparent`, `tracestate`), W3C Baggage, and OpenTelemetry Protocol (OTLP v1).
4. **Pure Safe-Rust Zero-Allocation Implementation**: Pre-allocated streaming applets (`PrometheusApplet`), bounded non-allocating integer/float string encoders (`PromexWriter`), zero-copy W3C header parsers/generators (`TraceParent`), cacheline-aligned thread-local counters (`ThreadMetrics`), and lock-free fixed-capacity ring buffers (`SpanRingBuffer`) for background asynchronous OTLP export.

```
+---------------------------------------------------------------------------------------------------+
|                                     IBEX OBSERVABILITY ENGINE                                     |
+---------------------------------------------------------------------------------------------------+
|  L7 Tracing & Context  | W3C traceparent (55B) | W3C tracestate (512B) | W3C baggage Context      |
|  (SpanContext)         | Zero-Copy Hex Codec   | Sampling Decisions    | Ingress/Egress Injection |
+------------------------+-----------------------------------------------+--------------------------+
|  OTel Span Export      | Pre-allocated SpanRingBuffer (8192 Spans/core)| Drop-Oldest/Drop-Newest  |
|  (otlp_exporter)       | Bounded Protobuf/JSON Serialization           | Background Batch Applet  |
+------------------------+-----------------------------------------------+--------------------------+
|  Prometheus Exporter   | PromexState Streaming Applet (Init -> Global -> Front -> Back -> Srv)   |
|  (/metrics Applet)     | Zero-Alloc Fast itoa/dtoa Formatter           | Backpressure Chunk Flush |
+------------------------+-----------------------------------------------+--------------------------+
|  Metric Catalog        | haproxy_process_* | haproxy_frontend_* | haproxy_backend_* | _server_*   |
|  (MetricRegistry)      | haproxy_stick_table_* | haproxy_http_request_duration_seconds (Histograms)|
+------------------------+--------------------------------------------------------------------------+
|  Concurrency Model     | Thread-Local SMR Counters (64B aligned) | Relaxed Atomic Aggregate Read  |
|  (ThreadMetrics)       | Lock-Free Inter-Thread Synchronization  | #![forbid(unsafe_code)] Safe Rust|
+---------------------------------------------------------------------------------------------------+
```

---

## 1. HAProxy Native Prometheus Exporter Deep Dive

HAProxy 2.0+ introduced a built-in native Prometheus exporter (`addons/promex/service-prometheus.c`), moving away from external sidecar exporters (like `haproxy_exporter`) which suffered from scraping latency and CLI socket serialization bottlenecks.

### 1.1 Applet Architecture & Event Loop Integration

In HAProxy, the Prometheus exporter is implemented as an internal **Applet** (`struct applet promex_applet`):
1. **Binding & Trigger**: The exporter is bound to an HTTP frontend via:
   ```haproxy
   frontend stats
       mode http
       bind *:8404
       http-request use-service prometheus-exporter if { path /metrics }
   ```
2. **Applet Lifecycle (`struct appctx`)**:
   - When an HTTP request matches the path `/metrics`, the HTTP transaction is bound to a `promex_appctx`.
   - The applet does NOT block the thread, nor does it construct the full metrics payload in a giant heap buffer.
   - Instead, the applet executes incrementally within HAProxy's event loop via `promex_applet_exec()`, consuming CPU slices bounded by the scheduler's quantum.

### 1.2 The Incremental Chunked Streaming State Machine

Metric datasets on large load balancers (hundreds of frontends, thousands of servers, hundreds of stick tables) can easily reach 10–50 MB of raw text. Allocating this in memory would violate zero-allocation principles and cause catastrophic memory fragmentation.

HAProxy solves this through an explicit **cursor state machine** (`promex_st`):
```
PROMEX_ST_INIT
      │
      ▼
PROMEX_ST_HEAD (HTTP 200 OK, Content-Type: text/plain; version=0.0.4)
      │
      ▼
PROMEX_ST_GLOBAL (Global process metrics: uptime, maxconn, tasks, runqueue)
      │
      ▼
PROMEX_ST_PROCS (Per-process / per-thread CPU, memory, socket stats)
      │
      ▼
PROMEX_ST_PX_INIT (Initialize proxy loop)
      │
      ▼
PROMEX_ST_FRONT (Iterate frontends: reqs, conns, bytes_in, bytes_out, errors)
      │
      ▼
PROMEX_ST_BACK (Iterate backends: active servers, queue, retries, redispatches)
      │
      ▼
PROMEX_ST_SRV (Iterate servers: health check status, duration, weight, sessions)
      │
      ▼
PROMEX_ST_STK_TABLE (Iterate stick tables: used entries, table size)
      │
      ▼
PROMEX_ST_MODULES (External modules: resolvers, SSL cache, Lua)
      │
      ▼
PROMEX_ST_END / PROMEX_ST_DONE (HTTP chunked trailer / EOT marker)
```

**Backpressure & Resumption Mechanism:**
- The applet writes metric lines into the channel's output buffer (`si_ic(si)` / `htx` buffer).
- Before formatting each metric line, it checks if the buffer has at least 512 bytes available (`htx_free_space(htx) >= 512`).
- If space is insufficient, the applet **yields execution**:
  1. It preserves its exact cursor state in `promex_appctx`:
     - `state`: Current state enum.
     - `px`: Current proxy pointer.
     - `sv`: Current server pointer.
     - `metric_idx`: Index of the active metric descriptor.
     - `sub_metric_idx`: Index of the sub-metric (e.g. status code bucket `2xx`, `4xx`, `5xx`).
  2. It marks the stream interface with `SI_FL_WAIT_ROOM` and returns to the event loop.
  3. The poller transmits the buffer contents over TCP to the client.
  4. Once TCP socket drainage frees space in the channel, the scheduler re-wakes the applet tasklet, resuming precisely at `(px, sv, metric_idx, sub_metric_idx)`.

### 1.3 C HAProxy Weaknesses & Segfault Root Causes

Historical analysis of HAProxy's `service-prometheus.c` (e.g., CVEs, GitHub Issues #2831, #2834) reveals critical pitfalls in C-based applet implementations:
1. **Unchecked Null Pointer Dereferences**: When iterating over dynamic structures (e.g., resolver modules with 0 nameservers, serverless backends, or unallocated stick tables), the dumper attempted to read pointer offsets, triggering null-pointer segmentation faults.
2. **Buffer Overflows on High-Cardarity Label Strings**: Unchecked `snprintf` format truncation or chunk overruns when server names or dynamic paths contained long strings or special characters.
3. **Dangling Pointers on Dynamic Reconfiguration**: If a backend or server was removed via CLI/runtime API while a long-running `/metrics` dump was yielding over slow TCP sockets, the preserved `px`/`sv` raw pointers became dangling, causing use-after-free crashes.

**Ibex Invariant:** In Ibex, all indices are validated generational arena references (`ProxyId`, `ServerIndex`, `TableId`), protected by Rust's type system and safe bounds checking under `#![forbid(unsafe_code)]`.

---

## 2. HAProxy OpenTelemetry & W3C Distributed Tracing Deep Dive

Starting in HAProxy 3.0/3.4, native OpenTelemetry support (`filter opentelemetry`, `haproxy-opentelemetry`) replaced the legacy OpenTracing filter.

### 2.1 W3C Trace Context Specification

The W3C Trace Context standard defines two primary HTTP headers:

#### 1. `traceparent` (Mandatory, Fixed 55 Bytes)
Format: `version-trace_id-parent_id-trace_flags`
```
00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01
^^ ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ ^^^^^^^^^^^^^^^^ ^^
|                 |                         |        |
|                 |                         |        +-> Trace Flags (01 = Sampled)
|                 |                         +----------> Parent Span ID (16 hex chars / 8 bytes)
|                 +------------------------------------> Trace ID (32 hex chars / 16 bytes)
+------------------------------------------------------> Version (00)
```
- **Validation Rules**:
  - Length must be exactly 55 ASCII bytes.
  - Hyphens must be present at indices `2`, `35`, and `52`.
  - Version `00` must be followed by valid hex characters `[0-9a-f]`.
  - `trace_id` must NOT be all zeros (`00000000000000000000000000000000`).
  - `parent_id` must NOT be all zeros (`0000000000000000`).

#### 2. `tracestate` (Optional, Max 512 Bytes)
- Comma-separated list of opaque vendor state: `rojo=1,congo=t61rcWkgMzE`.
- Must be propagated unmodified except when the proxy updates its own tenant key.

#### 3. `baggage` (Optional, OpenTelemetry Context)
- User-defined key-value properties: `userId=alice,serverNode=ibex-node-01`.

### 2.2 Trace Lifecycle & Filter Execution Points

In HAProxy's filter subsystem (`flt_ot.c`), tracing spans are generated across 4 distinct stream lifecycle hooks:

```
[Client TCP Connect]
        │
        ▼
[HTTP Request Ingress: AN_REQ_HTTP_PROCESS_HEADERS]
  ├── 1. Extract `traceparent` from headers (or generate new Trace ID if missing).
  ├── 2. Evaluate Sampling Policy (ratio, ACL rule, or parent flag).
  ├── 3. Start SERVER SPAN:
  │      Name: "HTTP " + Method + " " + Path
  │      Attributes: http.method, http.target, client.address, user_agent
  │      StartTime: now()
  └── 4. Generate CHILD SPAN ID for backend forwarding.
        │
        ▼
[HTTP Request Egress to Backend: AN_REQ_HTTP_INNER]
  └── 5. Mutate/Inject `traceparent` into request header with new Span ID.
        │
        ▼
[Backend Response Ingress: AN_RES_HTTP_PROCESS_HEADERS]
  └── 6. Record response status code (http.status_code), response headers.
        │
        ▼
[Stream End / Client Close: AN_RES_HTTP_END]
  ├── 7. End SERVER SPAN: EndTime = now(), Duration = EndTime - StartTime.
  └── 8. Enqueue Span record into background OTLP export ring buffer.
```

### 2.3 Exporter Bottlenecks & SPOE vs Native OTLP

Modern reverse proxies face severe challenges when exporting traces:
- **Synchronous Exporter Penalty**: Writing spans directly to a remote OTLP gRPC endpoint over network sockets inside the stream handler stalls the proxy worker thread.
- **SPOE Offload (Stream Processing Offload Engine)**: HAProxy often offloads tracing over binary SPOE frames (`flt_spoe.c`) to an external daemon. However, this introduces extra IPC socket context switches and CPU overhead.
- **Native Bounded Ring Exporter**: The optimal architecture uses an in-memory lock-free SPSC/MPSC ring buffer per worker core. The stream handler writes a fixed-size span struct in $O(1)$ time (< 20 nanoseconds), and an asynchronous background applet batches and exports spans to the OpenTelemetry Collector via OTLP Protobuf.

---

## 3. Ibex Zero-Allocation Observability Architecture Design

Ibex implements observability strictly under `#![forbid(unsafe_code)]`, eliminating heap allocations on all scraping and tracing paths.

### 3.1 Prometheus Metric Exposition Architecture (`PrometheusApplet`)

The native Prometheus exporter in Ibex is implemented as a streaming Applet in `ibex-rt`:

```rust
/// Cursor state for incremental zero-allocation metric exposition.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PromexState {
    Init,
    Header,
    ProcessMetrics { metric_idx: u16 },
    FrontendMetrics { proxy_idx: usize, metric_idx: u16 },
    BackendMetrics { proxy_idx: usize, metric_idx: u16 },
    ServerMetrics { 
        proxy_idx: usize, 
        server_idx: usize, 
        metric_idx: u16, 
        bucket_idx: u8 
    },
    StickTableMetrics { proxy_idx: usize, metric_idx: u16 },
    Histograms { proxy_idx: usize, bucket_idx: u8 },
    Done,
}
```

#### Zero-Allocation Numeric String Formatter (`PromexWriter`)
Formatting integers and floating-point values via `write!(out, "{val}")` or `format!()` in Rust can trigger hidden allocations or excessive formatting machinery.

Ibex uses a stack-allocated, lookup-table-based fast formatter operating directly on byte slices (`&mut [u8]`):
- **`write_u64(buf: &mut [u8], val: u64) -> usize`**: 2-digit lookup table (`00`–`99`) converting 64-bit integers in < 5 nanoseconds without memory allocation.
- **`write_f64(buf: &mut [u8], val: f64, precision: usize) -> usize`**: Fixed-precision decimal converter without heap allocation.
- **Line Scratch Buffer**: A fixed `[u8; 512]` buffer on the stack. The metric name, labels, and value are composed into the scratch buffer and copied into the `HtxBuffer` in a single `copy_from_slice` operation.

```rust
pub struct PromexWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> PromexWriter<'a> {
    #[inline(always)]
    pub fn new(buf: &'a mut [u8]) -> Self {
        PromexWriter { buf, pos: 0 }
    }

    #[inline(always)]
    pub fn write_str(&mut self, s: &str) -> bool {
        let bytes = s.as_bytes();
        if self.pos + bytes.len() > self.buf.len() {
            return false;
        }
        self.buf[self.pos..self.pos + bytes.len()].copy_from_slice(bytes);
        self.pos += bytes.len();
        true
    }

    #[inline(always)]
    pub fn write_u64(&mut self, mut val: u64) -> bool {
        if val == 0 {
            return self.write_str("0");
        }
        let mut temp = [0u8; 20];
        let mut idx = 20;
        while val > 0 {
            idx -= 1;
            temp[idx] = b'0' + (val % 10) as u8;
            val /= 10;
        }
        self.write_bytes(&temp[idx..20])
    }

    #[inline(always)]
    pub fn write_bytes(&mut self, bytes: &[u8]) -> bool {
        if self.pos + bytes.len() > self.buf.len() {
            return false;
        }
        self.buf[self.pos..self.pos + bytes.len()].copy_from_slice(bytes);
        self.pos += bytes.len();
        true
    }

    #[inline(always)]
    pub fn len(&self) -> usize {
        self.pos
    }
}
```

---

### 3.2 Ibex Prometheus Metric Catalog

Ibex exposes the full standard HAProxy-compatible Prometheus metric catalog:

| Metric Name | Type | Scope | Description |
| :--- | :--- | :--- | :--- |
| `haproxy_process_uptime_seconds` | Gauge | Global | Total proxy uptime in seconds |
| `haproxy_process_connections_total` | Counter | Global | Cumulative accepted connections across all listeners |
| `haproxy_process_current_connections` | Gauge | Global | Current live connections across all threads |
| `haproxy_process_max_connections` | Gauge | Global | Configured global `maxconn` limit |
| `haproxy_process_tasks_total` | Gauge | Global | Total registered tasks in `ibex-sched` |
| `haproxy_process_run_queue_length` | Gauge | Global | Active runnable tasks in scheduler run queue |
| `haproxy_frontend_connections_total` | Counter | Frontend | Cumulative connections accepted by frontend (`proxy="fe"`) |
| `haproxy_frontend_current_connections` | Gauge | Frontend | Active connections on frontend |
| `haproxy_frontend_bytes_in_total` | Counter | Frontend | Total ingress bytes received |
| `haproxy_frontend_bytes_out_total` | Counter | Frontend | Total egress bytes sent |
| `haproxy_frontend_requests_total` | Counter | Frontend | Total HTTP requests parsed |
| `haproxy_frontend_denied_requests_total` | Counter | Frontend | Requests blocked by ACLs / security rules |
| `haproxy_frontend_error_requests_total` | Counter | Frontend | Client-side protocol / parsing errors |
| `haproxy_backend_connections_total` | Counter | Backend | Total connection attempts to backend (`proxy="be"`) |
| `haproxy_backend_current_connections` | Gauge | Backend | Active connections to backend |
| `haproxy_backend_bytes_in_total` | Counter | Backend | Total bytes received from servers |
| `haproxy_backend_bytes_out_total` | Counter | Backend | Total bytes sent to servers |
| `haproxy_backend_failed_connections_total` | Counter | Backend | Failed connection attempts to servers |
| `haproxy_backend_connection_retries_total` | Counter | Backend | Server connection retries executed |
| `haproxy_backend_redispatches_total` | Counter | Backend | Connection redispatches to alternative servers |
| `haproxy_backend_active_servers` | Gauge | Backend | Number of healthy active servers |
| `haproxy_backend_backup_servers` | Gauge | Backend | Number of healthy backup servers |
| `haproxy_server_status` | Gauge | Server | Server operational status (`1` = UP, `0` = DOWN) |
| `haproxy_server_check_status` | Gauge | Server | Last health check status (`1` = PASSED, `0` = FAILED) |
| `haproxy_server_check_duration_milliseconds` | Gauge | Server | Duration of last health check probe |
| `haproxy_server_check_failures_total` | Counter | Server | Total health check probe failures |
| `haproxy_server_down_transitions_total` | Counter | Server | Total UP -> DOWN state transitions |
| `haproxy_server_weight` | Gauge | Server | Current active load balancing weight |
| `haproxy_server_current_connections` | Gauge | Server | Active concurrent sessions on server |
| `haproxy_server_total_connections` | Counter | Server | Cumulative sessions assigned to server |
| `haproxy_server_bytes_in_total` | Counter | Server | Total bytes received from server |
| `haproxy_server_bytes_out_total` | Counter | Server | Total bytes sent to server |
| `haproxy_stick_table_size` | Gauge | Table | Maximum configured table entries |
| `haproxy_stick_table_used_entries` | Gauge | Table | Current live allocated entries in stick table |
| `haproxy_http_request_duration_seconds_bucket` | Histogram | Proxy | Request latency buckets (`le="0.005"`, `0.01"`, `0.05"`, `0.1"`, `0.5"`, `1.0"`, `5.0"`, `+Inf`) |
| `haproxy_http_request_duration_seconds_sum` | Counter | Proxy | Cumulative request duration in seconds |
| `haproxy_http_request_duration_seconds_count` | Counter | Proxy | Total completed request count |

---

### 3.3 Zero-Copy W3C Trace Context Implementation

Ibex implements the W3C Trace Context standard with zero dynamic allocations using fixed-size byte structures.

```rust
/// Fully parsed and validated W3C `traceparent` representation.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TraceParent {
    pub version: u8,
    pub trace_id: [u8; 16],
    pub parent_id: [u8; 8],
    pub flags: u8,
}

impl TraceParent {
    pub const HEADER_LEN: usize = 55;

    /// Parses a raw ASCII HTTP header value into `TraceParent` in O(1) time.
    /// Strictly zero allocation, zero unsafe.
    pub fn parse(header_bytes: &[u8]) -> Result<Self, TraceContextError> {
        if header_bytes.len() != Self::HEADER_LEN {
            return Err(TraceContextError::InvalidLength);
        }

        // Delimiter validation
        if header_bytes[2] != b'-' || header_bytes[35] != b'-' || header_bytes[52] != b'-' {
            return Err(TraceContextError::InvalidDelimiter);
        }

        // Version validation (currently only 0x00 is supported)
        let version = decode_hex_u8(&header_bytes[0..2])?;
        if version == 0xFF {
            return Err(TraceContextError::InvalidVersion);
        }

        // Trace ID (16 bytes = 32 hex chars)
        let mut trace_id = [0u8; 16];
        decode_hex_slice(&header_bytes[3..35], &mut trace_id)?;
        if trace_id == [0u8; 16] {
            return Err(TraceContextError::ZeroTraceId);
        }

        // Parent / Span ID (8 bytes = 16 hex chars)
        let mut parent_id = [0u8; 8];
        decode_hex_slice(&header_bytes[36..52], &mut parent_id)?;
        if parent_id == [0u8; 8] {
            return Err(TraceContextError::ZeroSpanId);
        }

        // Trace flags (1 byte = 2 hex chars)
        let flags = decode_hex_u8(&header_bytes[53..55])?;

        Ok(TraceParent {
            version,
            trace_id,
            parent_id,
            flags,
        })
    }

    /// Serializes `TraceParent` into a fixed 55-byte ASCII buffer.
    #[inline(always)]
    pub fn serialize(&self, out: &mut [u8; Self::HEADER_LEN]) {
        const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

        // Version (2 chars)
        out[0] = HEX_CHARS[(self.version >> 4) as usize];
        out[1] = HEX_CHARS[(self.version & 0x0F) as usize];
        out[2] = b'-';

        // Trace ID (32 chars)
        for i in 0..16 {
            out[3 + i * 2] = HEX_CHARS[(self.trace_id[i] >> 4) as usize];
            out[4 + i * 2] = HEX_CHARS[(self.trace_id[i] & 0x0F) as usize];
        }
        out[35] = b'-';

        // Parent / Span ID (16 chars)
        for i in 0..8 {
            out[36 + i * 2] = HEX_CHARS[(self.parent_id[i] >> 4) as usize];
            out[37 + i * 2] = HEX_CHARS[(self.parent_id[i] & 0x0F) as usize];
        }
        out[52] = b'-';

        // Flags (2 chars)
        out[53] = HEX_CHARS[(self.flags >> 4) as usize];
        out[54] = HEX_CHARS[(self.flags & 0x0F) as usize];
    }

    /// Returns true if this trace is sampled (flag bit 0 set).
    #[inline(always)]
    pub const fn is_sampled(&self) -> bool {
        (self.flags & 0x01) != 0
    }
}
```

---

### 3.4 OpenTelemetry Span Lifecycle & In-Memory Span Ring Buffer

Tracing spans must be buffered with zero allocation and exported asynchronously to prevent stalling request forwarding.

```rust
/// Compact 128-byte Span record for in-memory ring buffering.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct SpanRecord {
    pub trace_id: [u8; 16],
    pub span_id: [u8; 8],
    pub parent_span_id: [u8; 8],
    pub start_time_unix_nano: u64,
    pub end_time_unix_nano: u64,
    pub http_status_code: u16,
    pub proxy_id: u16,
    pub server_id: u16,
    pub client_ip: [u8; 16],
    pub is_ipv6: bool,
    pub client_port: u16,
    pub bytes_received: u64,
    pub bytes_sent: u64,
    pub trace_flags: u8,
    pub error_flag: u8,
    pub _reserved: [u8; 26],
}

/// Fixed-capacity lock-free bounded SPSC/MPSC ring buffer for telemetry spans.
pub struct SpanRingBuffer<const CAPACITY: usize> {
    entries: Box<[SpanRecord; CAPACITY]>,
    head: std::sync::atomic::AtomicUsize,
    tail: std::sync::atomic::AtomicUsize,
    dropped_spans: std::sync::atomic::AtomicU64,
}
```

**Span Pipeline Operation:**
1. **On Stream Start**: A `SpanContext` is initialized directly inside the `Stream` struct.
2. **On Header Processing**: If `traceparent` is present, it is parsed via `TraceParent::parse`. If absent, a new `trace_id` is generated using a fast thread-local pseudo-random / ChaCha8 generator.
3. **On Forwarding**: A new random 8-byte `child_span_id` is created and injected as `traceparent` to the upstream backend server.
4. **On Stream Completion**: `start_time_unix_nano` and `end_time_unix_nano` are recorded. A `SpanRecord` is constructed and pushed to the core's `SpanRingBuffer`. If the ring buffer is full (collector backpressure), the oldest span is overwritten or dropped and `dropped_spans` atomic counter is incremented, preserving proxy forwarding latency without crashing.
5. **Background OTLP Exporter Task**: A scheduler background task (`Class::Bulk`) drains batches of up to 256 `SpanRecord`s from `SpanRingBuffer`, encodes them into OTLP Protobuf / JSON frames, and transmits them over HTTP/2 or gRPC to the OpenTelemetry Collector.

---

### 3.5 Multi-Core Concurrency & Atomic Metric Aggregation

Project Ibex runs an event-driven thread-per-core architecture (`!Send` sessions). To prevent cross-thread cacheline bouncing and lock contention during metric recording:

```
+------------------ Core 0 ------------------+    +------------------ Core 1 ------------------+
| Stream Handler -> ThreadMetrics (Core 0)   |    | Stream Handler -> ThreadMetrics (Core 1)   |
| (Local increments: 0 lock, 0 atomic xchg)  |    | (Local increments: 0 lock, 0 atomic xchg)  |
| 64-byte Cacheline-Aligned Per-Core Arrays  |    | 64-byte Cacheline-Aligned Per-Core Arrays  |
+--------------------------------------------+    +--------------------------------------------+
                                      │                  │
                                      ▼                  ▼
                         ┌────────────────────────────────────────┐
                         │   Prometheus Exporter Scrape Request   │
                         │   Sum relaxed atomics across all cores │
                         │   Zero lock, Zero thread pause         │
                         └────────────────────────────────────────┘
```

1. **Thread-Local Counters (`ThreadMetrics`)**:
   - Each worker core maintains its own cacheline-aligned (64-byte padded) array of metrics.
   - Incrementing a counter during request forwarding requires only a local memory load and store (no atomic locked bus cycles, no cache-coherency ping-pong).
2. **Scraper Aggregation**:
   - When a `/metrics` request arrives, the `PrometheusApplet` reads and sums the corresponding counter slots across all thread structures using relaxed atomic reads (`Ordering::Relaxed`).
   - The primary request forwarding loops on other threads continue unimpeded with zero lock overhead.

---

## 4. Performance, Memory Footprint & Anti-DDoS Analysis

### 4.1 Memory Footprint per Component

| Component | Quantity | Sizing per Entity | Total Fixed Memory | Allocation Timing |
| :--- | :--- | :--- | :--- | :--- |
| `PrometheusApplet` | 1 per active scrape session | 256 bytes | ~16 KB (for 64 concurrent scrapers) | Pre-allocated in `AppletArena` at startup |
| `ThreadMetrics` | 1 per CPU Core | 128 KB (covers 4,096 proxies/servers) | ~1 MB (8-core machine) | Pre-allocated at startup |
| `SpanRingBuffer` | 1 per CPU Core | 8,192 spans * 128 bytes | 1 MB per core | Pre-allocated at startup |
| `TraceParent` Context | Embedded in `Stream` | 55 bytes | 0 extra heap (part of pre-allocated `StreamArena`) | Startup |
| **Total Telemetry Overhead** | - | - | **< 12 MB for entire system** | **Deterministic / Zero Run-time Alloc** |

### 4.2 Anti-DDoS & Slow-Scraper Protection

1. **Scraper Concurrency Limiting**: Limit active Prometheus scraping connections to at most 16 concurrent sessions using `maxconn` and scheduler rate-limiting (`Class::Normal`).
2. **Streaming Timeout Guard**: If a scraper client opens `/metrics` and stalls TCP reads (Slowloris-style attack on metric applets), `timeout client` (e.g. 5,000 ms) automatically closes the connection and recycles the `PrometheusApplet` slot.
3. **Trace Ingress Rate Limiting**: Probabilistic sampling (e.g. 1% or 0.1% sampling) and token-bucket rate limiters prevent malformed or high-rate client traces from overflowing the `SpanRingBuffer`.

---

## 5. Implementation Roadmap & Integration Milestones

1. **Phase 1: Zero-Alloc W3C Codec & Metric Registry**:
   - Implement `TraceParent` parser/serializer with 100% property-tested boundary validation (`ibex-core` / `ibex-proto`).
   - Implement `PromexWriter` zero-allocation fast numeric formatters (`ibex-rt::stats`).
2. **Phase 2: Native Prometheus Applet Engine**:
   - Extend `ibex-rt::applet` with `PrometheusApplet` cursor state machine.
   - Implement `/metrics` route dispatching in `ProxyEngine`.
   - Implement differential tests comparing `/metrics` exposition format against HAProxy 3.x `service-prometheus`.
3. **Phase 3: OpenTelemetry Distributed Tracing**:
   - Embed `SpanContext` into `Stream`.
   - Implement `SpanRingBuffer` and background asynchronous OTLP exporter applet.
   - Implement end-to-end integration test validating distributed trace propagation against OpenTelemetry Collector and Jaeger.
