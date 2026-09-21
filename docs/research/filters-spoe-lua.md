# Ibex Extensibility Architecture: Filters, Async SPOE & Script Sandboxing

**Status:** Research & Architecture Specification (Milestone 8 / Extensibility Subsystem)  
**Author:** Ibex Extensibility & SPOE/Lua Researcher  
**Safety & Concurrency Invariant:** `#![forbid(unsafe_code)]`, zero-allocation hot-path (NASA JPL Rule 3), level-triggered asynchronous I/O, `!Send` thread-local affinity.

---

## Executive Summary

Extensibility in a soft real-time reverse proxy allows operators to inject custom business logic, Web Application Firewall (WAF) rule sets, external authentication (SSO, OAuth2, LDAP), dynamic header rewriting, and traffic inspection. However, extensibility must not compromise proxy availability, memory safety, or latency predictability.

This specification blueprints the three extensibility tiers for Project Ibex:
1. **Ibex Stream Filter Pipeline (`ibex-filter`)**: A high-performance, zero-allocation native filter engine mirroring HAProxy's filter hooks (`src/filters.c`), orchestrating stream transformations over native HTX buffers.
2. **Rust-Native Async SPOE Client (`ibex-spoe`)**: A zero-copy client implementing the binary Stream Processing Offload Protocol (SPOP v2.0), multiplexing asynchronous requests to out-of-process agent daemons (e.g. ModSecurity WAF, CrowdSec, OPA, OpenResty) without blocking the proxy.
3. **Embedded Script Sandboxing (`ibex-script`)**: A memory-safe, fuel-budgeted script execution sandbox (WASM / Safe Bytecode) operating strictly under `#![forbid(unsafe_code)]` with cooperative preemption and bounded memory quotas.

```
+---------------------------------------------------------------------------------------------------+
|                                     IBEX EXTENSIBILITY STACK                                      |
+---------------------------------------------------------------------------------------------------+
|  L7 Stream Filter Pipeline   |  Filter Lifecycle Hooks  |  Channel Data Cursors | Header Holding  |
|  (crates/ibex-filter)        |  on_headers / on_payload |  Resumable State Mach | HTX Transcoding |
+------------------------------+--------------------------+-----------------------+-----------------+
|  Async SPOE Offload Engine   |  Binary SPOP v2.0 Codec  |  Multiplexed MUX      | Eb64 Tree Trans |
|  (crates/ibex-spoe)          |  Peers Varint / TypedData|  Pipelined Offload    | Action Applier  |
+------------------------------+--------------------------+-----------------------+-----------------+
|  Safe Script Sandboxing      |  WASM / Safe Bytecode    |  Deterministic Fuel   | Memory Slabs    |
|  (crates/ibex-script)        |  Safe Host-Guest ABI     |  HTX Mutator Trait    | Sample Bridge   |
+------------------------------+--------------------------+-----------------------+-----------------+
|  Core Runtime & Sched        |  ibex-sched Class::Normal|  ibex-sample Lattice  | ibex-stick-table|
|  (crates/ibex-rt / sched)    |  Tick Timer Deadlines    |  Zero Alloc Arenas    | #![forbid(..)]  |
+---------------------------------------------------------------------------------------------------+
```

---

## 1. HAProxy Filter Engine Deep Dive (`src/filters.c`)

HAProxy’s filter engine (`src/filters.c`, `include/haproxy/filters.h`, `include/haproxy/filters-t.h`) provides a modular hook architecture attached to streams (`struct stream`).

### 1.1 Filter Data Structures & Topologies

- **`struct flt_conf`**: Proxy-level filter configuration parsed during startup. Contains the filter identifier, vtable callbacks (`struct flt_ops *ops`), and configuration state.
- **`struct filter`**: Stream-level filter instance. Pre-allocated per stream.
  - `calls`: Total invocation counter.
  - `offset[2]`: 64-bit cursor tracking filtered input bytes for request (`offset[0]`) and response (`offset[1]`).
  - `pre_analyzers` / `post_analyzers`: Bitmasks specifying which channel analyzers require filter interception.
- **`struct chn_flt`**: Embedded within `struct channel` (`req.flt` and `res.flt`):
  - `filters`: Doubly-linked list of active filters attached to the channel.
  - `current`: Pointer to the currently executing filter for resumable iteration.
  - `offset`: Channel-level forwarded byte cursor.

### 1.2 Lifecycle Callbacks (`struct flt_ops`)

```
Stream Creation ──> flt_stream_init() ──> ops->attach()
                                 │
                                 ▼
                         ops->stream_start()
                                 │
                                 ▼
Backend Selection ─> ops->stream_set_backend()
                                 │
     ┌───────────────────────────┴───────────────────────────┐
     ▼                                                       ▼
[Request Channel]                                   [Response Channel]
ops->channel_start_analyze()                        ops->channel_start_analyze()
ops->channel_pre_analyze()                          ops->channel_pre_analyze()
ops->http_headers() / http_payload()                ops->http_headers() / http_payload()
ops->channel_post_analyze()                         ops->channel_post_analyze()
ops->channel_end_analyze()                          ops->channel_end_analyze()
     └───────────────────────────┬───────────────────────────┘
                                 ▼
                         ops->stream_stop()
                                 │
                                 ▼
Stream Destruction ─> ops->detach() ──> flt_stream_release()
```

### 1.3 Resumable Filter Loop Execution

A key design requirement in HAProxy is that a filter must be able to pause processing (e.g., waiting for an asynchronous agent response or more data) without blocking the thread or restarting the filter iteration from scratch.

HAProxy implements this via the `resume_filter_list_*` state machine:
```c
static inline struct filter *resume_filter_list_start(struct stream *strm, struct channel *chn) {
    if (chn->flt.current)
        return chn->flt.current;
    return (chn->flt.current = flt_list_start(strm, chn));
}

static inline void resume_filter_list_break(struct stream *strm, struct channel *chn,
                                            struct filter *filter, int ret) {
    chn->flt.current = NULL;
    if (ret == 0) {
        strm->waiting_entity.type = STRM_ENTITY_FILTER;
        strm->waiting_entity.ptr  = filter;
        chn->flt.current = filter; // Save resume point
    }
}
```
When a filter returns `0` (wait), the stream records `chn->flt.current = filter` and yields back to the scheduler. When the stream is later woken up (e.g. on incoming network packet or offload response), `resume_filter_list_start()` immediately resumes execution at the exact filter that yielded.

### 1.4 Payload Filtering & Header Holding (`STRM_FLT_FL_HOLD_HTTP_HDRS`)

When filtering streaming HTTP/HTX payloads, multiple filters may be chained (e.g. SPOE inspection -> Decompression -> HTTP compression). HAProxy maintains an invariant:
- Each filter `f` maintains its own `FLT_OFF(f, chn)`.
- The channel only forwards data up to `min(FLT_OFF(f_1, chn), FLT_OFF(f_2, chn), ...)`.
- If a filter needs to inspect or mutate headers before forwarding them to the backend, it sets the flag `STRM_FLT_FL_HOLD_HTTP_HDRS`. The HTTP analyzer will not commit or forward the request line and headers until all filters clear this requirement.

---

## 2. Stream Processing Offload Engine (SPOE) & Protocol (SPOP)

SPOE (`src/flt_spoe.c`, `src/mux_spop.c`, `doc/SPOE.txt`) offloads CPU-heavy or blocking tasks—such as ModSecurity WAF parsing, virus scanning, machine-learning bot detection, and IP reputation scoring—to external standalone daemons over TCP or Unix Domain Sockets using the binary Stream Processing Offload Protocol (SPOP).

### 2.1 SPOP Binary Frame Format

All SPOP communication occurs via binary frames prefixed by a 4-byte big-endian unsigned length:

```
+------------------------------------------------------------------------------------+
|  FRAME-LENGTH (4 Bytes, Big-Endian Network Byte Order)                             |
+------------------------------------------------------------------------------------+
|  FRAME-TYPE (1 B) |  FLAGS (4 Bytes, BE)  | STREAM-ID (varint) | FRAME-ID (varint) |
+-------------------+-----------------------+--------------------+-------------------+
|  FRAME-PAYLOAD (Variable: KV-LIST | LIST-OF-MESSAGES | LIST-OF-ACTIONS)            |
+------------------------------------------------------------------------------------+
```

#### Frame Types
| Type ID | Name | Direction | Description |
| :--- | :--- | :--- | :--- |
| `1` | `HAPROXY-HELLO` | Proxy -> Agent | Initial handshake announcing supported versions, max frame size, capabilities. |
| `2` | `HAPROXY-DISCONNECT` | Proxy -> Agent | Graceful or error disconnection frame with status code and reason string. |
| `3` | `NOTIFY` | Proxy -> Agent | Transmits stream event messages and typed sample values. |
| `101` | `AGENT-HELLO` | Agent -> Proxy | Handshake response acknowledging negotiated version and frame limits. |
| `102` | `AGENT-DISCONNECT` | Agent -> Proxy | Disconnect frame sent by agent before socket shutdown. |
| `103` | `ACK` | Agent -> Proxy | Acknowledges a `NOTIFY` frame and carries an ordered list of actions. |

#### Frame Flags
- `FIN (0x00000001)`: Indicates the final payload frame. (Must always be set; fragmentation is deprecated).
- `ABORT (0x00000002)`: Indicates that processing for the frame has been aborted.

### 2.2 Peers Variable-Length Integer (`varint`) Encoding

SPOP utilizes HAProxy Peers variable-length integer encoding to serialize 32-bit and 64-bit integers and length prefixes with optimal byte density:

| Value Range | Encoded Bytes | Byte Structure |
| :--- | :--- | :--- |
| `0 <= X < 240` | 1 byte | `[ XXXXXXXX ]` (direct 8-bit value) |
| `240 <= X < 2,288` | 2 bytes | `[ 1111 XXXX ] [ 0XXXXXXX ]` (offset = 240) |
| `2,288 <= X < 264,432` | 3 bytes | `[ 1111 XXXX ] [ 1XXXXXXX ] [ 0XXXXXXX ]` |
| `264,432 <= X < 33,818,864` | 4 bytes | `[ 1111 XXXX ] [ 1XXXXXXX ]*2 [ 0XXXXXXX ]` |
| `33,818,864 <= X < 4,328,786,160` | 5 bytes | `[ 1111 XXXX ] [ 1XXXXXXX ]*3 [ 0XXXXXXX ]` |

### 2.3 SPOP Typed Data Representation

Typed data in SPOP uses a 1-byte header containing a 4-bit Type ID and 4-bit Flag bitfield, followed by payload:
`TYPED-DATA: <TYPE:4 bits><FLAGS:4 bits><DATA>`

| Type ID | Type Name | Byte Payload Format |
| :--- | :--- | :--- |
| `0` | `NULL` | `<0x00>` (no data) |
| `1` | `BOOL` | `<0x01 \| (val ? 0x10 : 0x00)>` |
| `2` | `INT32` | `<0x02> <VALUE:varint>` (ZigZag or direct varint) |
| `3` | `UINT32` | `<0x03> <VALUE:varint>` |
| `4` | `INT64` | `<0x04> <VALUE:varint>` |
| `5` | `UINT64` | `<0x05> <VALUE:varint>` |
| `6` | `IPV4` | `<0x06> <4 bytes network-order in_addr>` |
| `7` | `IPV6` | `<0x07> <16 bytes network-order in6_addr>` |
| `8` | `STRING` | `<0x08> <LENGTH:varint> <UTF-8 / ASCII BYTES>` |
| `9` | `BINARY` | `<0x09> <LENGTH:varint> <RAW BYTES>` |

### 2.4 Payload Structures

1. **`LIST-OF-MESSAGES` (NOTIFY Payload)**:
   ```
   [ <MESSAGE-NAME:String> <NB-ARGS:1 byte> <ARG-NAME:String> <ARG-VALUE:TypedData> ... ]
   ```
2. **`LIST-OF-ACTIONS` (ACK Payload)**:
   ```
   [ <ACTION-TYPE:1 byte> <NB-ARGS:1 byte> <ACTION-ARGS:TypedData> ... ]
   ```
   - **`SET-VAR (1)`**: `NB-ARGS = 3` -> `[VAR-SCOPE: 1 byte, VAR-NAME: String, VAR-VALUE: TypedData]`
     - Scopes: `0: PROCESS`, `1: SESSION`, `2: TRANSACTION`, `3: REQUEST`, `4: RESPONSE`.
   - **`UNSET-VAR (2)`**: `NB-ARGS = 2` -> `[VAR-SCOPE: 1 byte, VAR-NAME: String]`
3. **`KV-LIST` (HELLO & DISCONNECT Payload)**:
   ```
   [ <KEY:String> <VALUE:TypedData> ... ]
   ```

### 2.5 Asynchronous Non-Blocking Execution Model

```
Client Stream (s)               SPOE Filter / Mux               External SPOA Daemon
      │                                 │                                │
      │ 1. Event (e.g. on-http-req)     │                                │
      ├────────────────────────────────>│                                │
      │    Encode NOTIFY frame          │                                │
      │    State: WAITING_ACK           │                                │
      │    Task yielded to scheduler    │  2. NOTIFY (stream_id, frame_id)│
      │ ──[ Proxy handles other FDs ]── │───────────────────────────────>│
      │                                 │                                │  3. WAF / Auth
      │                                 │                                │     Inspection
      │                                 │  4. ACK (stream_id, frame_id)  │
      │                                 │<───────────────────────────────┤
      │                                 │     Actions: set-var ip_score=95
      │ 5. Wake Stream Task             │                                │
      │<────────────────────────────────┤                                │
      │    Apply actions to txn vars    │                                │
      │    Resume HTTP processing       │                                │
```

- **Multiplexed Pipelining**: SPOP multiplexes hundreds of streams over a single TCP connection (`mux_spop`). ACK frames may arrive out of order; the proxy correlates them using `(STREAM-ID, FRAME-ID)`.
- **Fault Tolerance & Circuit Breaking**:
  - `timeout processing`: If the SPOA does not reply within the deadline (e.g. 25ms), the stream aborts offloading.
  - `option continue-on-error`: If the agent is down, the stream continues without offload (fail-open) or can reject the request with HTTP 500/503 (fail-close).
  - Variable prefixes (`option var-prefix`) prevent namespace collisions between independent security agents.

---

## 3. HAProxy Lua Engine Deep Dive (`src/hlua.c`)

HAProxy embeds a Lua 5.3/5.4 engine (`src/hlua.c`, `src/hlua_fcn.c`, `doc/lua.txt`) allowing custom scripting for sample fetches, converters, actions, and full background services/applets.

### 3.1 Architecture & Coroutine Encapsulation

- **`struct hlua`**: Represents the Lua execution context for a stream or background task:
  - `lua_State *T`: The coroutine stack allocated via `lua_newthread()`.
  - `flags`: State flags (`HLUA_RUN`, `HLUA_CTRLYIELD`, `HLUA_EXIT`, `HLUA_NOYIELD`, `HLUA_BUSY`).
  - `timer`: `struct hlua_timer` tracking cumulative CPU runtime against execution budgets.
  - `task`: Pointer to the `struct task` registered in HAProxy's scheduler.

### 3.2 Cooperative Scheduling Loop (`hlua_ctx_resume`)

The engine enters Lua execution through `hlua_ctx_resume()`:

```c
int hlua_ctx_resume(struct hlua *lua, int yield_allowed) {
    // 1. Arm instruction count hook to prevent infinite loops
    lua_sethook(lua->T, hlua_hook, LUA_MASKCOUNT, hlua_get_nb_instruction(lua));
    
    // 2. Start CPU burst timer
    hlua_timer_start(&lua->timer);
    
    // 3. Resume Lua coroutine
    ret = lua_resume(lua->T, hlua_states[lua->state_id], lua->nargs, &nres);
    
    // 4. Stop CPU burst timer
    hlua_timer_stop(&lua->timer);
    
    switch (ret) {
        case LUA_OK:
            return HLUA_E_OK;
            
        case LUA_YIELD:
            // Check execution and burst timeouts
            if (hlua_timer_check(&lua->timer) <= 0) {
                lua_settop(lua->T, 0);
                return HLUA_E_ETMOUT;
            }
            // If forced yield from instruction hook:
            if (HLUA_IS_CTRLYIELDING(lua)) {
                task_wakeup(lua->task, TASK_WOKEN_MSG); // Reschedule self
                return HLUA_E_AGAIN;
            }
            // If yielding on I/O or sleep:
            return HLUA_E_AGAIN; // Stay parked until I/O or timer event wakes task
            
        case LUA_ERRRUN:
            // Capture runtime error and stack traceback
            return HLUA_E_ERRMSG;
    }
}
```

### 3.3 Instruction Counting Hook (`hlua_hook`) & Anti-Stall Protection

To prevent a rogue or buggy Lua script containing `while true do end` from hanging the single-threaded epoll loop:
1. `lua_sethook(lua->T, hlua_hook, LUA_MASKCOUNT, tune.lua.instructions)` configures the Lua bytecode interpreter to execute `hlua_hook()` every 10,000 bytecode instructions.
2. In `hlua_hook()`:
   ```c
   if (lua_isyieldable(L)) {
       MAY_LJMP(hlua_yieldk(L, 0, 0, NULL, TICK_ETERNITY, HLUA_CTRLYIELD));
       return;
   }
   ```
3. The hook forces a yield with the flag `HLUA_CTRLYIELD`.
4. `hlua_ctx_resume()` catches the yield, enqueues `lua->task` in the scheduler, and immediately returns control to HAProxy's event loop.
5. Established connections and epoll I/O proceed without latency spikes. When the scheduler next services `lua->task`, the Lua coroutine resumes where it was interrupted.

### 3.4 Non-Blocking Asynchronous I/O via Continuation Yields (`hlua_yieldk`)

When a Lua script performs network I/O (`core.tcp()`, `httpclient:send()`, `applet:receive()`, `core.msleep()`):
1. The socket I/O call attempts non-blocking `recv()` / `send()`.
2. If data is not ready (`EAGAIN` / buffer empty), the Lua C-binding registers the socket FD with HAProxy's poller and calls:
   ```c
   hlua_yieldk(L, 0, 0, hlua_socket_receive_yield, timeout_tick, 0);
   ```
3. Crucially, `HLUA_CTRLYIELD` is **not** set. The task is **not** rescheduled in the run queue.
4. When the poller detects `FD_POLL_IN` on the socket (or the timeout expires), the I/O callback calls `task_wakeup(lua->task, TASK_WOKEN_IO)`.
5. The scheduler runs `lua->task`, calling `hlua_ctx_resume()`, which enters the Lua continuation function `hlua_socket_receive_yield` to consume the newly arrived socket data.
6. **Result**: Zero thread blocking and zero epoll loop stalls during external network calls.

---

## 4. Project Ibex Filter Architecture Blueprint

The Project Ibex Filter Engine (`crates/ibex-filter`) provides a pure `#![forbid(unsafe_code)]` stream filter pipeline.

### 4.1 Safe Trait Definition (`IbexFilter`)

```rust
pub enum FilterResult {
    /// Proceed to the next filter in the chain.
    Continue,
    /// Pause execution; wait for asynchronous event or more data.
    Wait,
    /// Withhold HTTP headers from upstream forwarding.
    HoldHeaders,
    /// Abort transaction immediately with HTTP error status.
    Abort(u16),
}

pub enum FilterDataResult {
    /// Forward `n` bytes of payload down the pipeline.
    Forward(usize),
    /// Withhold all data until additional chunks arrive.
    Wait,
    /// Abort payload processing with HTTP error status.
    Abort(u16),
}

pub trait IbexFilter: 'static {
    /// Filter name for logging and debugging.
    fn name(&self) -> &'static str;

    /// Invoked when a stream transaction is instantiated.
    fn on_stream_start(&mut self, _ctx: &mut StreamContext) -> FilterResult {
        FilterResult::Continue
    }

    /// Invoked when HTTP request headers have been parsed into HTX.
    fn on_client_headers(&mut self, _ctx: &mut StreamContext, _req: &mut HtxBuffer) -> FilterResult {
        FilterResult::Continue
    }

    /// Invoked as request body chunks stream through HTX.
    fn on_client_body(
        &mut self,
        _ctx: &mut StreamContext,
        _req: &mut HtxBuffer,
        _offset: usize,
        len: usize,
    ) -> FilterDataResult {
        FilterDataResult::Forward(len)
    }

    /// Invoked when HTTP response headers are received from backend.
    fn on_server_headers(&mut self, _ctx: &mut StreamContext, _res: &mut HtxBuffer) -> FilterResult {
        FilterResult::Continue
    }

    /// Invoked as response body chunks stream from backend.
    fn on_server_body(
        &mut self,
        _ctx: &mut StreamContext,
        _res: &mut HtxBuffer,
        _offset: usize,
        len: usize,
    ) -> FilterDataResult {
        FilterDataResult::Forward(len)
    }

    /// Invoked when the stream terminates.
    fn on_stream_end(&mut self, _ctx: &mut StreamContext) {}
}
```

### 4.2 Zero-Allocation Filter Chain Layout

In adherence to NASA JPL Rule 3 (no dynamic heap allocations on the request hot path), filter instances and channel cursors are statically pre-allocated in the stream context arena:

```rust
pub const MAX_STREAM_FILTERS: usize = 8;

pub struct FilterSlot {
    pub filter: Box<dyn IbexFilter>,
    pub req_offset: u64,
    pub res_offset: u64,
    pub is_resumable: bool,
}

pub struct FilterChain {
    pub slots: BoundedVec<FilterSlot, MAX_STREAM_FILTERS>,
    pub hold_http_headers: bool,
    pub current_filter_idx: Option<usize>,
}

impl FilterChain {
    pub fn process_client_headers(
        &mut self,
        ctx: &mut StreamContext,
        htx: &mut HtxBuffer,
    ) -> FilterResult {
        let start_idx = self.current_filter_idx.unwrap_or(0);
        for idx in start_idx..self.slots.len() {
            let slot = &mut self.slots[idx];
            match slot.filter.on_client_headers(ctx, htx) {
                FilterResult::Continue => {}
                FilterResult::HoldHeaders => {
                    self.hold_http_headers = true;
                }
                FilterResult::Wait => {
                    self.current_filter_idx = Some(idx);
                    return FilterResult::Wait;
                }
                FilterResult::Abort(status) => {
                    self.current_filter_idx = None;
                    return FilterResult::Abort(status);
                }
            }
        }
        self.current_filter_idx = None;
        FilterResult::Continue
    }
}
```

---

## 5. Project Ibex Rust-Native Async SPOE Client Blueprint

The Project Ibex SPOE Client (`crates/ibex-spoe`) provides an asynchronous binary SPOP v2.0 offload client implemented purely in safe Rust.

### 5.1 Safe SPOP Binary Wire Codec

```rust
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SpopFrameType {
    HaproxyHello = 1,
    HaproxyDisconnect = 2,
    Notify = 3,
    AgentHello = 101,
    AgentDisconnect = 102,
    Ack = 103,
}

pub struct SpopHeader {
    pub frame_type: SpopFrameType,
    pub flags: u32,
    pub stream_id: u64,
    pub frame_id: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SpopTypedData<'a> {
    Null,
    Boolean(bool),
    Int32(i32),
    Uint32(u32),
    Int64(i64),
    Uint64(u64),
    Ipv4([u8; 4]),
    Ipv6([u8; 16]),
    Str(&'a str),
    Binary(&'a [u8]),
}

#[derive(Debug, Clone, PartialEq)]
pub enum SpopAction<'a> {
    SetVar {
        scope: SpopVarScope,
        name: &'a str,
        value: SpopTypedData<'a>,
    },
    UnsetVar {
        scope: SpopVarScope,
        name: &'a str,
    },
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SpopVarScope {
    Process = 0,
    Session = 1,
    Transaction = 2,
    Request = 3,
    Response = 4,
}
```

#### Zero-Copy Peers Varint Codec (`#![forbid(unsafe_code)]`)

```rust
pub struct SpopCodec;

impl SpopCodec {
    #[inline]
    pub fn decode_varint(buf: &[u8]) -> Result<(u64, usize), SpoeCodecError> {
        if buf.is_empty() {
            return Err(SpoeCodecError::UnexpectedEof);
        }
        let first = buf[0];
        if first < 240 {
            return Ok((first as u64, 1));
        }
        let mut val = (first - 240) as u64;
        let mut shift = 4;
        let mut idx = 1;
        while idx < buf.len() {
            let b = buf[idx];
            idx += 1;
            val |= ((b & 0x7F) as u64) << shift;
            shift += 7;
            if (b & 0x80) == 0 {
                return Ok((val + 240, idx));
            }
        }
        Err(SpoeCodecError::UnexpectedEof)
    }

    #[inline]
    pub fn encode_varint(mut val: u64, out: &mut [u8]) -> Result<usize, SpoeCodecError> {
        if val < 240 {
            if out.is_empty() { return Err(SpoeCodecError::BufferOverflow); }
            out[0] = val as u8;
            return Ok(1);
        }
        if out.len() < 2 { return Err(SpoeCodecError::BufferOverflow); }
        val -= 240;
        out[0] = (240 + (val & 0x0F)) as u8;
        val >>= 4;
        let mut idx = 1;
        while val >= 128 {
            if idx >= out.len() { return Err(SpoeCodecError::BufferOverflow); }
            out[idx] = (0x80 | (val & 0x7F)) as u8;
            val >>= 7;
            idx += 1;
        }
        if idx >= out.len() { return Err(SpoeCodecError::BufferOverflow); }
        out[idx] = (val & 0x7F) as u8;
        Ok(idx + 1)
    }
}
```

### 5.2 Multiplexed SPOP Connection & Transaction Router

```rust
pub struct PendingSpoeTxn {
    pub stream_id: u32,
    pub task_ref: TaskRef,
    pub deadline: Tick,
}

pub struct SpopMux {
    pub fd: RawFd,
    pub pending_txns: Eb64Tree<PendingSpoeTxn>, // Key = (stream_id << 32) | frame_id
    pub out_buf: BoundedRingBuffer<65536>,
    pub in_buf: BoundedRingBuffer<65536>,
    pub state: SpopMuxState,
}
```

- When a stream triggers an SPOE offload event, it serializes a `NOTIFY` frame into the multiplexer's `out_buf`, registers its `(stream_id, frame_id)` in the `pending_txns` tree, sets a timeout in `ibex-sched`, and yields.
- When the SPOP socket receives bytes, `SpopMux` decodes incoming `ACK` frames, looks up the corresponding `PendingSpoeTxn` in $O(k)$ time via `Eb64Tree`, executes the decoded actions (`SetVar`/`UnsetVar`) on the transaction sample variables, and calls `sched.wakeup(txn.task_ref)`.

---

## 6. Project Ibex Embedded Script Sandboxing Blueprint

To support custom on-the-fly request evaluation (equivalent to HAProxy Lua) under strict `#![forbid(unsafe_code)]`, Ibex utilizes a sandboxed, fuel-metered bytecode execution engine.

### 6.1 Pure-Rust Script Engine Architecture Comparison

| Engine Strategy | Safety Invariant | Instruction Budgeting (Fuel) | Memory Bounds | Cold Start / Overhead |
| :--- | :--- | :--- | :--- | :--- |
| **Wasmtime / Safe WASM** | Pure safe wrapper; capabilities sandbox | Hardware & Software fuel subtraction | Strict WebAssembly Linear Memory Pages | ~50µs instantiation / near-native speed |
| **Pure-Rust Script (Rhai / Rune)** | `#![forbid(unsafe_code)]` native Rust | AST / Opcode step limits | Bounded Arena Allocator | ~1µs execution / lightweight |
| **C Lua FFI (`mlua` / C-Lua)** | Requires `unsafe` C bindings | Debug hook instruction counters | Difficult to isolate C heaps | Requires unsafe isolation boundary |

**Ibex Architecture Decision**: Project Ibex adopts a dual-tier sandbox:
1. **Tier 1 (Safe Bytecode / Rhai / Safe-Lua Interpreter)**: Compiled under `#![forbid(unsafe_code)]` for microsecond-latency request header transforms, custom rate limiting, and dynamic routing rules.
2. **Tier 2 (WASM Core Sandbox)**: Capability-isolated WebAssembly engine for complex third-party WAF filters and legacy plugins.

### 6.2 Deterministic Fuel Accounting & Cooperative Preemption

```rust
pub struct ScriptBudget {
    pub max_fuel: u64,
    pub remaining_fuel: u64,
    pub memory_quota_bytes: usize,
    pub allocated_bytes: usize,
}

pub enum ScriptOutcome<T> {
    Complete(T),
    Yielded { continuation_id: u32 },
    OutOfFuel,
    OutOfMemory,
    RuntimeError(String),
}
```

- **Fuel Metering**: Each script execution turn is granted a fixed quota (e.g. 50,000 fuel units). Each bytecode operation, string concatenation, and memory allocation deducts fuel.
- **Cooperative Resumption**: If fuel runs out during a long-running computation, the script engine serializes its execution frame, yields control to `ibex-sched` with `Class::Normal`, and reschedules itself, preventing event loop starvation.
- **Memory Sandboxing**: Script memory allocations draw strictly from a pre-allocated per-stream `StaticArena` (e.g. 64 KB). Exceeding this budget triggers immediate, graceful trap termination without panics.

### 6.3 Safe Host-Guest ABI

The guest script interacts with the proxy strictly through safe reference wrappers:

```rust
pub trait ScriptHostAbi {
    /// Retrieve sample value from the sample lattice (e.g. "req.hdr(Host)").
    fn get_sample(&self, sample_name: &str) -> Option<Sample>;

    /// Inject or rewrite an HTTP header in native HTX.
    fn set_header(&mut self, name: &str, value: &str) -> Result<(), ScriptError>;

    /// Delete an HTTP header in native HTX.
    fn del_header(&mut self, name: &str) -> Result<(), ScriptError>;

    /// Read or increment stick-table rate counters.
    fn stick_table_track(&mut self, table_id: u32, key: &[u8]) -> Result<u64, ScriptError>;

    /// Perform a non-blocking background TCP/HTTP request.
    fn async_fetch(&mut self, url: &str, timeout_ms: u32) -> Result<u32, ScriptError>;
}
```

---

## 7. Memory Bounds & NASA JPL Rule 3 Conformance

1. **Zero Dynamic Allocation on Request Flow**: All `IbexFilter` slots, `SpopMux` frame buffers, and script state contexts are sized and pre-allocated at proxy initialization.
2. **Deterministic Bounded Iteration**: All binary frame parsing loops in `ibex-spoe` and `ibex-filter` are wrapped with `bounded_loop!(1024)` macros to prevent algorithmic complexity attacks on malformed inputs.
3. **No Unsafe Pointer Sharing**: Unlike HAProxy's `void *ctx` and raw C pointers, Ibex filters, SPOE multiplexers, and script sandboxes interact exclusively through borrow-checked typed references, guaranteeing spatial and temporal memory safety.

---

## 8. Implementation Roadmap & Milestones

| Milestone | Deliverable | Target Crate | Verification Standard |
| :--- | :--- | :--- | :--- |
| **8.1** | Core Filter Trait & HTX Pipeline Hooks | `crates/ibex-filter` | Unit tests with mock filter chains; differential test with HAProxy `flt_http_comp`. |
| **8.2** | Safe SPOP v2.0 Binary Codec | `crates/ibex-spoe` | Differential codec fuzzing against HAProxy `flt_spoe.c` frames; varint property tests. |
| **8.3** | Async SPOE Multiplexing Engine | `crates/ibex-spoe` | End-to-end integration test with real SPOA daemon (e.g. Python/C SPOA server). |
| **8.4** | Pure-Safe Script Sandboxing & Host ABI | `crates/ibex-script` | Fuel exhaustion tests; memory ceiling assertion tests; WAF rule benchmarks. |
