# Alcyon QUIC & HTTP/3 Architecture Blueprint

**Status:** Research & Architecture Specification (Milestone 7 / Future Transport Architecture)  
**Author:** Alcyon QUIC & HTTP/3 Architecture Researcher  
**Safety & Concurrency Invariant:** `#![forbid(unsafe_code)]`, zero-allocation hot-path (NASA JPL Rule 3), level-triggered batch I/O, `!Send` thread-local affinity.

---

## Executive Summary

QUIC (RFC 9000), QUIC TLS 1.3 (RFC 9001), and HTTP/3 (RFC 9114) represent a paradigm shift in Internet transport and proxy architecture. Unlike TCP where the kernel handles stream reassembly, congestion control, ACK generation, and connection state machines, QUIC places the entire transport and encryption stack inside the userspace application layer over UDP datagrams.

This document establishes the architecture for native QUIC and HTTP/3 in Project Alcyon, based on exhaustive research into:
1. **HAProxy 3.5-dev native QUIC/H3 implementation** (`src/quic_sock.c`, `src/quic_cid.c`, `src/quic_conn.c`, `src/quic_rx.c`, `src/quic_tx.c`, `src/quic_tls.c`, `src/quic_ssl.c`, `src/xprt_quic.c`, `src/mux_quic.c`, `src/h3.c`, and `include/haproxy/quic_*.h`).
2. **IETF Standards**: RFC 9000 (QUIC Transport), RFC 9001 (QUIC TLS 1.3), RFC 9002 (Loss Detection & Congestion Control), RFC 9114 (HTTP/3), and RFC 9204 (QPACK).
3. **Rustls 0.23 QUIC Engine**: Operating strictly under `#![forbid(unsafe_code)]`, providing record-less TLS 1.3 handshake state machines, header protection key derivation, and packet encryption.
4. **Alcyon Engine Integration**: Level-triggered `Poller` with `recvmmsg`/`sendmmsg` batching, `FdTab` virtualized FD-less sessions, 256-shard `ebtree` CID routing, stateless ODCID hashing, zero-allocation packet and frame index arenas, unified TCP/QUIC TLS 1.3 certificate dispatch, and `Class::Heavy` scheduler throttling against asymmetric handshake attacks.

```
+---------------------------------------------------------------------------------------------------+
|                                          ALCYON ARCHITECTURE                                        |
+---------------------------------------------------------------------------------------------------+
|  L7 HTTP/3 (RFC 9114)  |  H3 Control Stream (0x00)  |  QPACK Streams (0x02/03)  | Request Streams |
|                        +----------------------------+---------------------------+-----------------+
|                        |             Direct Zero-Copy Transcoding to Native HTX Blocks            |
+------------------------+--------------------------------------------------------------------------+
|  L7 MUX (mux_quic)     | Stream Multiplexing | Stream Flow Control | Out-of-Order Reassembly Tree |
+------------------------+--------------------------------------------------------------------------+
|  L5/6 Transport        |  rustls::quic (RFC 9001 TLS 1.3)  |  Initial / Handshake / 1-RTT Keys   |
|  (xprt_quic)           |  Header Protection (AES-ECB/ChaCha20) | In-Band Key Updates (1-bit phase) |
+------------------------+--------------------------------------------------------------------------+
|  L4 QUIC Transport     | Packet Coalescing | Loss Detection & ACK Ranges | CUBIC/BBR Congestion   |
|  (quic_conn)           | Connection Migration | Path MTU Discovery | Anti-Amplification (3x Limit)|
+------------------------+--------------------------------------------------------------------------+
|  Ingress & Routing     | 256-Shard EbMbTree CID Routing | Stateless ODCID XXH64 | Inter-Thread Ring|
|  (quic_sock)           | Level-Triggered recvmmsg / sendmmsg / UDP_SEGMENT GSO | FdTab (CO_FL_FDLESS)|
+---------------------------------------------------------------------------------------------------+
```

---

## 1. HAProxy Native QUIC & HTTP/3 Architecture Deep Dive

HAProxy's native QUIC engine was developed to achieve bare-metal performance without external third-party C libraries (such as `quiche` or `ngtcp2`), relying on an internal modular architecture that integrates with its event loop, `ebtree`, memory pools, and `HTX` buffering.

### 1.1 Socket Layer & Poller Interaction (`src/quic_sock.c`, `include/haproxy/quic_sock.h`)

HAProxy manages UDP sockets through two distinct operational modes:
1. **Shared Listener Socket (`QUIC_SOCK_MODE_LSTNR`)**:
   - A single UDP socket bound to the listening port handles all incoming datagrams from thousands of concurrent clients.
   - When the file descriptor becomes readable (`FD_POLL_IN`), `quic_lstnr_sock_fd_iocb()` is invoked.
   - Datagrams are received in a tight batch loop bounded by `global.tune.maxpollevents` using `recvmsg()` (or `recvmmsg()`).
   - The socket relies on `IP_PKTINFO` (IPv4) or `IPV6_RECVPKTINFO` (IPv6) via `recvmsg()` control ancillary data (`struct cmsghdr`) to retrieve the exact local destination IP address and port, ensuring response datagrams are transmitted with the correct source IP even when bound to wildcard `0.0.0.0` or `::`.
2. **Dedicated Connected Connection Sockets (`QUIC_SOCK_MODE_CONN`)**:
   - For established connections under high traffic, HAProxy can optionally allocate a dedicated UDP socket (`qc_alloc_fd()`), call `connect()` to the remote client address/port, and attach it to the `quic_conn`.
   - The kernel filters packets for that connection, offloading IP/port matching and enabling direct level-triggered FD wakeups via `quic_conn_sock_fd_iocb()`.
3. **Virtualized `CO_FL_FDLESS` Connections**:
   - In the common shared listener mode, individual QUIC connections do not possess a unique OS file descriptor.
   - The connection struct is marked with the flag `CO_FL_FDLESS`. The higher-level session and stream engines operate without raw FD operations, delegating all I/O subscriptions to the QUIC transport layer (`xprt_quic`).
4. **Inter-Thread Datagram Dispatching (`mpring`)**:
   - Incoming datagrams arriving on thread $T_A$ may belong to a connection owned by thread $T_B$ (identified by the Destination Connection ID).
   - Rather than locking the connection across threads, thread $T_A$ enqueues the datagram into a lock-free multi-producer ring buffer (`mpring_write_reserve` / `mpring_write_commit` on `quic_dghdlrs[cid_tid].buf`) and wakes the target thread's tasklet (`quic_lstnr_dghdlr`).
5. **GSO / GRO Batch Transmission**:
   - QUIC packet egress leverages Generic Segmentation Offload (`UDP_SEGMENT` via `cmsg_set_gso()`) in `qc_snd_buf()`. Multiple coalesced packets up to 64 KB are passed to the kernel in a single `sendmsg()` call, where the network interface card (NIC) segments them into MTU-sized UDP datagrams, drastically reducing syscall overhead.

### 1.2 Connection ID Architecture & `ebtree` Dispatch (`src/quic_cid.c`, `include/haproxy/quic_cid.h`)

Routing incoming UDP datagrams to the correct connection object is the central routing challenge of QUIC. HAProxy solves this with a multi-tier `ebtree` design:

```
                          Incoming UDP Datagram
                                    │
                         Extract DCID (1st byte)
                                    │
                       ┌────────────┴────────────┐
                       │  _quic_cid_tree_idx()   │
                       │     (index = cid[0])    │
                       └────────────┬────────────┘
                                    │
                 ┌──────────────────┼──────────────────┐
                 ▼                  ▼                  ▼
          ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
          │ Tree Shard 0│    │Tree Shard 1 │... │Tree Shard255│
          │ (EbMbTree)  │    │ (EbMbTree)  │    │ (EbMbTree)  │
          └──────┬──────┘    └─────────────┘    └─────────────┘
                 │
            ebmb_lookup()
                 │
        ┌────────┴────────┐
        ▼                 ▼
   [Found Node]      [Not Found]
        │                 │
Extract quic_conn   Is INITIAL or 0-RTT?
        │                 │
Dispatch to Thread   ┌────┴────┐
                     ▼         ▼
                   [Yes]      [No]
                     │         │
          quic_derive_cid()  Drop Packet
          (XXH64 from ODCID)
                     │
              Re-lookup in Shard
```

1. **256-Way Sharded Match-Bytes Tree (`quic_fe_cid_trees[256]`)**:
   - To eliminate global lock contention across worker threads, HAProxy shards the global frontend Connection ID lookup table into 256 independent `ebmbtree` (Match-Bytes Tree) instances.
   - The shard index is determined by the first byte of the Connection ID (`cid[0]`).
   - Each shard is protected by an independent reader-writer lock (`HA_RWLOCK_RDLOCK` / `HA_RWLOCK_WRLOCK`), enabling concurrent, lock-free parallel lookups across threads.
2. **Stateless ODCID Derivation Optimization**:
   - When a client initiates a connection, it generates a random Destination Connection ID, termed the Original Destination Connection ID (ODCID).
   - If the server inserted every random ODCID into the global tree, malicious clients could flood Initial packets to exhaust server memory and trigger lock churn.
   - HAProxy avoids inserting ODCIDs into the global tree. Instead, it deterministically derives a new server Connection ID from the ODCID using XXH64:
     $$\text{Derived CID} = \text{XXH64}(\text{ODCID} \mathbin{\Vert} \text{Client IP:Port} \mathbin{\Vert} \text{Boot Seed})$$
   - When subsequent Initial or 0-RTT packets arrive with the ODCID, `retrieve_qc_conn_from_cid()` detects a cache miss, computes `quic_derive_cid()`, and executes a secondary lookup on the derived CID shard. Once the handshake completes, the client switches to the server-assigned CID.
3. **Per-Connection Active CID Tree (`qc->cids`)**:
   - Each `quic_conn` maintains a local `eb64_tree` of active Connection IDs keyed by sequence number (`conn_id->seq_num.key`).
   - When `NEW_CONNECTION_ID` or `RETIRE_CONNECTION_ID` frames are processed, nodes are inserted or retired in $O(\log N)$ with $N \le 8$, guaranteeing deterministic bounded execution.

### 1.3 Core Connection State Machine & Packet Engine (`src/quic_conn.c`, `src/quic_rx.c`, `src/quic_tx.c`)

1. **Three Independent Packet Number Spaces**:
   - `QUIC_PKTNS_INITIAL`: Carries Initial `CRYPTO` frames for `ClientHello` / `ServerHello`.
   - `QUIC_PKTNS_HANDSHAKE`: Carries Handshake `CRYPTO` frames for certificate exchange and `Finished`.
   - `QUIC_PKTNS_APP` (Application / 0-RTT / 1-RTT): Carries user application data (`STREAM`), HTTP/3 frames, and active path management.
   - Packet numbers are monotonically increasing 62-bit integers within each space. ACKs in one packet number space never acknowledge packets in another space.
2. **Header Protection & Packet Number Decoding (`qc_do_rm_hp`)**:
   - Ingress datagrams have their packet numbers and header flags masked to prevent traffic analysis.
   - A 16-byte sample is extracted from the packet payload at `pn_offset + 4`.
   - The sample is decrypted using the Header Protection cipher context (`rx.hp_ctx`, AES-ECB or ChaCha20) to generate a 5-byte mask.
   - Mask byte 0 unmasks the header flags and reveals the packet number length ($1 \dots 4$ bytes).
   - Mask bytes $1 \dots 4$ unmask the truncated packet number.
   - The full 62-bit packet number is reconstructed via `decode_packet_number()` using the largest received packet number window:
     $$\text{Candidate} = (\text{ExpectedPN} \mathbin{\&} \sim\text{Mask}) \mid \text{TruncatedPN}$$
3. **In-Place AEAD Decryption (`qc_pkt_decrypt`)**:
   - Packet payloads are decrypted in place using AES-128-GCM, AES-256-GCM, or ChaCha20-Poly1305.
   - Associated Authenticated Data (AAD) includes the unprotected header bytes up to the packet payload offset.
4. **Packet Coalescing & Frame Packing (`quic_tx.c`)**:
   - Egress UDP datagrams coalesce multiple QUIC packets across different encryption levels into a single datagram (e.g., `Initial[ACK, CRYPTO]` + `Handshake[ACK, CRYPTO]` + `1-RTT[STREAM]`).
   - Coalescing maximizes MTU utilization and eliminates handshake round-trips.
5. **Loss Detection, ACK Ranges, and Congestion Control**:
   - ACKs use compressed range encoding (Largest Acknowledged, First ACK Range, Gap, ACK Range blocks).
   - Retransmission does not retransmit the packet; instead, individual unacknowledged frames (`STREAM`, `CRYPTO`) are re-queued into the packet builder.
   - Congestion control is modular: CUBIC (`quic_cc_cubic.c`), NewReno (`quic_cc_newreno.c`), and BBR (`quic_cc_bbr.c`) track bytes in flight against `cwnd` and `ssthresh`, with burst pacing (`quic_pacing.c`) to smooth packet release.

### 1.4 Transport Layer & Stream Multiplexer (`src/xprt_quic.c`, `src/mux_quic.c`)

1. **Transport Layer Abstraction (`xprt_quic.c`)**:
   - Implements HAProxy's `xprt_ops` vtable for QUIC.
   - Provides `subscribe()` / `unsubscribe()` for `SUB_RETRY_RECV` and `SUB_RETRY_SEND` wait events, seamlessly integrating with the scheduler without polling OS descriptors.
2. **Stream Multiplexer (`mux_quic.c`)**:
   - Manages connection context `struct qcc` and individual stream contexts `struct qcs`.
   - Tracks the stream identifier bitmask:
     - Bit 0: Client-initiated (`0`) vs Server-initiated (`1`)
     - Bit 1: Bidirectional (`0`) vs Unidirectional (`1`)
   - Manages stream state: `IDLE`, `OPEN`, `HALF_CLOSED_REMOTE`, `HALF_CLOSED_LOCAL`, `CLOSED`.
   - Flow control enforcement: Per-stream flow control (`MAX_STREAM_DATA` / `STREAM_DATA_BLOCKED`) and connection flow control (`MAX_DATA` / `DATA_BLOCKED`).
3. **Out-of-Order Stream Frame Reassembly**:
   - QUIC packets may arrive out of order over UDP.
   - Incoming `STREAM` frames are inserted into an `eb64_tree` keyed by stream byte offset (`rxbuf->off_node`).
   - Contiguous in-order byte ranges are delivered to the application layer; gaps remain buffered in the tree until missing offsets arrive.

### 1.5 HTTP/3 Protocol Layer & Zero-Copy HTX Transcoding (`src/h3.c`)

HAProxy's HTTP/3 engine sits directly atop `mux_quic`:
1. **Unidirectional Control & QPACK Streams**:
   - Upon connection establishment, HAProxy opens a server unidirectional Control Stream (type `0x00`) and transmits its `SETTINGS` frame (`SETTINGS_MAX_FIELD_SECTION_SIZE`, `SETTINGS_QPACK_MAX_TABLE_CAPACITY`, `SETTINGS_QPACK_BLOCKED_STREAMS`).
   - Opens unidirectional QPACK Encoder (type `0x02`) and Decoder (type `0x03`) streams to maintain dynamic header compression tables.
2. **HTTP/3 Frame Demuxing**:
   - Frame format: `Type` (VarInt) + `Length` (VarInt) + `Payload`.
   - Parses `HEADERS` (0x01) and `DATA` (0x00) frames from bidirectional client request streams.
3. **Zero-Copy HTX Transcoding**:
   - HTTP/3 QPACK headers are decoded directly into native HTX blocks (`HTX_BLK_REQ_HDR`, `htx_add_header()`), avoiding intermediary string allocations.
   - HTTP/3 `DATA` payloads are streamed directly into HTX data blocks (`HTX_BLK_DATA`), matching the exact pipeline used for HTTP/1.1 (`mux_h1`) and HTTP/2 (`mux_h2`).

---

## 2. RFC 9000, RFC 9001, RFC 9114 & `rustls::quic` Specifications

### 2.1 RFC 9000: QUIC Transport Protocol

```
+-----------------------------------------------------------------------------------------------+
| Long Header Packet (Initial, 0-RTT, Handshake, Retry)                                          |
| 0                   1                   2                   3                                 |
| 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1                                 |
|+-+-+-+-+-+-+-+-+-----------------------------------------------+                              |
||1|1|T T|X X X X|                Version (32)                   |                              |
|+-+-+-+-+-+-+-+-+-----------------------------------------------+                              |
||DCID Len (8)   |          Destination Connection ID (0..160)   |                              |
|+-+-+-+-+-+-+-+-+-----------------------------------------------+                              |
||SCID Len (8)   |             Source Connection ID (0..160)     |                              |
|+-+-+-+-+-+-+-+-+-----------------------------------------------+                              |
|| Payload Length (VarInt) | Packet Number (8..32) | Protected Payload (AEAD Tag) ...          |
+-----------------------------------------------------------------------------------------------+
| Short Header Packet (1-RTT Application Data)                                                  |
| 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1                                 |
|+-+-+-+-+-+-+-+-+-----------------------------------------------+                              |
||0|1|S|R|R|K|P P|          Destination Connection ID (0..160)   |                              |
|+-+-+-+-+-+-+-+-+-----------------------------------------------+                              |
|| Packet Number (8..32) | Protected Payload & Frames (AEAD Tag) ...                            |
+-----------------------------------------------------------------------------------------------+
```

1. **Variable-Length Integer (VarInt) Encoding**:
   - 2-bit prefix dictates integer length:
     - `00`: 1 byte (6-bit integer, $0 \dots 63$)
     - `01`: 2 bytes (14-bit integer, $0 \dots 16,383$)
     - `10`: 4 bytes (30-bit integer, $0 \dots 1,073,741,823$)
     - `11`: 8 bytes (62-bit integer, $0 \dots 4,611,686,018,427,387,903$)
2. **Frame Types**:
   - `0x00` `PADDING`, `0x01` `PING`, `0x02-0x03` `ACK` (with/without ECN), `0x04` `RESET_STREAM`, `0x05` `STOP_SENDING`, `0x06` `CRYPTO`, `0x07` `NEW_TOKEN`, `0x08-0x0F` `STREAM`, `0x10` `MAX_DATA`, `0x11` `MAX_STREAM_DATA`, `0x12-0x13` `MAX_STREAMS`, `0x14` `DATA_BLOCKED`, `0x15` `STREAM_DATA_BLOCKED`, `0x16-0x17` `STREAMS_BLOCKED`, `0x18` `NEW_CONNECTION_ID`, `0x19` `RETIRE_CONNECTION_ID`, `0x1A` `PATH_CHALLENGE`, `0x1B` `PATH_RESPONSE`, `0x1C-0x1D` `CONNECTION_CLOSE`, `0x1E` `HANDSHAKE_DONE`.
3. **Anti-Amplification Defense**:
   - Prior to client address validation (via successful handshake or `PATH_RESPONSE`), the server **must not transmit more than 3 times the cumulative bytes received** from the unvalidated client address:
     $$\text{BytesSent} \le 3 \times \text{BytesReceived}$$
   - Prevents QUIC servers from being weaponized in UDP reflection DDoS attacks.

### 2.2 RFC 9001: QUIC TLS 1.3 Cryptography & Header Protection

```
+-----------------------------------------------------------------------------------------------+
| TLS 1.3 in TCP vs QUIC                                                                        |
+-----------------------------------------------------------------------------------------------+
| TCP + TLS 1.3:                                                                                |
| [IP Header] -> [TCP Header] -> [TLS Record Header (5B)] -> [Encrypted TLS Record Payload]    |
| (TLS owns framing, record chunking, sequence numbers, alert records)                         |
+-----------------------------------------------------------------------------------------------+
| QUIC + TLS 1.3 (RFC 9001):                                                                   |
| [IP Header] -> [UDP Header] -> [QUIC Packet Header (HP Masked)] -> [AEAD Payload: CRYPTO/...] |
| (NO TLS RECORD LAYER. TLS provides handshake state machine; QUIC provides packet framing)     |
+-----------------------------------------------------------------------------------------------+
```

1. **Bypassing the TLS Record Layer**:
   - In QUIC, the standard TLS 1.3 record layer (5-byte record header `0x17 0x03 0x03 [len]`) is **completely eliminated**.
   - Raw TLS handshake messages (`ClientHello`, `ServerHello`, `EncryptedExtensions`, `Certificate`, `CertificateVerify`, `Finished`) are packetized into QUIC `CRYPTO` frames.
2. **QUIC Transport Parameters Extension (`0x39` / 57)**:
   - Transport configuration (flow control limits, CID limits, idle timeouts, stateless reset tokens) is encoded inside the TLS `quic_transport_parameters` extension during the handshake.
3. **HKDF Key Derivation Pipeline**:
   - **Initial Salt (QUIC v1)**: `0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a`
   - **Initial Secret**: $\text{HKDF-Extract}(\text{salt}_{\text{v1}}, \text{client\_initial\_dcid})$
   - **Client/Server Initial Secret**: $\text{HKDF-Expand-Label}(\text{InitialSecret}, \text{"client in"} / \text{"server in"}, \text{SHA256}, 32)$
   - **AEAD Key / IV / Header Protection Key**: Derived via labels `"quic key"`, `"quic iv"`, `"quic hp"`.
4. **Header Protection (HP) Mechanics**:
   - AEAD encrypts the packet payload (generating ciphertext + 16-byte authentication tag).
   - A 16-byte sample is taken from the ciphertext at offset $\text{pn\_offset} + 4$.
   - **AES-128 / AES-256**: $\text{Mask} = \text{AES-ECB}(\text{HP\_Key}, \text{Sample})[0 \dots 5]$
   - **ChaCha20**: $\text{Mask} = \text{ChaCha20}(\text{HP\_Key}, \text{Counter} = \text{Sample}[0..4], \text{Nonce} = \text{Sample}[4..16])[0 \dots 5]$
   - **Masking Byte 0**:
     - Long Header: $\text{Byte}_0 \oplus= (\text{Mask}[0] \mathbin{\&} 0\text{x0F})$
     - Short Header: $\text{Byte}_0 \oplus= (\text{Mask}[0] \mathbin{\&} 0\text{x1F})$
   - **Masking Packet Number**: $\text{PN}[0 \dots L-1] \oplus= \text{Mask}[1 \dots L]$
5. **In-Band Key Update**:
   - After handshake completion, 1-RTT packets contain a 1-bit `Key Phase` toggle in the short header.
   - When either peer initiates a key update, next-generation application secrets are computed using HKDF label `"quic ku"`.

### 2.3 `rustls::quic` Pure-Rust Memory Safety (`#![forbid(unsafe_code)]`)

The `rustls` crate (version 0.23 with features `["std", "ring", "quic"]`) provides native support for RFC 9001 without C-FFI OpenSSL dependencies:

```rust
use rustls::quic::{Connection, ServerConnection, KeyChange, HeaderProtectionKey, PacketKey};

// 1. Instantiate Server QUIC TLS state machine
let mut quic_tls = ServerConnection::new(
    server_config,
    rustls::quic::Version::V1,
    quic_transport_params_bytes,
)?;

// 2. Feed raw CRYPTO frame payload into rustls (NO record layer)
quic_tls.read_hs(&crypto_frame_bytes)?;

// 3. Extract outbound CRYPTO handshake bytes for packet builder
let mut out_crypto = Vec::new();
quic_tls.write_hs(&mut out_crypto);

// 4. Poll key availability events
while let Some(event) = quic_tls.next_event() {
    match event {
        KeyChange::Handshake { keys } => {
            // Install Handshake AEAD and Header Protection keys
            rx_handshake_key = keys.rx;
            tx_handshake_key = keys.tx;
        }
        KeyChange::OneRtt { keys, next } => {
            // Install 1-RTT Application Data keys and Key Update material
            rx_app_key = keys.rx;
            tx_app_key = keys.tx;
        }
    }
}
```

**Memory Safety Guarantees**:
- Pure `#![forbid(unsafe_code)]`: Eliminates buffer overruns, pointer arithmetic vulnerabilities, double-frees, and OpenSSL memory corruption bugs.
- Deterministic panic-free parsing: Handshake parsing failures are returned as explicit `Result<_, rustls::Error>`.

---

## 3. Architectural Impact on Alcyon

### 3.1 UDP Datagram Polling in `Poller` and `FdTab`

In TCP, `Poller` and `FdTab` manage 1:1 file descriptors (`FdState::Conn` / `FdState::Listener`). QUIC introduces 1:N session demultiplexing over a single UDP listener descriptor:

```
+-----------------------------------------------------------------------------------------------+
| Poller (Level-Triggered epoll)                                                                |
|                                                                                               |
|   epoll_wait() -> Event { fd: 7, readable: true }                                             |
|                                                                                               |
| FdTab[7] -> FdState::UdpListener { listener_id: 2 }                                           |
|                                                                                               |
| Batch Ingress Loop: recvmmsg() (up to 64 datagrams per syscall)                               |
|                                                                                               |
| +-------------------------------------------------------------------------------------------+ |
| | Datagram 0: DCID = 0x8a4f... -> EbMbTree Lookup -> Session 42 (Local Thread) -> Ingress Q | |
| | Datagram 1: DCID = 0x1b2c... -> EbMbTree Lookup -> Thread 3 -> Inter-Thread Ring Buffer  | |
| | Datagram 2: DCID = 0xff00... -> ODCID Derived   -> New Connection Handshake Tasklet       | |
| +-------------------------------------------------------------------------------------------+ |
+-----------------------------------------------------------------------------------------------+
```

1. **`FdState::UdpListener` in `FdTab`**:
   ```rust
   pub enum FdState {
       Closed,
       Listener { listener: u32 },
       UdpListener { listener: u32 },
       CliListener,
       Conn { task: TaskRef, conn: u32 },
   }
   ```
2. **Batch I/O with `recvmmsg` & `sendmmsg`**:
   - `recvmmsg` receives up to 64 datagrams in a single kernel transition using pre-allocated `mmsghdr` buffers.
   - `sendmmsg` and `UDP_SEGMENT` (GSO) coalesce up to 64 KB of datagrams per egress syscall.
3. **Virtualized `CO_FL_FDLESS` Sessions**:
   - QUIC sessions are assigned index-based `SessionRef` and `TaskRef` references without holding an OS `RawFd`.
   - Scheduler readiness is triggered directly by datagram ingress queues and timer wheels.

### 3.2 256-Shard `ebtree` CID Routing & Stateless ODCID Derivation

```
+-----------------------------------------------------------------------------------------------+
| Sharded EbMbTree Connection ID Dispatcher                                                     |
+-----------------------------------------------------------------------------------------------+
| Array of 256 Shards: [ Shard 0 | Shard 1 | ... | Shard 255 ]                                 |
| Each Shard: EbMbTree (Match-Bytes Tree) mapping &[u8] (DCID) -> QuicConnRef (u32)             |
+-----------------------------------------------------------------------------------------------+
| Lookup Cost: O(k) where k = 8..20 bytes (CID length). 0 Heap Allocation.                     |
| Parallelism: Zero cross-shard contention across worker threads.                               |
+-----------------------------------------------------------------------------------------------+
```

1. **Thread-Safe Sharded CID Registry**:
   - Sharded into 256 `EbMbTree` tables indexed by `dcid[0]`.
   - Insertion, lookup, and deletion operate in $O(k)$ bitwise steps where $k \le 20$ bytes.
2. **Stateless ODCID Derivation Engine**:
   - Avoids global tree insertion for initial client handshakes:
     ```rust
     pub fn derive_server_cid(odcid: &[u8], client_addr: &SocketAddr, boot_seed: u64) -> [u8; 8] {
         let mut hasher = ahash::AHasher::default();
         hasher.write(odcid);
         hasher.write_u64(boot_seed);
         match client_addr {
             SocketAddr::V4(v4) => {
                 hasher.write(&v4.ip().octets());
                 hasher.write_u16(v4.port());
             }
             SocketAddr::V6(v6) => {
                 hasher.write(&v6.ip().octets());
                 hasher.write_u16(v6.port());
             }
         }
         hasher.finish().to_be_bytes()
     }
     ```
3. **Seamless Connection Migration**:
   - When a mobile client switches networks (e.g., Wi-Fi to 5G), the source IP and port change.
   - Because Alcyon routes datagrams strictly via DCID in the `EbMbTree` rather than `(IP, Port)`, the datagram is instantly dispatched to the existing session without connection teardown.
   - The session updates its peer address upon validating the migration via `PATH_CHALLENGE` / `PATH_RESPONSE`.

### 3.3 Zero-Allocation Memory Layout for Datagrams & Streams

In alignment with **NASA JPL Rule 3** and `design/006-data-layout.md`, the QUIC data path executes **zero heap allocations**:

```
+-----------------------------------------------------------------------------------------------+
| ZERO-ALLOCATION PRE-ALLOCATED ARENAS (Boot-Time Sized)                                        |
+-----------------------------------------------------------------------------------------------+
| 1. DatagramArena: Fixed 2048-byte buffer slots for recvmmsg/sendmmsg batching                 |
| 2. QuicConnArena: 256-byte packed QuicConn structs (cacheline-aligned)                        |
| 3. QuicStreamArena: 128-byte QuicStream structs indexed by u32 arena indices                  |
| 4. ReassemblyArena: Out-of-order stream frame nodes managed by Eb64Tree (keyed by byte offset)|
| 5. HtxBufferPool: Direct zero-copy HTTP/3 header & data transcoding into native HTX blocks    |
+-----------------------------------------------------------------------------------------------+
```

1. **`QuicConn` Packed Layout (Target: 256 Bytes / 4 Cache Lines)**:
   ```rust
   #[repr(C, align(64))]
   pub struct QuicConn {
       // --- Cache Line 0: Identifiers & Routing (64 B) ---
       pub scid: [u8; 20],              // 20 B: Source Connection ID
       pub scid_len: u8,                // 1 B
       pub dcid: [u8; 20],              // 20 B: Destination Connection ID
       pub dcid_len: u8,                // 1 B
       pub peer_addr: SocketAddr,       // 28 B: Peer socket address
       pub state: QuicConnState,        // 1 B: State enum
       pub flags: u32,                  // 4 B: Flags (validated, closing, etc.)
       
       // --- Cache Line 1: Scheduler & Flow Control (64 B) ---
       pub task_ref: TaskRef,           // 4 B: Owning task
       pub session_ref: SessionRef,     // 4 B: Owning session
       pub max_data_local: u64,         // 8 B: Connection RX flow control
       pub max_data_remote: u64,        // 8 B: Connection TX flow control
       pub data_sent: u64,              // 8 B: Total bytes sent
       pub data_recvd: u64,             // 8 B: Total bytes received
       pub next_stream_id_bidi: u64,    // 8 B: Stream ID allocator
       pub next_stream_id_uni: u64,     // 8 B: Stream ID allocator
       pub active_streams: u32,         // 4 B: Stream count
       pub _pad1: [u8; 8],              // 8 B
       
       // --- Cache Line 2: Loss Detection & RTT (64 B) ---
       pub largest_acked_pn: u64,       // 8 B
       pub next_pn: u64,                // 8 B
       pub smoothed_rtt_us: u32,        // 4 B: Microseconds
       pub rttvar_us: u32,              // 4 B
       pub min_rtt_us: u32,             // 4 B
       pub cwnd_bytes: u64,             // 8 B: Congestion window
       pub ssthresh_bytes: u64,         // 8 B: Slow start threshold
       pub bytes_in_flight: u64,        // 8 B: Unacknowledged bytes
       pub loss_time: Tick,             // 4 B: Timer tick
       pub idle_timeout: Tick,          // 4 B: Idle timeout tick
       pub _pad2: [u8; 12],             // 12 B
       
       // --- Cache Line 3: Crypto Context & Keys (64 B) ---
       pub enc_level: EncryptionLevel,  // 1 B
       pub key_phase: bool,             // 1 B
       pub tls_slot: u32,               // 4 B: Index into TlsArena
       pub _reserved: [u8; 58],         // 58 B padding to exact 256 B
   }
   ```
2. **Stream Frame Out-of-Order Reassembly via `Eb64Tree`**:
   - Out-of-order chunks are stored in an arena-backed `Eb64Tree` keyed by byte offset.
   - When missing ranges arrive, bytes are pumped directly into the `HtxBuffer` without intermediate string cloning.

### 3.4 Unified TLS 1.3 Configuration Sharing (`bind ... ssl` & `bind ... quic`)

```
+-----------------------------------------------------------------------------------------------+
| UNIFIED TLS 1.3 CONFIGURATION (Shared Arc<rustls::ServerConfig>)                              |
+-----------------------------------------------------------------------------------------------+
|                                                                                               |
|                          ┌──────────────────────────────────┐                                 |
|                          │    Arc<rustls::ServerConfig>     │                                 |
|                          └────────────────┬─────────────────┘                                 |
|                                           │                                                   |
|                ┌──────────────────────────┴──────────────────────────┐                        |
|                ▼                                                     ▼                        |
|   TCP HTTPS Listener (`bind :443 ssl`)                 QUIC HTTP/3 Listener (`bind :443 quic`)|
|   - ALPN: ["h2", "http/1.1"]                           - ALPN: ["h3"]                         |
|   - TLS 1.3 Record Layer                               - QUIC TLS 1.3 (RFC 9001, Record-less) |
|   - ResolvesServerCert (EbMbTree SNI)                  - ResolvesServerCert (EbMbTree SNI)    |
|   - Zero-Copy TlsArena                                 - Zero-Copy DatagramArena              |
+-----------------------------------------------------------------------------------------------+
```

1. **Shared Multi-Certificate SNI Dispatch**:
   - Both TCP and QUIC listeners share the exact same `ResolvesServerCert` provider backed by `ebtree::EbMbTree` (from Milestone 3).
   - Wildcard (`*.example.com`) and exact (`api.example.com`) certificates resolve in $O(k)$ time across both protocols.
2. **Hot-Reload Certificate Parity**:
   - Updating a certificate via the runtime CLI or configuration reload updates the underlying `Arc<ServerConfig>` atomically, updating both TCP HTTPS and QUIC HTTP/3 listeners simultaneously.

### 3.5 Anti-DDoS Scheduler Integration (`Class::Heavy`)

1. **CPU Exhaustion Defense**:
   - Initial QUIC packet decryption, ECDH key exchange, and certificate signature verification are computationally asymmetric.
   - Incoming Initial packets that require cryptographic handshakes are tagged with `state::HEAVY = 1 << 5` and scheduled under `Class::Heavy` in `alcyon-sched`.
   - The scheduler restricts execution to **at most 1 heavy task per scheduler pass**, guaranteeing established HTTP/1.1, HTTP/2, and HTTP/3 transactions never experience latency spikes during SYN/Initial flooding.
2. **Stateless Retry Defense (`Retry` Packets)**:
   - Under server overload, Alcyon emits stateless `Retry` packets containing an encrypted `Token` with an AEAD Retry Integrity Tag.
   - The server drops the connection state entirely; legitimate clients replay their `Initial` packet with the validated token, confirming client IP ownership before allocating server memory.

---

## 4. Alcyon QUIC & HTTP/3 Implementation Roadmap (Milestone 7)

```
+-----------------------------------------------------------------------------------------------+
| IMPLEMENTATION ROADMAP                                                                        |
+-----------------------------------------------------------------------------------------------+
| Phase 1: UDP Poller & Batch I/O (`recvmmsg` / `sendmmsg`, `FdState::UdpListener`, GSO)         |
| Phase 2: Sharded `EbMbTree` CID Routing & Stateless ODCID Engine                              |
| Phase 3: `rustls::quic` Integration & RFC 9001 Packet/Header Protection                       |
| Phase 4: QUIC Transport State Machine (`QuicConn`, Packet Coalescing, Loss Detection, CUBIC)  |
| Phase 5: Stream Multiplexer (`mux_quic`, `MAX_STREAM_DATA`, Eb64Tree Reassembly)              |
| Phase 6: HTTP/3 & QPACK Engine (`mux_h3`, Direct HTX Transcoding)                             |
| Phase 7: Verification Suite (VTest differential tests against HAProxy 3.5 native QUIC)        |
+-----------------------------------------------------------------------------------------------+
```

### 4.1 Deliverables & Parity Validation Criteria

| Component | Target Metric / Validation Target |
| :--- | :--- |
| **`recvmmsg` Batching** | Drain $\ge 64$ datagrams per syscall under load; zero lost wakeups. |
| **CID Lookup Speed** | $O(k)$ lookup $\le 25\text{ ns}$ via 256-shard `EbMbTree`. |
| **Memory Footprint** | Exact 256-byte `QuicConn` structs; zero heap allocations on hot data path. |
| **Safety Invariant** | 100% pure Rust `#![forbid(unsafe_code)]` with zero `unsafe` blocks. |
| **RFC Conformance** | 100% conformance against RFC 9000, RFC 9001, RFC 9114 test suites. |
| **Differential Parity** | 100% interoperability against `curl --http3` and HAProxy 3.5-dev QUIC endpoints. |

---

*End of Architecture Specification.*
