# Alcyon PROXY Protocol v1 & v2 Architecture & Research Blueprint

## Executive Summary

The **PROXY Protocol** (Versions 1 & 2), designed by Willy Tarreau and HAProxy Technologies, is the industry standard mechanism for safely relaying connection metadata—including original client IP addresses, destination addresses, layer-4 ports, ALPN protocol identifiers, TLS SNI authorities, SSL client certificate properties, and network namespaces—across intermediate proxies, load balancers, and Layer-4 / NAT layers.

This document records the architectural research and Safe Rust implementation of PROXY protocol version 1 (human-readable text) and version 2 (binary framing) in **Alcyon** under `crates/alcyon-proto/src/proxy_protocol.rs`.

---

## 1. HAProxy 3.5 Implementation Audit

We performed an in-depth audit of HAProxy 3.5's production PROXY protocol engine in `/home/bhenc/reference/haproxy`:
- `doc/proxy-protocol.txt` (Complete PROXY protocol specification)
- `include/haproxy/connection.h` & `include/haproxy/connection-t.h` (Data types, TLV codes, bitmask constants)
- `src/connection.c` (`conn_recv_proxy`, `make_proxy_line_v1`, `make_proxy_line_v2`, `conn_send_proxy`)
- `src/sock.c` (Socket creation and namespace propagation)
- `src/hash.c` (`hash_crc32c` Castagnoli CRC32-C calculation)

### 1.1 PROXY Protocol Version 1 (Human-Readable ASCII)

Version 1 is an ASCII line-delimited protocol designed for easy debugging and human readability:
```text
PROXY <TCP4|TCP6|UNKNOWN> <src_addr> <dst_addr> <src_port> <dst_port>\r\n
```

Key invariants from HAProxy's `conn_recv_proxy` and `make_proxy_line_v1`:
1. **Length Bounds**: The maximum valid line length is strictly bounded to **107 characters** (excluding the terminating `\r\n`), or 108 bytes including trailing newline:
   - IPv4 worst-case: `PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535\r\n` (56 chars).
   - IPv6 worst-case: `PROXY TCP6 ffff:f...f:ffff ffff:f...f:ffff 65535 65535\r\n` (104 chars).
   - UNKNOWN short form: `PROXY UNKNOWN\r\n` (15 chars).
   - UNKNOWN worst-case: `PROXY UNKNOWN ffff:f...f:ffff ffff:f...f:ffff 65535 65535\r\n` (107 chars).
2. **Whitespace Strictness**: Tokens must be separated by **exactly one space** (`\x20`). Multiple spaces or trailing spaces before `\r\n` are strictly rejected.
3. **No Leading Zeroes**: IPv4 octets and port numbers must not have leading zeroes (e.g. `01.2.3.4` or `080`), eliminating ambiguity with octal encodings.
4. **UNKNOWN Semantics**: When `PROXY UNKNOWN` is received, the rest of the line before `\r\n` is discarded, and the receiver treats the connection as a direct/local connection (`ProxyCommand::Local`).

### 1.2 PROXY Protocol Version 2 (Binary Framing)

Version 2 is a high-performance binary protocol designed for zero-copy parsing, machine efficiency, and extensibility.

#### Binary Header Layout (16 Bytes Fixed Header)
```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|        12-Byte Protocol Signature (PP2_SIGNATURE)             |
|   \x0D \x0A \x0D \x0A \x00 \x0D \x0A \x51 \x55 \x49 \x54 \x0A|
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Ver  |  Cmd  |  Fam  | Trans |          Payload Length       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Address Block                          |
|         (AF_INET: 12 B | AF_INET6: 36 B | AF_UNIX: 216 B)     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   Type-Length-Value (TLVs)                    |
|                            ...                                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

1. **Protocol Signature (12 Bytes)**:
   `\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A` (`\r\n\r\n\0\r\nQUIT\n`). The null byte at index 4 ensures C string functions abort, and higher-level protocols (HTTP, TLS, SSH, FTP, SMTP) fail fast if accidentally presented with this signature.
2. **Version / Command Byte (`ver_cmd`)**:
   - Version (high 4 bits): Must be `0x2` (`0x20`).
   - Command (low 4 bits): `0x0` = `LOCAL` (e.g. health check), `0x1` = `PROXY` (relayed client connection).
3. **Family / Transport Byte (`fam_trans`)**:
   - Family (high 4 bits): `0x0` = `AF_UNSPEC`, `0x1` = `AF_INET` (IPv4), `0x2` = `AF_INET6` (IPv6), `0x3` = `AF_UNIX`.
   - Transport (low 4 bits): `0x0` = `UNSPEC`, `0x1` = `STREAM` (TCP / UNIX Stream), `0x2` = `DGRAM` (UDP / UNIX Dgram).
4. **Length Field (16-bit Big-Endian)**:
   Number of following bytes in the header (address block + TLVs). Total header size is `16 + len`.

### 1.3 Type-Length-Value (TLV) Architecture & Sub-TLVs

Following the address block, PROXY v2 supports arbitrary extension TLVs:
```c
struct pp2_tlv {
    uint8_t type;
    uint8_t length_hi;
    uint8_t length_lo;
    uint8_t value[0];
};
```

#### Registered TLV Type Registry

| Type Code | Constant | Description | Value Format |
| :--- | :--- | :--- | :--- |
| `0x01` | `PP2_TYPE_ALPN` | Negotiated Application Protocol (RFC 7301) | Opaque bytes (e.g., `h2`, `http/1.1`) |
| `0x02` | `PP2_TYPE_AUTHORITY` | SNI / Server Name Indication (RFC 3546) | UTF-8 string (hostname) |
| `0x03` | `PP2_TYPE_CRC32C` | Castagnoli CRC32-C Header Checksum | 4-byte big-endian integer |
| `0x04` | `PP2_TYPE_NOOP` | Padding / Byte Alignment | Arbitrary zero/ignored bytes |
| `0x05` | `PP2_TYPE_UNIQUE_ID` | Opaque Unique Connection ID | Up to 128 bytes |
| `0x20` | `PP2_TYPE_SSL` | SSL/TLS Connection Container | `struct pp2_tlv_ssl` + sub-TLVs |
| `0x21` | `PP2_SUBTYPE_SSL_VERSION` | SSL TLS Version String | ASCII (e.g. `TLSv1.3`, `TLSv1.2`) |
| `0x22` | `PP2_SUBTYPE_SSL_CN` | SSL Client Certificate Common Name | UTF-8 string (from DN OID 2.5.4.3) |
| `0x23` | `PP2_SUBTYPE_SSL_CIPHER` | Negotiated Cipher Suite Name | ASCII (e.g. `TLS_AES_256_GCM_SHA384`) |
| `0x24` | `PP2_SUBTYPE_SSL_SIG_ALG` | Certificate Signature Algorithm | ASCII (e.g. `RSA-PSS-SHA256`) |
| `0x25` | `PP2_SUBTYPE_SSL_KEY_ALG` | Certificate Key Algorithm | ASCII (e.g. `RSA4096`, `ECDSA`) |
| `0x26` | `PP2_SUBTYPE_SSL_GROUP` | Key Exchange Group | ASCII (e.g. `secp256r1`, `X25519`) |
| `0x27` | `PP2_SUBTYPE_SSL_SIG_SCHEME` | Key Exchange Signature Scheme | ASCII (e.g. `rsa_pss_rsae_sha256`) |
| `0x28` | `PP2_SUBTYPE_SSL_CLIENT_CERT` | Raw X.509 Client Certificate | ASN.1 DER binary payload |
| `0x30` | `PP2_TYPE_NETNS` | Network Namespace | ASCII string |
| `0xE0..=0xEF`| `PP2_TYPE_MIN_CUSTOM` | Application-Specific Custom TLVs | Custom payloads |
| `0xF0..=0xF7`| `PP2_TYPE_MIN_EXPERIMENT` | Experimental TLVs | Experimental payloads |
| `0xF8..=0xFF`| `PP2_TYPE_MIN_FUTURE` | Future Multi-Byte Types | Reserved |

#### SSL TLV Container (`PP2_TYPE_SSL`)
```text
+-------------------+--------------------+----------------------------+
| client (1 byte)   | verify (4 bytes BE)| sub-TLVs (0 or more)       |
+-------------------+--------------------+----------------------------+
```
- `client` Bitflags:
  - `0x01` (`PP2_CLIENT_SSL`): Client connected over SSL/TLS.
  - `0x02` (`PP2_CLIENT_CERT_CONN`): Client presented a certificate on this connection.
  - `0x04` (`PP2_CLIENT_CERT_SESS`): Client presented a certificate in this TLS session.
- `verify`: 32-bit big-endian integer; `0` indicates successful verification, non-zero indicates error.

#### Castagnoli CRC32-C (`PP2_TYPE_CRC32C`)
Compliant with RFC 4960 Appendix B, polynomial `0x1EDC6F41` (reflected `0x82F63B78`):
1. The 4-byte CRC32C field inside `PP2_TYPE_CRC32C` is initialized to all zeroes `[0, 0, 0, 0]`.
2. CRC32-C is calculated across the entire header (`16 + len` bytes).
3. The resulting checksum is stored in big-endian order into the TLV value.
4. On decode, the receiver validates the checksum without needing memory allocations or modifying immutable input buffers.

---

## 2. Alcyon Safe Rust Architecture

Implemented in `crates/alcyon-proto/src/proxy_protocol.rs` under strict `#![forbid(unsafe_code)]`.

```text
                                 +-----------------------+
                                 |  Incoming Byte Stream |
                                 +-----------+-----------+
                                             |
                                 ProxyHeader::parse(buf)
                                             |
                     +-----------------------+-----------------------+
                     |                                               |
             [ Starts with "PROXY " ]                    [ Starts with PP2_SIGNATURE ]
                     |                                               |
               parse_v1(...)                                   parse_v2(...)
                     |                                               |
       +-------------+-------------+                  +--------------+--------------+
       |             |             |                  |              |              |
      TCP4          TCP6        UNKNOWN             AF_INET       AF_INET6       AF_UNIX / UNSPEC
       |             |             |                  |              |              |
  [ Ipv4Addr ]  [ Ipv6Addr ]   [ Unspec ]        [ Ipv4Addr ]   [ Ipv6Addr ]   [ [u8; 108] ]
                                                      |              |              |
                                                      +--------------+--------------+
                                                                     |
                                                             TlvIter / SslTlv
                                                                     |
                                                           [ Zero-Copy Slices ]
```

### 2.1 Core API Signatures

```rust
// Zero-allocation zero-copy parser
impl<'a> ProxyHeader<'a> {
    pub fn parse(buf: &'a [u8]) -> Result<Option<(Self, usize)>, ProxyParseError>;
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, ProxyEncodeError>;
    pub fn tlvs(&self) -> TlvIter<'a>;
    pub fn find_tlv(&self, tlv_type: u8) -> Option<Result<Tlv<'a>, ProxyParseError>>;
    pub fn alpn(&self) -> Option<Result<&'a [u8], ProxyParseError>>;
    pub fn authority(&self) -> Option<Result<&'a str, ProxyParseError>>;
    pub fn crc32c(&self) -> Option<Result<u32, ProxyParseError>>;
    pub fn unique_id(&self) -> Option<Result<&'a [u8], ProxyParseError>>;
    pub fn netns(&self) -> Option<Result<&'a str, ProxyParseError>>;
    pub fn ssl(&self) -> Option<Result<SslTlv<'a>, ProxyParseError>>;
}
```

### 2.2 Zero-Allocation TLV Builder

For outbound client connections (`send-proxy` and `send-proxy-v2`):
```rust
pub struct TlvBuilder<'b> { ... }

impl<'b> TlvBuilder<'b> {
    pub fn new(buf: &'b mut [u8]) -> Self;
    pub fn append_alpn(&mut self, alpn: &[u8]) -> Result<(), ProxyEncodeError>;
    pub fn append_authority(&mut self, authority: &str) -> Result<(), ProxyEncodeError>;
    pub fn append_unique_id(&mut self, id: &[u8]) -> Result<(), ProxyEncodeError>;
    pub fn append_netns(&mut self, netns: &str) -> Result<(), ProxyEncodeError>;
    pub fn append_noop(&mut self, len: usize) -> Result<(), ProxyEncodeError>;
    pub fn append_ssl(&mut self, client: u8, verify: u32, sub_tlvs: &[u8]) -> Result<(), ProxyEncodeError>;
    pub fn append_crc32c_placeholder(&mut self) -> Result<(), ProxyEncodeError>;
}
```

---

## 3. Verification & Test Suite

The test suite covers:
1. **HAProxy Differential Vector Parity**: Validated against exact test vectors from `doc/proxy-protocol.txt` and `src/connection.c`.
2. **Partial Streaming & Fragmentation Resilience**: Validated that any incomplete prefix returns `Ok(None)` and properly parses once all bytes arrive.
3. **Error Injection & Security Bounds**: Validated rejection of line overruns (> 107 bytes), leading zeroes in IP/ports, malformed TLVs, invalid versions/commands, and corrupted CRC32-C checksums.
4. **Property-Based Fuzzing (`proptest`)**:
   - `prop_v1_ipv4_roundtrip`: Arbitrary IPv4 / port roundtrip.
   - `prop_v1_ipv6_roundtrip`: Arbitrary IPv6 / port roundtrip.
   - `prop_v2_ipv4_roundtrip`: Arbitrary IPv4 + ALPN + Authority TLVs roundtrip.
   - `prop_v2_crc32c_fuzz`: Checksum integrity across random unique IDs.
   - `prop_fuzz_parser_never_panics`: Fuzz parser over arbitrary random byte sequences (panics forbidden).
   - `prop_streaming_chunk_resilience`: Arbitrary split-point fragmentation streaming tests.
5. **Clippy Cleanliness**: 100% clean under `cargo clippy -p alcyon-proto --all-targets -- -D warnings`.
