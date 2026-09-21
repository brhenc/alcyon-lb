# Ibex HTTP/1 Parser Differential Fuzzing Harness

This directory contains the differential fuzzing harness for Ibex's HTTP/1 parser (`crates/ibex-proto`).
It performs automated differential testing against a live reference oracle—**HAProxy 3.5-dev7** (`/home/bhenc/reference/haproxy/haproxy`)—as well as self-differential testing across streaming modes within Ibex itself.

---

## Why This Harness Exists

In modern reverse proxy and application gateway architectures, HTTP/1 framing discrepancies between two implementations processing the same byte stream are, by construction, **HTTP request smuggling vulnerabilities** (CL.TE, TE.CL, TE.TE, desync attacks).

A memory-safe proxy in Rust that is merely unexploitable to memory corruption is a necessary baseline, but safety alone does not prevent logic and framing desynchronization CVEs. This harness differential tests the wire parser against the industry-standard reference (HAProxy 3.5) to detect every framing, normalization, and acceptance discrepancy.

---

## Architecture & Generator Strategy

### Safe Stable Rust (`#![forbid(unsafe_code)]`)
Traditional fuzzing tools like `cargo-fuzz`/`libFuzzer` require nightly Rust and introduce unsafe memory hooks. To strictly uphold Ibex's workspace contract (`#![forbid(unsafe_code)]` on safe stable Rust), we built a **property-based structured and combinatorial mutation generator**.

### Why Hand-Rolled Structured + Combinatorial Generation?
1. **Targeted CVE Exploration:** Pure random byte streams are rejected immediately at byte 0 by both parsers, yielding minimal semantic coverage. The generator specifically biases toward known HTTP request smuggling vectors:
   - `Content-Length` & `Transfer-Encoding` conflicts (CL.TE, TE.CL, TE.TE)
   - Duplicate, conflicting, comma-separated, signed, and overflowing `Content-Length` headers
   - `Transfer-Encoding` variations (casing, whitespace, trailing `, identity`, unrecognized encodings)
   - Obs-fold continuation lines (RFC 7230 §3.2.4 whitespace continuations)
   - Line terminator variations (standard CRLF, bare LF, bare CR, mixed, doubled delimiters)
   - Chunk size formatting (leading zeros, `+`/`-` signs, hex casing, chunk extensions with quotes)
   - Header malformations (embedded NUL bytes, space/TAB before colons, empty names, missing colons)
   - Pipelined requests with ambiguous body boundaries and smuggling prefixes
   - Buffer limit boundaries (oversized URIs, header count > 100, header names > 255 bytes)
2. **Speed & Determinism:** High throughput (evaluates 300+ requests in <6 seconds against live HAProxy) with 100% deterministic reproducibility via seeded PRNG.
3. **Live Oracle Integration:** Spawns a real HAProxy 3.5 process on dynamic ephemeral ports with a concurrent non-blocking HTTP backend.

---

## Harness Validation & Self-Test

Before running fuzzing cases, the harness executes a mandatory **Self-Test** on 5 baseline valid HTTP/1 requests:
1. `GET / HTTP/1.1` (Plain GET)
2. `GET /search?q=test HTTP/1.1` (GET with query parameters)
3. `POST /submit HTTP/1.1` with `Content-Length: 5`
4. `POST /chunked HTTP/1.1` with `Transfer-Encoding: chunked`
5. Pipelined back-to-back GET requests

If either Ibex or HAProxy rejects any baseline valid request, the harness fails loudly and aborts immediately, preventing false findings.

---

## Discrepancy Classification

Discrepancies are categorized into 4 distinct classes:

| Category | Description | Security Impact |
| :--- | :--- | :--- |
| **Category 1 (Acceptance)** | One parser accepts input as valid HTTP/1 while the other rejects it (HTTP 400 Bad Request or parse syntax error). | Attack surface divergence; parser differential. |
| **Category 2 (Framing)** | Both parsers accept the input, but disagree on parsed method, URI, header count, or body length. | Request misinterpretation, cache poisoning, routing bypass. |
| **Category 3 (Smuggling Boundary)** | Disagreements on message boundaries (where this request ends and the next begins), unconsumed trailing bytes, or keep-alive connection reuse on ambiguous framing. | **Critical:** Direct HTTP Request Smuggling (CL.TE / TE.CL / pipeline desync). |
| **Self-Differential** | Ibex parser produces different results when receiving the full buffer at once vs incremental single-byte streaming. | Streaming parser state machine desynchronization. |

---

## Running the Harness

### Fast CI Run (Default: < 10 seconds)
```bash
cargo run --manifest-path fuzz/Cargo.toml
```

### Extended Soak Run (2,500+ Iterations)
```bash
cargo run --manifest-path fuzz/Cargo.toml -- --soak
```

### Custom Configuration & Seeding
```bash
cargo run --manifest-path fuzz/Cargo.toml -- \
  --haproxy /home/bhenc/reference/haproxy/haproxy \
  --corpus-dir fuzz/corpus \
  --findings-file fuzz/FINDINGS.md \
  --iters 500 \
  --seed 12345
```

---

## Output Artifacts

- `fuzz/FINDINGS.md`: Comprehensive markdown report documenting every distinct discrepancy with hex dumps, parser behaviors, and root cause analysis.
- `fuzz/corpus/`: Verbatim binary files (`finding_*.bin`) for every discovered discrepancy, suitable for regression testing and offline replay.
