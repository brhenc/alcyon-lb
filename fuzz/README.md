# Ibex HTTP/1 Parser Differential Fuzzing Harness

This directory contains the differential fuzzing harness for Ibex's HTTP/1 parser (`crates/ibex-proto`).
It performs automated differential testing against a live reference oracle—**HAProxy 3.5-dev8** (`/home/bhenc/reference/haproxy/haproxy`)—as well as self-differential testing across streaming modes within Ibex itself.

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

---

# libFuzzer targets (`fuzz/libfuzzer/`) — crash-finding, no oracle

The harness above compares Ibex with HAProxy. The targets below only look for
**panics, hangs and out-of-memory** on arbitrary input (task R1, `docs/milestones.md`).
They are a separate crate, `fuzz/libfuzzer/` (its own `[workspace]`, not a member of the
Ibex workspace); libFuzzer links only into those binaries, never into Ibex. The normal
`cargo build --workspace` and `tools/checkin.sh` do not build it and need no nightly.

| target | what it feeds |
|---|---|
| `h1_request` | HTTP/1 request head: `find_eoh`, `request_framing`, `H1Parser` (whole and split) |
| `h1_response` | HTTP/1 response head: `H1Parser` in response mode |
| `h2_frames` | HTTP/2 frame decoder, frames then fed to a server `H2Multiplexer` |
| `hpack` | HPACK decoder (two blocks on one decoder) and the Huffman decoder |
| `proxy_protocol` | PROXY protocol v1 and v2 header + TLV accessors |
| `config` | `ibex_config::parse_str` |
| `logfmt` | log-format compiler (`LogFormat::compile`, `compile_unique_id`) |
| `sample_expr` | `ibex_sample::Expr::parse` |
| `regex` | `ibex_regex::UserRegex::new` |
| `check_reply` | health-check replies: Redis, SMTP, PgSQL, SSL hello, http-check, tcp-check expect (`ibex_rt::check_reply`) |
| `check_ldap_mysql` | LDAP and MySQL check replies (apart: known panics, review #7) |
| `cookie` | `cookie::client_side` and `process_response` over hostile Cookie / Set-Cookie values |
| `syslog` | log-forward stream framing (`logfwd::read_frame`), RFC 5424/3164 parse, header rebuild |
| `cli` | stats socket command lines at user/operator level (`CliApplet::process_commands`) |
| `h2_mux` | server `MuxH2` fed a client byte stream; asserts it holds at most 2 MiB |

## One-time setup (needs internet, once)

```
rustup toolchain install nightly
cargo install cargo-fuzz
```

On this machine (2026-10-05) rustup's `cargo`/`rustc` are in `~/.local/rustup-bin`, not
on `PATH`; `cargo-fuzz` itself is in `~/.cargo/bin`. Do not put rustup's shims in
`~/.cargo/bin`: the gate's coverage step puts that directory first on `PATH`, and must get
the system `cargo` (`/usr/bin`, matching `llvm-profdata`). Call it as
`~/.local/rustup-bin/cargo +nightly fuzz …`, or `export PATH=$HOME/.local/rustup-bin:$PATH`
in the shell you fuzz from only. Every command below runs **from the repository root** with
`--fuzz-dir fuzz/libfuzzer`; run from inside `fuzz/libfuzzer`, cargo-fuzz looks for
`fuzz/libfuzzer/fuzz/Cargo.toml` and fails.

(`cargo-fuzz` is a Cargo plugin; libFuzzer itself is fetched as the `libfuzzer-sys`
crate on the first build.) Use a target directory on a big disk, not /tmp:

```
export CARGO_TARGET_DIR=$HOME/ibex-targets/fuzz CARGO_INCREMENTAL=0
```

## Run one target for a minute

```
cargo +nightly fuzz run --fuzz-dir fuzz/libfuzzer hpack -- -max_total_time=60
```

It prints a line per new coverage find (`#12345 NEW cov: ... exec/s: ...`) and stops
after 60 s with "Done". No `crash-` line means nothing was found. Drop `-- -max_total_time=60`
to run until you press Ctrl-C. List the targets: `cargo +nightly fuzz list --fuzz-dir fuzz/libfuzzer`.

## Run all targets for N hours

```
N=2    # hours in total
F="--fuzz-dir fuzz/libfuzzer"
for t in $(cargo +nightly fuzz list $F); do
  cargo +nightly fuzz run $F $t -- -max_total_time=$(( N*3600/9 )) 2>&1 | tee /tmp/fuzz-$t.log
done
```

Each target gets N/9 hours. Add `-- -max_total_time=S -rss_limit_mb=2048 -timeout=10` to
bound memory and treat inputs slower than 10 s as hangs. To use all cores on one target:
`cargo +nightly fuzz run --fuzz-dir fuzz/libfuzzer <t> --jobs 8 -- -max_total_time=S`.

## Where results land

- New interesting inputs: `fuzz/libfuzzer/corpus/<target>/` (seeds are committed; commit
  only ones that add coverage you care about, or run `cargo +nightly fuzz cmin --fuzz-dir fuzz/libfuzzer <t>` first).
- First run, 2026-10-05: all nine targets 60 s each, no crash, hang or OOM. Rough
  speed: proxy_protocol 340k exec/s, h2_frames 52k, sample_expr 26k, h1_response 24k,
  h1_request 21k, hpack 18k, logfmt 13k, config 6k, regex 1k.
- A crash, hang or OOM: `fuzz/libfuzzer/artifacts/<target>/crash-<hash>` (or `timeout-`,
  `oom-`). The run prints the panic message and the path.

## Turn a crash into a test

1. Replay it: `cargo +nightly fuzz run --fuzz-dir fuzz/libfuzzer <target> fuzz/libfuzzer/artifacts/<target>/crash-<hash>`
   (or `fuzz fmt` with the same arguments to print it).
2. Copy the file under `fuzz/libfuzzer/artifacts/` into git (it is a small binary).
3. Write a regular `#[test]` in the crate that owns the code (see the table), calling
   the same function with the bytes (`include_bytes!` of the artifact, or an escaped
   literal), and run it: **it must fail first** (AGENTS.md section 1). Then fix the code and
   watch it pass. Ask an agent to do this; give it the artifact path and the panic text.
