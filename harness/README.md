# Differential Proxy Test Harness (`harness/`)

## Overview

Project Alcyon targets **feature and syntactic parity with modern HAProxy (HAProxy 3.5-dev7)**. This test harness (`difftest.py`) measures observable behavior differentials between the reference oracle (`/home/bhenc/reference/haproxy/haproxy` by default) and candidate implementations (such as Alcyon).

The harness runs independent test scenarios against a proxy binary (or pairs of binaries), instruments the backend and client endpoints, and records structured, comparable metrics.

---

## Key Design Principles

1. **Zero External Dependencies**: Implemented strictly using the Python 3 standard library (`socket`, `subprocess`, `threading`, `time`, `json`, `argparse`, `dataclasses`, `struct`, `uuid`).
2. **Dynamic Port Allocation**: Every proxy listener and backend stub binds dynamically to port 0 (`SO_REUSEADDR`) and discovers its assigned port at runtime. No hardcoded ports are used, ensuring parallel execution without conflicts.
3. **Guaranteed Cleanup**: All proxy subprocesses, sockets, background threads, and temporary configuration files are managed in robust `try / finally` blocks with signal escalation (`SIGTERM` -> `SIGKILL`).
4. **Deterministic & Repeatable**: Test scenarios avoid race conditions by synchronizing on events, payload sizes, or socket states rather than arbitrary sleeps.
5. **Machine-Readable Output**: Full `--json` support emits structured results suitable for CI gating and regression tracking.
6. **Fuzzy vs. Strict Differential Tolerances**:
   - **Strict Semantics**: Byte exactness, sent/received payload lengths, connection shutdown sequence (clean EOF vs reset), half-close propagation, retry exhaustion, and `maxconn` queueing behavior must match identically.
   - **Tolerant Timing (Bucketing)**: Exact millisecond timings vary due to CPU scheduling and kernel jitter. Timeouts are categorized into coarse duration buckets (`<500ms`, `~1000ms`, `~2000ms`, `~3000ms`, `~4000ms`, `~5000ms`).

---

## Scenario Catalog

| Scenario | Stimulus / Configuration | Reference Baseline Behavior (HAProxy 3.5) |
|---|---|---|
| `echo` | Client streams 1 MiB binary payload with NUL bytes through proxy to an echo backend. | Byte-exact round trip (1,048,576 bytes sent and received), clean close, `<500ms`. |
| `client_close` | Client sends 8 KiB, then calls `shutdown(SHUT_WR)` mid-stream. | Proxy flushes pending request bytes to backend, propagates `SHUT_WR` to server (server reads EOF), clean close. |
| `server_close` | Backend sends 8 KiB response to client, then calls `shutdown(SHUT_WR)`. | Proxy flushes response bytes to client, propagates shutdown (client reads full payload + EOF), clean close. |
| `server_refused` | Client connects and sends data to proxy configured with an unopened backend port and `retries 2`. | Proxy attempts backend connect, receives `ECONNREFUSED`, spaces retries by `timeout connect`, closes client socket cleanly (~2000ms). |
| `connect_timeout` | Proxy configured with `server srv1 192.0.2.1:80` (RFC 5737 TEST-NET-1 blackhole) and `timeout connect 1000ms`, `retries 0`. | Proxy initiates non-blocking connect; SYN is blackholed; connect timer fires at ~1000ms; proxy closes client connection cleanly. |
| `client_timeout` | Client connects to proxy and remains silent (`timeout client 1000ms`). | Proxy client read timer fires at ~1000ms; proxy closes client socket cleanly. |
| `server_timeout` | Client sends request; backend accepts connection but never replies (`timeout server 1000ms`). | Proxy server read timer fires at ~1000ms; proxy closes client connection cleanly. |
| `maxconn` | 4 concurrent clients connect to proxy configured with `maxconn 2` against a backend with a 150ms hold delay. | Exactly 2 connections are active at the backend concurrently; excess 2 connections are queued in the listen backlog and processed sequentially as earlier connections complete. All 4 succeed. |
| `concurrent` | 50 simultaneous client threads each sending unique 1 KiB + UUID payloads through proxy. | All 50 complete concurrently, zero cross-talk, 100% byte-exact match. |
| `half_close` | Client sends 2 KiB request, shuts down write side (`SHUT_WR`), and keeps reading. Server verifies EOF, then sends 4 KiB response. | Proxy preserves full-duplex half-close: backend receives request and EOF; client receives full 4 KiB response byte-exact after write shutdown. |
| `http_get` | Client issues HTTP/1.0 GET request in `mode http`. | Proxy parses HTTP request, forwards to backend server, receives HTTP/1.0 200 OK, and forwards full response body. |
| `http_cookie` | Client sends HTTP GET with `Cookie: session=xyz; SERVERID=srv2` to a 2-server backend configured with `cookie SERVERID`. | Proxy inspects cookies and routes traffic to targeted server `srv2`. |
| `http_cliexp` | Client sends request to `/old-api/users` with proxy configured with `http-request replace-path ^/old-api/(.*) /new-api/\1`. | Proxy rewrites request path to `/new-api/users` before forwarding to backend. |
| `http_srvexp` | Backend returns `Location: http://backend.internal:8080/target` with proxy configured with `http-response replace-header Location ^https?://[^/]+(.*) \1`. | Proxy rewrites response header to `location: /target` before forwarding to client. |

---

## 1.0.2 vs 3.5 Behavioral & Syntactic Differences

The test harness was modernized from testing legacy HAProxy 1.0.2 (2001) syntax to modern HAProxy 3.5 (2026). The table below summarizes the key behavioral and syntactic differences:

1. **Config Syntax Evolution**:
   - `dispatch <ip:port>` removed $\to$ replaced by `server srv1 <ip:port>`.
   - `contimeout`, `clitimeout`, `srvtimeout` removed $\to$ replaced by `timeout connect <ms>ms`, `timeout client <ms>ms`, `timeout server <ms>ms`.
   - `cliexp` / `srvexp` regex directives removed $\to$ replaced by structured HTX action rules: `http-request replace-path` / `replace-header` and `http-response replace-header`.
   - Listening sockets require explicit `bind 127.0.0.1:<port>` statements inside `listen` or `frontend` sections.
2. **Timer Precision & Event Loop**:
   - **HAProxy 1.0.2**: Evaluated timers on `select()` ticks driven by statistics intervals (`STATTIME = 2000ms`), causing sub-2s timeouts (like 1000ms) to fire at ~2000ms.
   - **HAProxy 3.5**: Uses `epoll()` with high-precision timer wheels; a 1000ms timeout fires precisely at ~1000ms.
3. **Retry Spacing on `ECONNREFUSED`**:
   - **HAProxy 1.0.2**: Retried failed connection attempts immediately in a tight loop (`retry_spacing = 0ms`, completing in `<500ms`).
   - **HAProxy 3.5**: Implements retry spacing/backoff between connection attempts to the same server, taking ~2000ms for `retries 2` with `timeout connect 1000ms`.
4. **HTTP Parsing Engine & Header Representation**:
   - **HAProxy 1.0.2**: Legacy stream-based regex buffer parsing (`proto_http.c`).
   - **HAProxy 3.5**: Native HTX (HTTP Tree eXpression) engine. Header names are lowercased internally according to modern HTTP specification standards (e.g., `location: /target`).

---

## Usage

### 1. Baseline Mode (Reference Binary Only)

Runs the suite against the HAProxy 3.5 reference binary:

```bash
python3 harness/difftest.py --scenario all
```

Output:
```
--- Differential Proxy Test Harness (Baseline Mode: /home/bhenc/reference/haproxy/haproxy) ---

======================================================================================
SCENARIO           | STATUS | SENT     | RECVD    | EXACT | TIME     | OUTCOME
--------------------------------------------------------------------------------------
echo               | PASS   | 1048576  | 1048576  | YES   | <500ms   | clean_close
client_close       | PASS   | 8192     | 8192     | YES   | <500ms   | clean_close
server_close       | PASS   | 8192     | 8192     | YES   | <500ms   | clean_close
server_refused     | PASS   | 16       | 0        | YES   | ~2000ms  | clean_close
connect_timeout    | PASS   | 5        | 0        | YES   | ~1000ms  | clean_close
client_timeout     | PASS   | 0        | 0        | YES   | ~1000ms  | clean_close
server_timeout     | PASS   | 26       | 0        | YES   | ~1000ms  | clean_close
maxconn            | PASS   | 20       | 40       | YES   | <500ms   | clean_close
concurrent         | PASS   | 53340    | 53340    | YES   | <500ms   | clean_close
half_close         | PASS   | 2048     | 4096     | YES   | <500ms   | clean_close
http_get           | PASS   | 45       | 51       | YES   | <500ms   | clean_close
http_cookie        | PASS   | 71       | 45       | YES   | <500ms   | clean_close
http_cliexp        | PASS   | 48       | 40       | YES   | <500ms   | clean_close
http_srvexp        | PASS   | 39       | 60       | YES   | <500ms   | clean_close
======================================================================================
Baseline summary: 14/14 scenarios passed against reference.
```

### 2. Differential Mode (Reference vs Candidate)

Compares reference (HAProxy 3.5) and candidate (Alcyon) binaries:

```bash
python3 harness/difftest.py \
    --reference /home/bhenc/reference/haproxy/haproxy \
    --candidate target/debug/alcyon \
    --scenario all
```

Output:
```
--- Differential Proxy Test Harness (Comparison: /home/bhenc/reference/haproxy/haproxy vs /home/bhenc/project-ibex/target/debug/alcyon) ---

================================================================================================
SCENARIO           | DIFF RESULT | REF STATUS | CAND STATUS | DISCREPANCIES
------------------------------------------------------------------------------------------------
echo               | PARITY      | PASS       | PASS        | none (observable behavior matches)
client_close       | PARITY      | PASS       | PASS        | none (observable behavior matches)
server_close       | PARITY      | PASS       | PASS        | none (observable behavior matches)
server_refused     | DIVERGED    | PASS       | PASS        | elapsed_bucket differs: ref=~2000ms (2154.2ms), cand=<500ms (152.3ms)
connect_timeout    | PARITY      | PASS       | PASS        | none (observable behavior matches)
client_timeout     | PARITY      | PASS       | PASS        | none (observable behavior matches)
server_timeout     | PARITY      | PASS       | PASS        | none (observable behavior matches)
maxconn            | PARITY      | PASS       | PASS        | none (observable behavior matches)
concurrent         | PARITY      | PASS       | PASS        | none (observable behavior matches)
half_close         | PARITY      | PASS       | PASS        | none (observable behavior matches)
http_get           | PARITY      | PASS       | PASS        | none (observable behavior matches)
http_cookie        | PARITY      | PASS       | PASS        | none (observable behavior matches)
http_cliexp        | DIVERGED    | PASS       | FAIL        | status differs: ref=PASS, cand=FAIL; bytes_received differs: ref=40, cand=0; client_outcome differs: ref=clean_close, cand=error
http_srvexp        | DIVERGED    | PASS       | FAIL        | status differs: ref=PASS, cand=FAIL; bytes_received differs: ref=60, cand=0; client_outcome differs: ref=clean_close, cand=error
================================================================================================
Differential summary: 11/14 scenarios in full feature parity.
```

### 3. Individual Scenarios & JSON Output

```bash
# Run a specific scenario:
python3 harness/difftest.py --scenario echo

# Emit machine-readable JSON:
python3 harness/difftest.py --candidate target/debug/alcyon --json
```

---

## Standalone VTC Regression Test Runner (`vtc_runner.py`)

`harness/vtc_runner.py` is a standalone, dependency-free Varnish Test Case (`.vtc`) runner designed to execute HAProxy regression test suites directly against Alcyon (or any HAProxy-compatible proxy binary).

### Capabilities:
- **Grammar & Directive Parsing**: Parses `vtest`/`varnishtest`, `feature`, `server sN { ... }`, `haproxy hN -conf { ... }`, `client cN -connect ... { ... }`, `barrier`, `delay`, `shell`, and `setenv`.
- **Inner Actions**: Supports `rxreq`, `rxreqhdrs`, `txreq`, `rxresp`, `rxresphdrs`, `txresp`, `expect`, `send`, `sendhex`, `recv`, `barrier <id> sync`, `delay`, and `close`.
- **Dynamic Macro Expansion**: Evaluates `${sN_addr}`, `${sN_port}`, `${sN_sock}`, `${hN_fe_addr}`, `${hN_fe_port}`, `${hN_fe_sock}`, `${testdir}`, `${tmpdir}`, and fallback syntax `${VAR-default}` / `${VAR:-default}`.
- **Config Rewriting & Socket Port Allocation**: Intercepts `bind "fd@${fe}"` and `listen <id>` configurations, allocating ephemeral ports and adapting the config for Alcyon.
- **Detailed Assertions & Diff Reporting**: Formats assertion failures with ANSI colored diffs showing target, operator, expected, and actual values.
- **JSON Suite Reporting**: Generates machine-readable test summaries via `--json <file>`.

### Usage:
```bash
# Run a single VTC test:
./harness/vtc_runner.py /home/bhenc/reference/haproxy/reg-tests/balance/balance-rr.vtc

# Run an entire test directory with JSON output:
./harness/vtc_runner.py /home/bhenc/reference/haproxy/reg-tests/http-rules/ --json harness/http_rules_results.json

# Enable verbose execution trace:
./harness/vtc_runner.py -v /home/bhenc/reference/haproxy/reg-tests/balance/balance-rr.vtc
```
