# Differential Proxy Test Harness (`harness/`)

## Overview

Ibex's Milestone 0 goal is **`mode tcp` at HAProxy 1.0 feature parity**. This test harness (`difftest.py`) measures observable behavior differentials between the reference binary (HAProxy 1.0.2) and candidate implementations (such as Ibex).

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
   - **Tolerant Timing (Bucketing)**: Exact millisecond timings vary due to CPU scheduling and kernel jitter. Furthermore, HAProxy 1.0.2 inspects timer expirations on `select()` ticks driven by statistics intervals (`STATTIME = 2000ms`). Timeouts are therefore categorized into coarse duration buckets (`<500ms`, `~1000ms`, `~2000ms`, `~3000ms`, `~4000ms`, `~5000ms`).

---

## Scenario Catalog

| Scenario | Stimulus / Configuration | Reference Baseline Behavior (HAProxy 1.0.2) |
|---|---|---|
| `echo` | Client streams 1 MiB binary payload with NUL bytes through proxy to an echo backend. | Byte-exact round trip (1,048,576 bytes sent and received), clean close, `<500ms`. |
| `client_close` | Client sends 8 KiB, then calls `shutdown(SHUT_WR)` mid-stream. | Proxy flushes pending request bytes to backend, propagates `SHUT_WR` to server (server reads EOF), clean close. |
| `server_close` | Backend sends 8 KiB response to client, then calls `shutdown(SHUT_WR)`. | Proxy flushes response bytes to client, propagates shutdown (client reads full payload + EOF), clean close. |
| `server_refused` | Client connects and sends data to proxy configured with an unopened backend port and `retries 2`. | Proxy attempts backend connect, receives `ECONNREFUSED`, retries immediately in loop (3 total attempts), closes client socket cleanly. |
| `connect_timeout` | Proxy configured with `dispatch 192.0.2.1:80` (RFC 5737 TEST-NET-1 blackhole) and `contimeout 1000`, `retries 0`. | Proxy initiates non-blocking connect; SYN is blackholed; connect timer fires at the next `select()` tick (~2000ms); proxy closes client connection. |
| `client_timeout` | Client connects to proxy and remains silent (`clitimeout 1000`). | Proxy client read timer fires at the next `select()` tick (~2000ms); proxy closes client socket cleanly. |
| `server_timeout` | Client sends request; backend accepts connection but never replies (`srvtimeout 1000`). | Proxy server read timer fires at the next `select()` tick (~2000ms); proxy closes client connection cleanly. |
| `maxconn` | 4 concurrent clients connect to proxy configured with `maxconn 2` against a backend with a 150ms hold delay. | Exactly 2 connections are active at the backend concurrently; excess 2 connections are queued in the listen backlog and processed sequentially as earlier connections complete. All 4 succeed. |
| `concurrent` | 50 simultaneous client threads each sending unique 1 KiB + UUID payloads through proxy. | All 50 complete concurrently, zero cross-talk, 100% byte-exact match. |
| `half_close` | Client sends 2 KiB request, shuts down write side (`SHUT_WR`), and keeps reading. Server verifies EOF, then sends 4 KiB response. | Proxy preserves full-duplex half-close: backend receives request and EOF; client receives full 4 KiB response byte-exact after write shutdown. |

---

## Usage

### 1. Baseline Mode (Reference Binary Only)

Runs the suite against the HAProxy 1.0.2 reference binary to record baseline metrics:

```bash
python3 harness/difftest.py \
    --reference /home/bhenc/reference/haproxy-1.0.2/haproxy102 \
    --scenario all
```

Output:
```
--- Differential Proxy Test Harness (Baseline Mode: /home/bhenc/reference/haproxy-1.0.2/haproxy102) ---

======================================================================================
SCENARIO           | STATUS | SENT     | RECVD    | EXACT | TIME     | OUTCOME
--------------------------------------------------------------------------------------
echo               | PASS   | 1048576  | 1048576  | YES   | <500ms   | clean_close
client_close       | PASS   | 8192     | 8192     | YES   | <500ms   | clean_close
server_close       | PASS   | 8192     | 8192     | YES   | <500ms   | clean_close
server_refused     | PASS   | 16       | 0        | YES   | <500ms   | clean_close
connect_timeout    | PASS   | 5        | 0        | YES   | ~2000ms  | clean_close
client_timeout     | PASS   | 0        | 0        | YES   | ~2000ms  | clean_close
server_timeout     | PASS   | 26       | 0        | YES   | ~2000ms  | clean_close
maxconn            | PASS   | 20       | 40       | YES   | <500ms   | clean_close
concurrent         | PASS   | 53340    | 53340    | YES   | <500ms   | clean_close
half_close         | PASS   | 2048     | 4096     | YES   | <500ms   | clean_close
======================================================================================
Baseline summary: 10/10 scenarios passed against reference.
```

### 2. Differential Mode (Reference vs Candidate)

Compares reference and candidate binaries directly:

```bash
python3 harness/difftest.py \
    --reference /home/bhenc/reference/haproxy-1.0.2/haproxy102 \
    --candidate /path/to/ibex \
    --scenario all
```

Output:
```
--- Differential Proxy Test Harness (Comparison: /home/bhenc/reference/haproxy-1.0.2/haproxy102 vs /path/to/ibex) ---

================================================================================================
SCENARIO           | DIFF RESULT | REF STATUS | CAND STATUS | DISCREPANCIES
------------------------------------------------------------------------------------------------
echo               | PARITY      | PASS       | PASS        | none (observable behavior matches)
client_close       | PARITY      | PASS       | PASS        | none (observable behavior matches)
server_close       | PARITY      | PASS       | PASS        | none (observable behavior matches)
server_refused     | PARITY      | PASS       | PASS        | none (observable behavior matches)
connect_timeout    | PARITY      | PASS       | PASS        | none (observable behavior matches)
client_timeout     | PARITY      | PASS       | PASS        | none (observable behavior matches)
server_timeout     | PARITY      | PASS       | PASS        | none (observable behavior matches)
maxconn            | PARITY      | PASS       | PASS        | none (observable behavior matches)
concurrent         | PARITY      | PASS       | PASS        | none (observable behavior matches)
half_close         | PARITY      | PASS       | PASS        | none (observable behavior matches)
================================================================================================
Differential summary: 10/10 scenarios in full feature parity.
```

### 3. Individual Scenarios & JSON Output

```bash
# Run a specific scenario:
python3 harness/difftest.py \
    --reference /home/bhenc/reference/haproxy-1.0.2/haproxy102 \
    --scenario echo

# Emit machine-readable JSON:
python3 harness/difftest.py \
    --reference /home/bhenc/reference/haproxy-1.0.2/haproxy102 \
    --json
```

---

## Verified Baseline Findings & Oracle Notes

1. **1 MiB Payload (`echo`)**: HAProxy 1.0.2 internal buffer is 4096 bytes (`BUFSIZE`). A 1 MiB stream passes smoothly through the buffer recycling loop without stalls or memory leaks.
2. **Half-Close Propagation (`client_close`, `half_close`)**: In `mode tcp`, HAProxy propagates client `SHUT_WR` to the server as `shutdown(srv_fd, SHUT_WR)` once all pending request bytes in the buffer are flushed. Server responses arriving after client write shutdown are preserved and forwarded to the client.
3. **Select Loop & Timeout Resolution (`connect_timeout`, `client_timeout`, `server_timeout`)**: In HAProxy 1.0.2, task timer expirations are evaluated in the main `select()` event loop. When no network I/O occurs, `select()` blocks up to `STATTIME` (2000 ms). Idle timeouts configured below 2000 ms fire on the first 2-second tick.
4. **Connection Retries (`server_refused`)**: Retries configured via `retries N` are executed immediately during the initial `SV_STCONN` state if `connect()` fails with `ECONNREFUSED`. After exhausting retries, HAProxy closes the client socket.
5. **Backlog Queuing (`maxconn`)**: When `nbconn >= maxconn`, HAProxy removes the listening socket from the `select()` read set. Additional client connections complete the TCP 3-way handshake in the kernel listen backlog and are accepted once active sessions close.
